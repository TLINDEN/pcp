/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013-2014 T.v.Dein.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    You can contact me by mail: <tom AT vondein DOT org>.
*/


#include "mgmt.h"

int _get_pk(Buffer *blob, pcp_pubkey_t *p) {
  if(buffer_left(blob) >= 96) {
    buffer_get_chunk(blob, p->masterpub, 32);
    buffer_get_chunk(blob, p->edpub, 32);
    buffer_get_chunk(blob, p->pub, 32);
    return 0;
  }
  else
    return 1;
}

int _check_keysig_h(Buffer *blob, rfc_pub_sig_h *h) {
  if(buffer_left(blob) >= sizeof(rfc_pub_sig_h)) {
    buffer_get_chunk(blob, h, sizeof(rfc_pub_sig_h));

    h->numsubs = be16toh(h->numsubs);

    if(h->version != EXP_SIG_VERSION) {
      fatal("Unsupported pubkey signature version %d, expected %d", h->version, EXP_SIG_VERSION);
      return 1;
    }
    if(h->type != EXP_SIG_TYPE) {
      fatal("Unsupported pubkey signature type %d, expected %d", h->type, EXP_SIG_TYPE);
      return 1;
    }
    if(h->pkcipher != EXP_SIG_CIPHER) {
      fatal("Unsupported pubkey signature cipher %d, expected %d", h->pkcipher, EXP_SIG_CIPHER);
      return 1;
    }
    if(h->hashcipher != EXP_HASH_CIPHER) {
      fatal("Unsupported pubkey signature hash cipher %d, expected %d", h->hashcipher, EXP_HASH_CIPHER);
      return 1;
    }
    if(h->numsubs > 0 && buffer_left(blob) < sizeof(rfc_pub_sig_s) * h->numsubs) {
      fatal("Signature size specification invalid (sig: %ld, bytes left: %ld, numsubs: %ld",
	    sizeof(rfc_pub_sig_s) * h->numsubs, buffer_left(blob), h->numsubs);
      return 1;
    }
    return 0;
  }
  else {
    fatal("Error: input data too small, import failed");
    return 1;
  }
}

int _check_sigsubs(Buffer *blob, pcp_pubkey_t *p, rfc_pub_sig_s *subheader) {
  byte *ignore = ucmalloc(32);

  if(subheader->type == EXP_SIG_SUB_NOTATION) {
    /* mail or owner */
    uint16_t nsize = buffer_get16na(blob);
    uint16_t vsize = buffer_get16na(blob);

    char *notation = ucmalloc(nsize);
    char *value = ucmalloc(vsize);

    if(buffer_get_chunk(blob, notation, nsize) == 0)
      return 1;
    if(buffer_get_chunk(blob, value, nsize) == 0)
      return 1;

    notation[nsize] = '\0';
    value[nsize] = '\0';

    if(strncmp(notation, "owner", 5) == 0) {
      memcpy(p->owner, value, vsize);
    }
    else if(strncmp(notation, "mail", 4) == 0) {
      memcpy(p->mail, value, vsize);
    }

    ucfree(notation, nsize);
    ucfree(value, vsize);
  }
  else {
    /* unsupported or ignored sig sub */
    if(buffer_get_chunk(blob, ignore, subheader->size) == 0)
      return 1;
  }

  return 0;
}

int _check_hash_keysig(Buffer *blob, pcp_pubkey_t *p, pcp_keysig_t *sk) {
  // read hash + sig
  size_t blobstop = blob->offset;
  size_t sigsize = crypto_sign_BYTES + crypto_generichash_BYTES_MAX;

  unsigned char *signature = ucmalloc(sigsize);
  if(buffer_get_chunk(blob, signature, sigsize) == 0)
    goto chker1;

  /* fill the keysig */
  sk->type = PCP_KEYSIG_NATIVE;
  
  /* everything minus version, ctime and cipher, 1st 3 fields */
  sk->size = blobstop - 6;
  memcpy(sk->belongs, p->id, 17);

  /* put the whole signature blob into our keysig */
  blob->offset = 6; /* woah, hack :) */
  sk->blob = ucmalloc(sk->size);
  buffer_get_chunk(blob, sk->blob, sk->size);

  /* verify the signature */
  unsigned char *verifyhash = pcp_ed_verify_key(signature, sigsize, p);
  if(verifyhash == NULL)
    goto chker1;

  /* re-calculate the hash */
  crypto_generichash_state *st = ucmalloc(sizeof(crypto_generichash_state));
  unsigned char *hash = ucmalloc(crypto_generichash_BYTES_MAX);
  crypto_generichash_init(st, NULL, 0, 0);
  crypto_generichash_update(st, sk->blob, sk->size);
  crypto_generichash_final(st, hash, crypto_generichash_BYTES_MAX);

  /* compare them */
  if(memcmp(hash, verifyhash, crypto_generichash_BYTES_MAX) != 0) {
    fatal("Signature verifies but signed hash doesn't match signature contents\n");
    goto chker2;
  }

  /* calculate the checksum */
  crypto_hash_sha256(sk->checksum, sk->blob, sk->size);
  
  /* we got here, so everything is good */
  p->valid = 1;

  ucfree(verifyhash, crypto_generichash_BYTES_MAX);
  ucfree(hash, crypto_generichash_BYTES_MAX);
  free(st);
  ucfree(signature, sigsize);
  
  return 0;

 chker2:
  ucfree(verifyhash, crypto_generichash_BYTES_MAX);
  ucfree(hash, crypto_generichash_BYTES_MAX);
  free(st);

 chker1:
  ucfree(signature, sigsize);

  return 1;
  
}

pcp_ks_bundle_t *pcp_import_pub(unsigned char *raw, size_t rawsize) {
  size_t clen;
  unsigned char *bin = NULL;
  Buffer *blob = buffer_new(512, "importblob");

  /* first, try to decode the input */
  bin = pcp_z85_decode((char *)raw, &clen);

  if(bin == NULL) {
    /* treat as binary blob */
    fatals_reset();
    buffer_add(blob, raw, rawsize);
  }
  else {
    /* use decoded */
    buffer_add(blob, bin, rawsize);
    ucfree(bin, clen);
  }

  /* now, try to disassemble, if it fails, assume pbp format */
  uint8_t version = buffer_get8(blob);

  if(version == PCP_KEY_VERSION) {
    /* ah, homerun */
    pcp_ks_bundle_t *b = pcp_import_pub_rfc(blob);
    pcp_keysig_t *sk = b->s;
    return b;
  }
  else {
    /* nope, it's probably pbp */
    return pcp_import_pub_pbp(blob);
  }
}

pcp_ks_bundle_t *pcp_import_pub_rfc(Buffer *blob) {
  pcp_pubkey_t *p = ucmalloc(sizeof(pcp_pubkey_t));
  pcp_keysig_t *sk = ucmalloc(sizeof(pcp_keysig_t));
  rfc_pub_sig_h *sigheader = ucmalloc(sizeof(rfc_pub_sig_h));
  rfc_pub_sig_s *subheader = ucmalloc(sizeof(rfc_pub_sig_s));

  if(buffer_done(blob)) goto be;
  p->ctime = buffer_get32na(blob);

  uint8_t pkcipher = buffer_get8(blob);
  if(buffer_done(blob)) goto be;

  if(pkcipher != EXP_PK_CIPHER) {
    fatal("Unsupported pk cipher %d, expected %d", pkcipher, EXP_PK_CIPHER);
    goto bef;
  }

  /* fetch pk material */
  if(_get_pk(blob, p) != 0)
    goto be;

  /* check sig header.
     currently not stored anywhere, but we could sometimes */
  if(_check_keysig_h(blob, sigheader) != 0)
    goto bef;

  /* iterate over subs, if any */
  int i;
  for (i=0; i<sigheader->numsubs; i++) {
    subheader->size = buffer_get32na(blob);
    subheader->type = buffer_get8(blob);
    _check_sigsubs(blob, p, subheader);
  }

  /* calc id */
  char *id = pcp_getpubkeyid(p);
  memcpy(p->id, id, 17);
  free(id);

  /* fill */
  p->type = PCP_KEY_TYPE_PUBLIC;
  p->version = PCP_KEY_VERSION;
  p->serial  = arc4random(); /* FIXME: maybe add this as a sig sub? */

  pcp_ks_bundle_t *b = ucmalloc(sizeof(pcp_ks_bundle_t));

  /* retrieve signature, store and verify it */
  if(_check_hash_keysig(blob, p, sk) != 0) {
    b->p = p;
    b->s = NULL;
  }
  else {
    b->p = p;
    b->s = sk;
  }

  return b;


 be:
  fatal("Error: input data too small, import failed");

 bef:
  buffer_free(blob);
  ucfree(sigheader, sizeof(rfc_pub_sig_h));
  ucfree(subheader, sizeof(rfc_pub_sig_s));
  ucfree(p, sizeof(pcp_pubkey_t));
  return NULL;
}

pcp_ks_bundle_t *pcp_import_pub_pbp(Buffer *blob) {
  return NULL;
}

Buffer *pcp_export_pbp_pub(pcp_key_t *sk) {
  struct tm *v, *c;
  unsigned char *signature = NULL;
  char *date = NULL;

  Buffer *out = buffer_new(320, "pbp01");
  Buffer *sig = buffer_new(320, "pbsig01");

  /* add raw key material */
  buffer_add(sig, sk->edpub, crypto_sign_PUBLICKEYBYTES);
  buffer_add(sig, sk->edpub, crypto_sign_PUBLICKEYBYTES);
  buffer_add(sig, sk->pub, crypto_box_PUBLICKEYBYTES);

  /* add creatioin and expire time as 32byte iso time string */
  time_t t = (time_t)sk->ctime;
  c = localtime(&t);
  time_t vt = t + 31536000;
  v = localtime(&vt);
  date = ucmalloc(65);
  sprintf(date, "%04d-%02d-%02dT%02d:%02d:%02d.000000      %04d-%02d-%02dT%02d:%02d:%02d.000000      ",
	  c->tm_year+1900-1, c->tm_mon+1, c->tm_mday, // wtf? why -1?
	  c->tm_hour, c->tm_min, c->tm_sec,
	  v->tm_year+1900-1, v->tm_mon+1, v->tm_mday,
	  v->tm_hour, v->tm_min, v->tm_sec);
  buffer_add(sig, date, 64);

  /* add owner */
  buffer_add(sig, sk->owner, strlen(sk->owner));

  /* calculate the signed key blob */
  signature = pcp_ed_sign(buffer_get(sig), buffer_size(sig), sk);

  if(signature == NULL)
    goto exppbperr01;

  /* put it out */
  buffer_add_buf(out, sig);

  free(date);
  buffer_free(sig);
  free(v);
  return out;
  

 exppbperr01:
  buffer_free(sig);
  buffer_free(out);
  free(date);
  free(v);
  return NULL;
}


Buffer *pcp_export_rfc_pub (pcp_key_t *sk) {
  Buffer *out = buffer_new(320, "bo1");
  Buffer *raw = buffer_new(256, "bs1");

  /* add the header */
  buffer_add8(out, PCP_KEY_VERSION);
  buffer_add32be(out, sk->ctime);
  buffer_add8(out, EXP_PK_CIPHER);

  /* add the keys */
  buffer_add(raw, sk->masterpub, 32);
  buffer_add(raw, sk->edpub, 32);
  buffer_add(raw, sk->pub, 32);

  /* add the sig header */
  buffer_add8(raw, EXP_SIG_VERSION);
  buffer_add8(raw, EXP_SIG_TYPE);
  buffer_add8(raw, EXP_SIG_CIPHER);
  buffer_add8(raw, EXP_HASH_CIPHER);
  buffer_add16be(raw, 5); /* we add 5 sub sigs always */

  /* add sig ctime */
  buffer_add32be(raw, 4);
  buffer_add8(raw, EXP_SIG_SUB_CTIME);
  buffer_add32be(raw, time(0));

  /* add sig expire time */
  buffer_add32be(raw, 4);
  buffer_add8(raw, EXP_SIG_SUB_SIGEXPIRE);
  buffer_add32be(raw, time(0) + 31536000);

  /* add key expire time */
  buffer_add32be(raw, 4);
  buffer_add8(raw, EXP_SIG_SUB_KEYEXPIRE);
  buffer_add32be(raw, sk->ctime + 31536000);

  size_t notation_size = 0;
  /* add name notation sub*/
  if(strlen(sk->owner) > 0) {
    size_t notation_size = strlen(sk->owner) + 4 + 5;
    buffer_add32be(raw, notation_size);
    buffer_add8(raw, EXP_SIG_SUB_NOTATION);
    buffer_add16be(raw, 5);
    buffer_add16be(raw, strlen(sk->owner));
    buffer_add(raw, "owner", 5);
    buffer_add(raw, sk->owner, strlen(sk->owner));
  }

  /* add mail notation sub */
  if(strlen(sk->mail) > 0) {
    notation_size = strlen(sk->mail) + 4 + 4;
    buffer_add32be(raw, notation_size);
    buffer_add8(raw, EXP_SIG_SUB_NOTATION);
    buffer_add16be(raw, 4);
    buffer_add16be(raw, strlen(sk->mail));
    buffer_add(raw, "mail", 4);
    buffer_add(raw, sk->mail, strlen(sk->mail));
  }

  /* add key flags */
  buffer_add32be(raw, 1);
  buffer_add8(raw, 27);
  buffer_add8(raw, 0x02 & 0x08 & 0x80);

  /* create a hash from the PK material and the raw signature packet */
  crypto_generichash_state *st = ucmalloc(sizeof(crypto_generichash_state));
  unsigned char *hash = ucmalloc(crypto_generichash_BYTES_MAX);

  crypto_generichash_init(st, NULL, 0, 0);
  crypto_generichash_update(st, buffer_get(raw), buffer_size(raw));
  crypto_generichash_final(st, hash, crypto_generichash_BYTES_MAX);

  /* sign the hash */
  unsigned char *sig = pcp_ed_sign_key(hash, crypto_generichash_BYTES_MAX, sk);

  /* append the signature packet to the output */
  buffer_add(out, buffer_get(raw), buffer_size(raw));

  /* append the signed hash */
  buffer_add(out, sig, crypto_sign_BYTES + crypto_generichash_BYTES_MAX);

  _dump("raw", buffer_get(raw), buffer_size(raw));

  /* and that's it. wasn't that easy? :) */
  buffer_free(raw);
  memset(hash, 0, crypto_generichash_BYTES_MAX);
  free(hash);
  memset(sig, 0, crypto_sign_BYTES + crypto_generichash_BYTES_MAX);
  free(sig);

  return out;
}
