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

/* #define _XOPEN_SOURCE strptime, linux glibc*/ 

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

int _check_keysig_h(PCPCTX *ptx, Buffer *blob, rfc_pub_sig_h *h) {
  if(buffer_left(blob) >= sizeof(rfc_pub_sig_h)) {
    buffer_get_chunk(blob, h, sizeof(rfc_pub_sig_h));

    h->numsubs = be16toh(h->numsubs);

    if(h->version != EXP_SIG_VERSION) {
      fatal(ptx, "Unsupported pubkey signature version %d, expected %d\n", h->version, EXP_SIG_VERSION);
      return 1;
    }
    if(h->type != EXP_SIG_TYPE) {
      fatal(ptx, "Unsupported pubkey signature type %d, expected %d\n", h->type, EXP_SIG_TYPE);
      return 1;
    }
    if(h->pkcipher != EXP_SIG_CIPHER) {
      fatal(ptx, "Unsupported pubkey signature cipher %d, expected %d\n", h->pkcipher, EXP_SIG_CIPHER);
      return 1;
    }
    if(h->hashcipher != EXP_HASH_CIPHER) {
      fatal(ptx, "Unsupported pubkey signature hash cipher %d, expected %d\n", h->hashcipher, EXP_HASH_CIPHER);
      return 1;
    }
    if(h->numsubs > 0 && buffer_left(blob) < sizeof(rfc_pub_sig_s) * h->numsubs) {
      fatal(ptx, "Signature size specification invalid (sig: %ld, bytes left: %ld, numsubs: %ld\n",
	    sizeof(rfc_pub_sig_s) * h->numsubs, buffer_left(blob), h->numsubs);
      return 1;
    }
    return 0;
  }
  else {
    fatal(ptx, "Error: input data too small, import failed\n");
    return 1;
  }
}

int _check_sigsubs(PCPCTX *ptx, Buffer *blob, pcp_pubkey_t *p, rfc_pub_sig_s *subheader) {
  uint16_t nsize, vsize;
  char *notation = NULL;
  
  if(subheader->size > buffer_left(blob)) {
    fatal(ptx, "Invalid header size %ld specified in source\n", subheader->size);
    return 1;
  }

  if(subheader->type == EXP_SIG_SUB_NOTATION) {
    /* mail or owner */
    nsize = buffer_get16na(blob);
    vsize = buffer_get16na(blob);

    if(nsize >  buffer_left(blob)) {
      fatal(ptx, "Invalid notation size %ld specified in source\n", nsize);
      return 1;
    }

    notation = ucmalloc(nsize+1);

    if(buffer_get_chunk(blob, notation, nsize) == 0) {
      fatal(ptx, "Invalid notation size, expected %ld bytes, but got 0\n", nsize);
      goto sgcerr;
    }

    notation[nsize] = '\0';

    if(vsize >  buffer_left(blob) || vsize > 255) {
      fatal(ptx, "Invalid notation value size %ld specified in source\n", vsize);
      goto sgcerr;
    }

    if(strncmp(notation, "owner", 5) == 0) {
      if(buffer_get_chunk(blob, p->owner, vsize) == 0) {
	fatal(ptx, "Invalid 'owner' notation, expected %ld bytes, but got 0\n", vsize);
	goto sgcerr;
      }
    }
    else if(strncmp(notation, "mail", 4) == 0) {
      if(buffer_get_chunk(blob, p->mail, vsize) == 0) {
	fatal(ptx, "Invalid 'mail' notation, expected %ld bytes, but got 0\n", vsize);
	goto sgcerr;
      }
    }
    else if(strncmp(notation, "serial", 6) == 0) {
      p->serial = buffer_get32na(blob);
    }
    ucfree(notation, nsize+1);
  }
  else {
    /* unsupported or ignored sig subs:
       we (currently) ignore sig ctime, expire and keyexpire,
       since the ctime - which is the only one we need internally -
       is already known from the key ctime. This may change in
       the future though.
     */
    if(buffer_fwd_offset(blob, subheader->size) == 0) {
      fatal(ptx, "Invalid 'unsupported' notation, expected %ld bytes, but got 0\n", subheader->size);
      return 1;
    }
  }

  return 0;

 sgcerr:
  ucfree(notation, nsize+1);
  return 1;
}


int _check_hash_keysig(PCPCTX *ptx, Buffer *blob, pcp_pubkey_t *p, pcp_keysig_t *sk) {
  // read hash + sig
  size_t blobstop = blob->offset; /* key header + mp,sp,cp */
  size_t sigsize = crypto_sign_BYTES + crypto_generichash_BYTES_MAX;
  size_t phead = (2 * sizeof(uint8_t)) + sizeof(uint64_t); /* rfc_pub_h */

  byte *signature = ucmalloc(sigsize);
  if(buffer_get_chunk(blob, signature, sigsize) == 0)
    goto chker1;

  /* fill the keysig */
  sk->type = PCP_KEYSIG_NATIVE;
  
  /* everything minus version, ctime and cipher, 1st 3 fields */
  sk->size = blobstop - phead;

  memcpy(sk->id, p->id, 17);

  /* put the whole signature blob into our keysig */
  blob->offset = phead;
  sk->blob = ucmalloc(sk->size + sigsize);

  buffer_get_chunk(blob, sk->blob, sk->size);

  /* verify the signature */
  byte *verifyhash = pcp_ed_verify_key(ptx, signature, sigsize, p);
  if(verifyhash == NULL) {
    goto chker1;
  }

  /* re-calculate the hash */
  crypto_generichash_state *st = ucmalloc(sizeof(crypto_generichash_state));
  byte *hash = ucmalloc(crypto_generichash_BYTES_MAX);
  crypto_generichash_init(st, NULL, 0, 0);
  crypto_generichash_update(st, sk->blob, sk->size);
  crypto_generichash_final(st, hash, crypto_generichash_BYTES_MAX);

  /* compare them */
  if(memcmp(hash, verifyhash, crypto_generichash_BYTES_MAX) != 0) {
    fatal(ptx, "Signature verifies but signed hash doesn't match signature contents\n");
    goto chker2;
  }

  /* calculate the checksum */
  crypto_hash_sha256(sk->checksum, sk->blob, sk->size);
  
  /* we got here, so everything is good */
  p->valid = 1;

  /* append the sig */
  memcpy(&sk->blob[sk->size], signature, sigsize);
  sk->size += sigsize;
  
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


pcp_ks_bundle_t *pcp_import_pub(PCPCTX *ptx, byte *raw, size_t rawsize) {
  size_t clen;
  byte *bin = NULL;
  char *z85 = NULL;

  if(rawsize == 0) {
    fatal(ptx, "Input file is empty!\n");
    return NULL;
  }

  Buffer *blob = buffer_new(512, "importblob");

  /* first, try to decode the input */
  z85 = pcp_readz85string(ptx, raw, rawsize);

  if(z85 != NULL)
    bin = pcp_z85_decode(ptx, z85, &clen);

  if(bin == NULL) {
    /* treat as binary blob */
    fatals_reset(ptx);
    buffer_add(blob, raw, rawsize);
  }
  else {
    /* use decoded */
    buffer_add(blob, bin, clen);
    ucfree(bin, clen);
  }

  /* now, try to disassemble, if it fails, assume pbp format */
  uint8_t version = buffer_get8(blob);

  if(version == PCP_KEY_VERSION) {
    /* ah, homerun */
    return pcp_import_pub_rfc(ptx, blob);
  }
  else {
    /* nope, it's probably pbp */
    return pcp_import_pub_pbp(ptx, blob);
  }
}

pcp_ks_bundle_t *pcp_import_binpub(PCPCTX *ptx, byte *raw, size_t rawsize) {
  Buffer *blob = buffer_new(512, "importblob");
  pcp_ks_bundle_t *bundle = NULL;

#ifdef HAVE_JSON
  if(ptx->json) {
    bundle = pcp_import_pub_json(ptx, raw, rawsize);
  }
  else {
#endif
   
    buffer_add(blob, raw, rawsize);

    /* now, try to disassemble, if it fails, assume pbp format */
    uint8_t version = buffer_get8(blob);

    if(version == PCP_KEY_VERSION) {
      /* ah, homerun */
      bundle = pcp_import_pub_rfc(ptx, blob);
    }
    else {
      /* nope, it's probably pbp */
      bundle = pcp_import_pub_pbp(ptx, blob);
    }

#ifdef HAVE_JSON
  }
#endif
  
  buffer_free(blob);
  return bundle;

}

pcp_ks_bundle_t *pcp_import_pub_rfc(PCPCTX *ptx, Buffer *blob) {
  pcp_keysig_t *sk = NULL;
  pcp_ks_bundle_t *b = NULL;
  rfc_pub_sig_h *sigheader = ucmalloc(sizeof(rfc_pub_sig_h));
  rfc_pub_sig_s *subheader = ucmalloc(sizeof(rfc_pub_sig_s));
  pcp_pubkey_t *p = ucmalloc(sizeof(pcp_pubkey_t));

  if(buffer_done(blob)) goto be;
  p->ctime = buffer_get64na(blob);

  uint8_t pkcipher = buffer_get8(blob);
  if(buffer_done(blob)) goto be;

  if(pkcipher != EXP_PK_CIPHER) {
    fatal(ptx, "Unsupported pk cipher %d, expected %d\n", pkcipher, EXP_PK_CIPHER);
    goto bef;
  }

  /* fetch pk material */
  if(_get_pk(blob, p) != 0)
    goto be;

  /* check sig header */
  if(_check_keysig_h(ptx, blob, sigheader) != 0)
    goto bef;

  /* iterate over subs, if any */
  int i;
  for (i=0; i<sigheader->numsubs; i++) {
    subheader->size = buffer_get32na(blob);
    subheader->type = buffer_get8(blob);
    if(_check_sigsubs(ptx, blob, p, subheader) != 0)
      goto bes;
  }
  ucfree(sigheader, sizeof(rfc_pub_sig_h));
  ucfree(subheader, sizeof(rfc_pub_sig_s));

  /* calc id */
  char *id = pcp_getpubkeyid(p);
  memcpy(p->id, id, 17);
  free(id);

  /* fill */
  p->type = PCP_KEY_TYPE_PUBLIC;
  p->version = PCP_KEY_VERSION;

  /* retrieve signature, store and verify it */
  b = ucmalloc(sizeof(pcp_ks_bundle_t));
  sk = ucmalloc(sizeof(pcp_keysig_t));

  if(_check_hash_keysig(ptx, blob, p, sk) != 0) {
    b->p = p;
    b->s = NULL;
  }
  else {
    b->p = p;
    b->s = sk;
  }

  return b;


 be:
  fatal(ptx, "Error: input data too small, import failed\n");

 bes:

 bef:
  ucfree(sigheader, sizeof(rfc_pub_sig_h));
  ucfree(subheader, sizeof(rfc_pub_sig_s));
  ucfree(p, sizeof(pcp_pubkey_t));
  return NULL;
}

pcp_ks_bundle_t *pcp_import_pub_pbp(PCPCTX *ptx, Buffer *blob) {
  char *date  = ucmalloc(20);
  char *parts = NULL;
  byte *sig = ucmalloc(crypto_sign_BYTES);
  int pnum;
  pbp_pubkey_t *b = NULL;
  pcp_pubkey_t *tmp = NULL;
  pcp_pubkey_t *pub = NULL;

  buffer_get_chunk(blob, sig, crypto_sign_BYTES);

  /* make sure it's a pbp */
  if(_buffer_is_binary(sig, crypto_sign_BYTES) == 0) {
    fatal(ptx, "failed to recognize input, that's probably no key\n");
    goto errimp2;
  }

  b = ucmalloc(sizeof(pbp_pubkey_t)); /* FIXME: separate type really needed? */
  buffer_get_chunk(blob, b->sigpub, crypto_sign_PUBLICKEYBYTES);
  buffer_get_chunk(blob, b->edpub, crypto_sign_PUBLICKEYBYTES);
  buffer_get_chunk(blob, b->pub, crypto_box_PUBLICKEYBYTES);
  buffer_get_chunk(blob, date, 18);

  date[19] = '\0';
  struct tm c;
  if(strptime(date, "%Y-%m-%dT%H:%M:%S", &c) == NULL) {
    fatal(ptx, "Failed to parse creation time in PBP public key file\n");
    free(date);
    ucfree(b, sizeof(pbp_pubkey_t));
    goto errimp2;
  }
  
  buffer_fwd_offset(blob, 46);
  memcpy(b->name, buffer_get(blob), buffer_left(blob));

  /*  parse the name */
  parts = strtok (b->name, "<>");
  pnum = 0;
  pub = ucmalloc(sizeof(pcp_pubkey_t));
  while (parts != NULL) {
    if(pnum == 0)
      memcpy(pub->owner, parts, strlen(parts));
    else if (pnum == 1)
      memcpy(pub->mail, parts, strlen(parts));
    parts = strtok(NULL, "<>");
    pnum++;
  }
  free(parts);

  if(strlen(b->name) == 0) {
    memcpy(pub->owner, "N/A", 3);
  }

  /*  fill in the fields */
  pub->ctime = (long)mktime(&c);
  pub->type = PCP_KEY_TYPE_PUBLIC;
  pub->version = PCP_KEY_VERSION;
  pub->serial  = arc4random();
  memcpy(pub->pub, b->pub, crypto_box_PUBLICKEYBYTES);
  memcpy(pub->edpub, b->edpub, crypto_sign_PUBLICKEYBYTES);
  memcpy(pub->id, pcp_getpubkeyid(pub), 17);
  _lc(pub->owner);
  ucfree(b, sizeof(pbp_pubkey_t));

  /* edpub used for signing, might differ */
  tmp = ucmalloc(sizeof(pcp_pubkey_t));
  memcpy(tmp->edpub, b->sigpub, crypto_sign_PUBLICKEYBYTES);

  byte *verify = pcp_ed_verify(ptx, buffer_get(blob), buffer_size(blob), tmp);
  free(tmp);

  pcp_ks_bundle_t *bundle = ucmalloc(sizeof(pcp_ks_bundle_t));
  bundle->p = pub;
  
  if(verify == NULL) {
    bundle->p = pub;
    bundle->s = NULL;
  }
  else {
    pcp_keysig_t *sk = ucmalloc(sizeof(pcp_keysig_t));
    sk->type = PCP_KEYSIG_PBP;
    sk->size = buffer_size(blob);
    memcpy(sk->id, pub->id, 17);
    sk->blob = ucmalloc(sk->size);
    memcpy(sk->blob, buffer_get(blob), sk->size);
    crypto_hash_sha256(sk->checksum, sk->blob, sk->size);
    pub->valid = 1;
    bundle->s = sk;
    bundle->p = pub;
    free(verify);
  }
  
  free(sig);
  return bundle;

 errimp2:
  free(sig);
  return NULL;
}


Buffer *pcp_export_pbp_pub(pcp_key_t *sk) {
  struct tm *v, *c;
  byte *signature = NULL;
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


Buffer *pcp_export_rfc_pub (PCPCTX *ptx, pcp_key_t *sk) {
  Buffer *out = buffer_new(320, "exportbuf");
  Buffer *raw = buffer_new(256, "keysigbuf");
  
  /* add the header */
  buffer_add8(out, PCP_KEY_VERSION);
  buffer_add64be(out, sk->ctime);
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

  /* we add 5-7 subs:
     ctime, sigexpire, keyexpire, serial, keyflags
     optional: owner, mail */
  uint16_t nsubs = 5;
  if(strlen(sk->owner) > 0)
    nsubs++;
  if(strlen(sk->mail) > 0)
    nsubs++;
  buffer_add16be(raw, nsubs);

  /* add sig ctime */
  buffer_add32be(raw, 8);
  buffer_add8(raw, EXP_SIG_SUB_CTIME);
  buffer_add64be(raw, time(0));

  /* add sig expire time */
  buffer_add32be(raw, 8);
  buffer_add8(raw, EXP_SIG_SUB_SIGEXPIRE);
  buffer_add64be(raw, time(0) + 31536000);

  /* add key expire time */
  buffer_add32be(raw, 8);
  buffer_add8(raw, EXP_SIG_SUB_KEYEXPIRE);
  buffer_add64be(raw, sk->ctime + 31536000);

  size_t notation_size = 0;
  /* add serial number notation sub */
  notation_size = 6 + 4 + 4;
  buffer_add32be(raw, notation_size);
  buffer_add8(raw, EXP_SIG_SUB_NOTATION);
  buffer_add16be(raw, 6);
  buffer_add16be(raw, 4);
  buffer_add(raw, "serial", 6);
  buffer_add32be(raw, sk->serial);

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
  buffer_add8(raw, EXP_SIG_SUB_KEYFLAGS);
  buffer_add8(raw, 0x02 & 0x08 & 0x80);

  /* create a hash from the PK material and the raw signature packet */
  crypto_generichash_state *st = ucmalloc(sizeof(crypto_generichash_state));
  byte *hash = ucmalloc(crypto_generichash_BYTES_MAX);

  crypto_generichash_init(st, NULL, 0, 0);
  crypto_generichash_update(st, buffer_get(raw), buffer_size(raw));
  crypto_generichash_final(st, hash, crypto_generichash_BYTES_MAX);

  /* sign the hash */
  byte *sig = pcp_ed_sign_key(hash, crypto_generichash_BYTES_MAX, sk);

  /* append the signature packet to the output */
  buffer_add(out, buffer_get(raw), buffer_size(raw));

  /* append the signed hash */
  buffer_add(out, sig, crypto_sign_BYTES + crypto_generichash_BYTES_MAX);

#ifdef HAVE_JSON
  if(ptx->json) {
    size_t siglen =  buffer_size(out) - 10;
    byte *jsig = ucmalloc(siglen);

    buffer_extract(out, jsig, 10, siglen);

    Buffer *jout = pcp_export_json_pub(ptx, sk, jsig, siglen);
    buffer_free(out);
    
    out = jout;
  }
#endif
  
  /* and that's it. wasn't that easy? :) */
  buffer_free(raw);
  memset(hash, 0, crypto_generichash_BYTES_MAX);
  free(hash);
  memset(sig, 0, crypto_sign_BYTES + crypto_generichash_BYTES_MAX);
  free(sig);

  if(out->end < 32)
    fatal(ptx, "failed to export public key");

  return out;
}

Buffer *pcp_export_secret(PCPCTX *ptx, pcp_key_t *sk, char *passphrase) {
  byte *nonce = NULL;
  byte *symkey = NULL;
  byte *cipher = NULL;
  size_t es;

  Buffer *raw = buffer_new(512, "secretbuf");
  Buffer *out = buffer_new(512, "secretcipherblob");

  buffer_add(raw, sk->mastersecret, 64);
  buffer_add(raw, sk->secret, 32);
  buffer_add(raw, sk->edsecret, 64);

  buffer_add(raw, sk->masterpub, 32);
  buffer_add(raw, sk->pub, 32);
  buffer_add(raw, sk->edpub, 32);

  if(strlen(sk->owner) > 0) {
    buffer_add16be(raw, strlen(sk->owner));
    buffer_add(raw, sk->owner,  strlen(sk->owner));
  }
  else
    buffer_add16be(raw, 0);
  
  if(strlen(sk->mail) > 0) {
    buffer_add16be(raw, strlen(sk->mail));
    buffer_add(raw, sk->mail, strlen(sk->mail));
  }
  else
    buffer_add16be(raw, 0);
  
  buffer_add64be(raw, sk->ctime);
  buffer_add32be(raw, sk->version);
  buffer_add32be(raw, sk->serial);
  
  nonce = ucmalloc(crypto_secretbox_NONCEBYTES);
  arc4random_buf(nonce, crypto_secretbox_NONCEBYTES);
  symkey = pcp_scrypt(ptx, passphrase, strlen(passphrase), nonce, crypto_secretbox_NONCEBYTES);

  es = pcp_sodium_mac(&cipher, buffer_get(raw), buffer_size(raw), nonce, symkey);

#ifdef HAVE_JSON
  if(ptx->json) {
    Buffer *jout = pcp_export_json_secret(ptx, sk, nonce, cipher, es);
    buffer_free(out);
    out = jout;
  }
  else {
#endif

    buffer_add(out, nonce, crypto_secretbox_NONCEBYTES);
    buffer_add(out, cipher, es);

#ifdef HAVE_JSON
  }
#endif 
  
  buffer_free(raw);
  ucfree(nonce, crypto_secretbox_NONCEBYTES);
  sfree(symkey);
  ucfree(cipher, es);

  return out;
}

pcp_key_t *pcp_import_binsecret(PCPCTX *ptx, byte *raw, size_t rawsize, char *passphrase) {
  Buffer *blob = buffer_new(512, "importskblob");
  buffer_add(blob, raw, rawsize);
  return pcp_import_secret_native(ptx, blob, passphrase);
}


pcp_key_t *pcp_import_secret(PCPCTX *ptx, byte *raw, size_t rawsize, char *passphrase) {
  size_t clen;
  byte *bin = NULL;
  char *z85 = NULL;

  if(rawsize == 0) {
    fatal(ptx, "Input file is empty!\n");
    return NULL;
  }

  Buffer *blob = buffer_new(512, "importskblob");

  /* first, try to decode the input */
  z85 = pcp_readz85string(ptx, raw, rawsize);
  if(z85 != NULL)
    bin = pcp_z85_decode(ptx, z85, &clen);

  if(bin == NULL) {
    /* treat as binary blob */
    fatals_reset(ptx);
    buffer_add(blob, raw, rawsize);
  }
  else {
    /* use decoded */
    buffer_add(blob, bin, clen);
    ucfree(bin, clen);
  }

  /* now we've got the blob, parse it */
  pcp_key_t *sk = pcp_import_secret_native(ptx, blob, passphrase);
  buffer_free(blob);

  return sk;
}

pcp_key_t *pcp_import_secret_native(PCPCTX *ptx, Buffer *cipher, char *passphrase) {
  pcp_key_t *sk = ucmalloc(sizeof(pcp_key_t));
  byte *nonce = ucmalloc(crypto_secretbox_NONCEBYTES);
  byte *symkey = NULL;
  byte *clear = NULL;
  size_t cipherlen = 0;
  size_t minlen = (64 * 2) + (32 * 4) + 8 + 4 + 4; /* key material and mandatory field sizes */
  uint16_t notationlen = 0;

  Buffer *blob = buffer_new(512, "secretdecryptbuf");
  
#ifdef HAVE_JSON
  if(ptx->json) {
    Buffer *parsed = pcp_import_secret_json(ptx, cipher);
    if(parsed == NULL) {
      goto impserr1;
    }
    cipher = parsed; /* re-used */
  }
#endif

  if(buffer_get_chunk(cipher, nonce, crypto_secretbox_NONCEBYTES) == 0)
    goto impserr1;

  symkey = pcp_scrypt(ptx, passphrase, strlen(passphrase), nonce, crypto_secretbox_NONCEBYTES);

  cipherlen = buffer_left(cipher);
  if(cipherlen < minlen) {
    fatal(ptx, "failed to decrypt the secret key file:\n"
	  "expected encrypted secret key size %ld is less than minimum len %ld\n",
	  cipherlen, minlen);
    goto impserr1;
  }

  /* decrypt the blob */
  if(pcp_sodium_verify_mac(&clear, buffer_get_remainder(cipher),
			   cipherlen, nonce, symkey) != 0) {

    fatal(ptx, "failed to decrypt the secret key file\n");
    goto impserr1;
  }

  /* prepare the extraction buffer */
  buffer_add(blob, clear, cipherlen - PCP_CRYPTO_ADD);

  /* extract the raw data into the structure */
  buffer_get_chunk(blob, sk->mastersecret, 64);
  buffer_get_chunk(blob, sk->secret, 32);
  buffer_get_chunk(blob, sk->edsecret, 64);

  buffer_get_chunk(blob, sk->masterpub, 32);
  buffer_get_chunk(blob, sk->pub, 32);
  buffer_get_chunk(blob, sk->edpub, 32);

  notationlen = buffer_get16na(blob);
  if(notationlen > 255) {
    fatal(ptx, "Invalid notation value size for owner\n");
    goto impserr2;
  }
  else if(notationlen > 0)
    buffer_get_chunk(blob, sk->owner, notationlen);

  notationlen = buffer_get16na(blob);
  if(notationlen > 255) {
    fatal(ptx, "Invalid notation value size for mail\n");
    goto impserr2;
  }
  else if(notationlen > 0)
    buffer_get_chunk(blob, sk->mail, notationlen);

  if(buffer_done(blob) == 1)
    goto impserr2;

  sk->ctime = buffer_get64na(blob);
  sk->version = buffer_get32na(blob);
  sk->serial = buffer_get32na(blob);


  /* fill in the calculated fields */
  char *id = pcp_getkeyid(sk);
  memcpy (sk->id, id, 17);
  sk->type = PCP_KEY_TYPE_SECRET;

  /* ready */
  ucfree(clear, cipherlen - PCP_CRYPTO_ADD);
  ucfree(nonce, crypto_secretbox_NONCEBYTES);
  buffer_free(blob);
  sfree(symkey);
  free(id);

  return sk;

 impserr2:
  ucfree(clear, cipherlen - PCP_CRYPTO_ADD);

 impserr1:
  ucfree(nonce, crypto_secretbox_NONCEBYTES);
  ucfree(sk, sizeof(pcp_key_t));
  buffer_free(blob);
  if(symkey != NULL)
    sfree(symkey);
  if(clear != NULL)
    free(clear);
  return NULL;
}








#ifdef HAVE_JSON

json_t *pcp_pk2json(pcp_pubkey_t *pk) {
  /* somewhat ugly, map the pub parts of a sk into
     a fake pk so that we don't have to write pcp_sk2json()
     for both key types. FIXME: 'd be better to have just 1
     struct for both types... */
  json_t *out;
  
  pcp_key_t *sk = malloc(sizeof(pcp_key_t));

  memcpy(sk->masterpub, pk->masterpub, 32);
  memcpy(sk->pub, pk->pub, 32);
  memcpy(sk->edpub, pk->edpub, 32);
  memcpy(sk->owner, pk->owner, 255);
  memcpy(sk->mail, pk->mail, 255);
  memcpy(sk->id, pk->id, 17);
  sk->ctime = pk->ctime;
  sk->version = pk->version;
  sk->serial = pk->serial;
  sk->type = pk->type;

  out = pcp_sk2json(sk, NULL, 0);
  ucfree(sk, sizeof(pcp_key_t));

  return out;
}

json_t *pcp_sk2json(pcp_key_t *sk, byte *sig, size_t siglen) {
  json_t *jout;
  char *cryptpub, *sigpub, *masterpub, *ssig;
 
  char *jformat = "{sssssssisisisissssssssssss}";

  cryptpub = _bin2hex(sk->pub, 32);
  sigpub   = _bin2hex(sk->edpub, 32);
  masterpub= _bin2hex(sk->masterpub, 32);
  
  if(sig != NULL) {
    ssig     = _bin2hex(sig, siglen);
  }
  else {
    ssig = malloc(1);
    ssig[0] = '\0';
    jformat = "{sssssssisisisissssssssss}";
  }
  
  jout = json_pack(jformat,
		   "id", sk->id,
		   "owner", sk->owner,
		   "mail", sk->mail,
		   "ctime", (int)sk->ctime,
		   "expire", (int)sk->ctime+31536000,
		   "version", (int)sk->version,
		   "serial", (int)sk->serial,
		   "type", "public",
		   "cipher", EXP_PK_CIPHER_NAME,
		   "cryptpub", cryptpub,
		   "sigpub", sigpub,
		   "masterpub", masterpub,
		   "signature", ssig
		   );

  free(cryptpub);
  free(sigpub);
  free(masterpub);
  if(sig != NULL)
    free(ssig);

  return jout;
}

Buffer *pcp_export_json_secret(PCPCTX *ptx, pcp_key_t *sk, byte *nonce, byte *cipher, size_t clen) {
  Buffer *b = buffer_new_str("jsonbuf");
  char *jdump, *xcipher, *xnonce;
  json_t *jout;
  json_error_t jerror;
  
  assert(ptx->json);

  jout = pcp_sk2json(sk, NULL, 0);

  xcipher = _bin2hex(cipher, clen);
  xnonce  = _bin2hex(nonce, crypto_secretbox_NONCEBYTES);

  json_object_set(jout, "type", json_string("secret"));
  json_object_set(jout, "secrets", json_string(xcipher));
  json_object_set(jout, "nonce", json_string(xnonce));

  jdump  = json_dumps(jout, JSON_INDENT(4) | JSON_PRESERVE_ORDER);

  if(jdump != NULL) {
    buffer_add(b, jdump, strlen(jdump));
    free(jdump);
  }
  else {
    fatal(ptx, "JSON encoding error: %s", jerror.text);
  }
  
  json_decref(jout);
  
  return b;
}

Buffer *pcp_export_json_pub(PCPCTX *ptx, pcp_key_t *sk, byte *sig, size_t siglen) {
  Buffer *b = buffer_new_str("jsonbuf");
  char *jdump;
  json_t *jout;
  json_error_t jerror;
  
  assert(ptx->json);

  jout = pcp_sk2json(sk, sig, siglen);
  jdump  = json_dumps(jout, JSON_INDENT(4) | JSON_PRESERVE_ORDER);

  if(jdump != NULL) {
    buffer_add_str(b, jdump);
    free(jdump);
  }
  else {
    fatal(ptx, "JSON encoding error: %s", jerror.text);
  }
  
  json_decref(jout);
  
  return b;
}

Buffer *pcp_import_secret_json(PCPCTX *ptx, Buffer *json) {
  json_error_t jerror;
  json_t *jtmp, *jin;
  size_t maxblob = 2048;
  size_t binlen;
  char *hexerr = "failed to decode hex string";
  
  jin = json_loadb((char *)buffer_get(json), buffer_size(json), JSON_DISABLE_EOF_CHECK, &jerror);
  if(jin == NULL)
    goto jirr1;

  byte *blob = ucmalloc(maxblob);
  /* re-use the buffer */
  json->end = 0;
  json->offset = 0;

  jtmp = json_object_get(jin, "nonce");
  if(jtmp == NULL)
    goto jirr2;
  binlen = _hex2bin(json_string_value(jtmp), blob, maxblob);
  if(binlen > 1)
    buffer_add(json, blob, binlen);
  else {
    strcpy(jerror.text, hexerr);
    goto jirr2;
  }
  
  jtmp = json_object_get(jin, "secrets");
  if(jtmp == NULL)
    goto jirr2;
  binlen = _hex2bin(json_string_value(jtmp), blob, maxblob);
  if(binlen > 1)
    buffer_add(json, blob, binlen);
  else {
    strcpy(jerror.text, hexerr);
    goto jirr2;
  }
  
  json_decref(jin);
  ucfree(blob, maxblob);
  return json;
  
 jirr2:
  ucfree(blob, maxblob);
  json_decref(jin);
  
 jirr1:
  fatal(ptx, "JSON decoding error: %s", jerror.text);
  return NULL;
}

pcp_ks_bundle_t *pcp_import_pub_json(PCPCTX *ptx, byte *raw, size_t rawsize) {
  pcp_ks_bundle_t *b = NULL;
  pcp_keysig_t *s = NULL;
  pcp_pubkey_t *p = NULL;
  json_error_t jerror;
  json_t *jin, *jtmp;
  byte *blob;
  size_t maxblob = 2048;
  const char *stmp;
  char *hexerr = "failed to decode hex string";
  
  jin = json_loadb((char *)raw, rawsize, JSON_DISABLE_EOF_CHECK, &jerror);
  if(jin == NULL)
    goto jerr1;
  
  p = ucmalloc(sizeof(pcp_pubkey_t));
  s =  ucmalloc(sizeof(pcp_keysig_t));
  b =  ucmalloc(sizeof(pcp_ks_bundle_t));
  blob = ucmalloc(maxblob);
  
  jtmp = json_object_get(jin, "id");
  if(jtmp == NULL)
    goto jerr2;
  memcpy(p->id, json_string_value(jtmp), 17);

  jtmp = json_object_get(jin, "cryptpub");
  if(jtmp == NULL)
    goto jerr2;
  if(_hex2bin(json_string_value(jtmp), blob, maxblob) == 32)
    memcpy(p->pub, blob, 32);
  else {
    strcpy(jerror.text, hexerr);
    goto jerr2;
  }

  jtmp = json_object_get(jin, "sigpub");
  if(jtmp == NULL)
    goto jerr2;
  if(_hex2bin(json_string_value(jtmp), blob, maxblob) == 32)
    memcpy(p->edpub, blob, 32);
  else {
    strcpy(jerror.text, hexerr);
    goto jerr2;
  }

  jtmp = json_object_get(jin, "masterpub");
  if(jtmp == NULL)
    goto jerr2;
  if(_hex2bin(json_string_value(jtmp), blob, maxblob) == 32)
    memcpy(p->masterpub, blob, 32);
  else {
    strcpy(jerror.text, hexerr);
    goto jerr2;
  }

  jtmp = json_object_get(jin, "owner");
  if(jtmp == NULL)
    goto jerr2;
  stmp = json_string_value(jtmp);
  if(stmp != NULL)
    strcpy(p->owner, stmp);
  else
    goto jerr2;
  
  jtmp = json_object_get(jin, "mail");
  if(jtmp == NULL)
    goto jerr2;
  stmp = json_string_value(jtmp);
  if(stmp != NULL)
    strcpy(p->mail, stmp);
  else
    goto jerr2;

  jtmp = json_object_get(jin, "ctime");
  if(jtmp == NULL)
    goto jerr2;
  p->ctime = (uint64_t)json_integer_value(jtmp);

  jtmp = json_object_get(jin, "version");
  if(jtmp == NULL)
    goto jerr2;
  p->version = (uint32_t)json_integer_value(jtmp);

  jtmp = json_object_get(jin, "serial");
  if(jtmp == NULL)
    goto jerr2;
  p->serial = (uint32_t)json_integer_value(jtmp);
  
  jtmp = json_object_get(jin, "type");
  if(jtmp == NULL)
    goto jerr2;
  if(json_string_value(jtmp)[0] == 'p')
    p->type = PCP_KEY_TYPE_PUBLIC;
  else {
    strcpy(jerror.text, "key type is not public");
    goto jerr2;
  }

  b->p = p;
  b->s = NULL;

  /*
    10 - header
    96 - keys
    n  - sigblob
     crypto_generichash_BYTES_MAX - sig
   */

  jtmp = json_object_get(jin, "signature");
  if(jtmp == NULL)
    goto jerr2;
  size_t siglen = _hex2bin(json_string_value(jtmp), blob, maxblob);
  if(siglen > 1) {
    /* we're fakin' an rfc blob here, so that _check_hash_keysig()
       get's what it expects and we don't have to implement it twice */
    Buffer *btmp = buffer_new(128, "btmp");
    byte fake[10] = { 0x00 };
    buffer_add(btmp, fake, 10);
    buffer_add(btmp, blob, siglen);

    btmp->offset = buffer_size(btmp) -
      (crypto_sign_BYTES + crypto_generichash_BYTES_MAX); /* 32*3 keys + 10 header */

    if(_check_hash_keysig(ptx, btmp, p, s) != 0) {
      b->s = NULL;
    }
    else {
      b->s = s;
    }
    buffer_free(btmp);
  }
  else {
    strcpy(jerror.text, "sigerr");
    goto jerr2;
  }

    return b;

 jerr2:
  free(p);
  free(s);
  free(b);
  free(blob);
  json_decref(jin);
  
 jerr1:
  fatal(ptx, "JSON decoding error: %s", jerror.text);
  return NULL;
}
#endif
