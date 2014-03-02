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

    if(buffer_get_chunk(blob, notation, nsize) == 0)
      return 1;

    notation[nsize] = '\0';

    if(strncmp(notation, "owner", 5) == 0) {
      if(buffer_get_chunk(blob, p->owner, vsize) == 0)
	return 1;
    }
    else if(strncmp(notation, "mail", 4) == 0) {
      if(buffer_get_chunk(blob, p->mail, vsize) == 0)
	return 1;
    }
    else if(strncmp(notation, "serial", 6) == 0) {
      p->serial = buffer_get32na(blob);
    }
    ucfree(notation, nsize);
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

  byte *signature = ucmalloc(sigsize);
  if(buffer_get_chunk(blob, signature, sigsize) == 0)
    goto chker1;

  /* fill the keysig */
  sk->type = PCP_KEYSIG_NATIVE;
  
  /* everything minus version, ctime and cipher, 1st 3 fields */
  sk->size = blobstop - 6;
  memcpy(sk->id, p->id, 17);

  /* put the whole signature blob into our keysig */
  blob->offset = 6; /* woah, hack :) */
  sk->blob = ucmalloc(sk->size);
  buffer_get_chunk(blob, sk->blob, sk->size);

  /* verify the signature */
  byte *verifyhash = pcp_ed_verify_key(signature, sigsize, p);
  if(verifyhash == NULL)
    goto chker1;

  /* re-calculate the hash */
  crypto_generichash_state *st = ucmalloc(sizeof(crypto_generichash_state));
  byte *hash = ucmalloc(crypto_generichash_BYTES_MAX);
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

pcp_ks_bundle_t *pcp_import_pub(byte *raw, size_t rawsize) {
  size_t clen;
  byte *bin = NULL;
  char *z85 = NULL;

  if(rawsize == 0) {
    fatal("Input file is empty!\n");
    return NULL;
  }

  Buffer *blob = buffer_new(512, "importblob");

  /* first, try to decode the input */
  z85 = pcp_readz85string(raw, rawsize);

  if(z85 != NULL)
    bin = pcp_z85_decode(z85, &clen);

  if(bin == NULL) {
    /* treat as binary blob */
    fatals_reset();
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
    return pcp_import_pub_rfc(blob);
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

  /* check sig header */
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
  char *date  = ucmalloc(19);
  char *ignore = ucmalloc(46);
  char *parts = NULL;
  byte *sig = ucmalloc(crypto_sign_BYTES);;
  int pnum;
  pbp_pubkey_t *b = ucmalloc(sizeof(pbp_pubkey_t));
  pcp_pubkey_t *tmp = ucmalloc(sizeof(pcp_pubkey_t));
  pcp_pubkey_t *pub = ucmalloc(sizeof(pcp_pubkey_t));

  buffer_get_chunk(blob, sig, crypto_sign_BYTES);

  /* make sure it's a pbp */
  if(_buffer_is_binary(sig, crypto_sign_BYTES) == 0) {
    fatal("failed to recognize input, that's probably no key\n");
    goto errimp2;
  }

  buffer_get_chunk(blob, b->sigpub, crypto_sign_PUBLICKEYBYTES);
  buffer_get_chunk(blob, b->edpub, crypto_sign_PUBLICKEYBYTES);
  buffer_get_chunk(blob, b->pub, crypto_box_PUBLICKEYBYTES);
  buffer_get_chunk(blob, date, 18);

  date[19] = '\0';
  struct tm c;
  if(strptime(date, "%Y-%m-%dT%H:%M:%S", &c) == NULL) {
    fatal("Failed to parse creation time in PBP public key file (<%s>)\n", date);
    free(date);
    goto errimp2;
  }
  
  buffer_get_chunk(blob, ignore, 46);
  free(ignore);
  memcpy(b->name, buffer_get(blob), buffer_left(blob));

  /*  parse the name */
  parts = strtok (b->name, "<>");
  pnum = 0;
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

  /* edpub used for signing, might differ */
  memcpy(tmp->edpub, b->sigpub, crypto_sign_PUBLICKEYBYTES);

  byte *verify = pcp_ed_verify(buffer_get(blob), buffer_size(blob), tmp);
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
  }
  
  return bundle;

 errimp2:
  return NULL;
}

Buffer *pcp_export_yaml_pub(pcp_key_t *sk) {
  Buffer *b = buffer_new_str("yamlbuf");
  struct tm *c;
  time_t t = time(0);
  c = localtime(&t);

  buffer_add_str(b, "#\n# YAML export of public key\n");
  buffer_add_str(b, "# Generated on: %04d-%02d-%02dT%02d:%02d:%02d\n",
		 c->tm_year+1900, c->tm_mon+1, c->tm_mday,
		 c->tm_hour, c->tm_min, c->tm_sec);
  buffer_add_str(b, "---\n");

  buffer_add_str(b, "id:         %s\n", sk->id);
  buffer_add_str(b, "owner:      %s\n", sk->owner);
  buffer_add_str(b, "mail:       %s\n", sk->mail);
  buffer_add_str(b, "ctime:      %ld\n", (long int)sk->ctime);
  buffer_add_str(b, "version:    %08x\n", sk->version);
  buffer_add_str(b, "serial:     %08x\n", sk->serial);
  buffer_add_str(b, "type:       public\n");
  buffer_add_str(b, "cryptpub:   "); buffer_add_hex(b, sk->pub, 32); buffer_add_str(b, "\n");
  buffer_add_str(b, "sigpub:     "); buffer_add_hex(b, sk->edpub, 32); buffer_add_str(b, "\n");
  buffer_add_str(b, "masterpub:  "); buffer_add_hex(b, sk->masterpub, 32); buffer_add_str(b, "\n");

  return b;
}

Buffer *pcp_export_perl_pub(pcp_key_t *sk) {
  Buffer *b = buffer_new_str("perlbuf");
  struct tm *c;
  time_t t = time(0);
  c = localtime(&t);
  size_t i;

  buffer_add_str(b, "#\n# Perl export of public key\n");
  buffer_add_str(b, "# Generated on: %04d-%02d-%02dT%02d:%02d:%02d\n",
		 c->tm_year+1900, c->tm_mon+1, c->tm_mday,
		 c->tm_hour, c->tm_min, c->tm_sec);
  buffer_add_str(b, "# \nmy %%key = (\n");

  buffer_add_str(b, "            id       => \"%s\",\n", sk->id);
  buffer_add_str(b, "            owner    => \"%s\",\n", sk->owner);
  buffer_add_str(b, "            mail     => '%s',\n", sk->mail); 
  buffer_add_str(b, "            ctime    => %ld,\n", (long int)sk->ctime);
  buffer_add_str(b, "            version  => x%08x,\n", sk->version);
  buffer_add_str(b, "            serial   => x%08x,\n", sk->serial);
  buffer_add_str(b, "            type     => \"public\",\n");

  buffer_add_str(b, "            cryptpub => [");
  for (i=0; i<31; ++i) {
    buffer_add_str(b, "x%02x,", sk->pub[i]);
    if(i % 8 == 7 && i > 0)
      buffer_add_str(b, "\n                          ");
  }
  buffer_add_str(b, "x%02x],\n", sk->pub[31]);

  buffer_add_str(b, "            sigpub =>    [");
  for (i=0; i<31; ++i) {
    buffer_add_str(b, "x%02x,", sk->edpub[i]);
    if(i % 8 == 7 && i > 0)
      buffer_add_str(b, "\n                          ");
  }
  buffer_add_str(b, "x%02x],\n", sk->edpub[31]);
  
  buffer_add_str(b, "            masterpub => [");
  for (i=0; i<31; ++i) {
    buffer_add_str(b, "x%02x,", sk->masterpub[i]);
    if(i % 8 == 7 && i > 0)
      buffer_add_str(b, "\n                          ");
  }
  buffer_add_str(b, "x%02x]\n", sk->masterpub[31]);

  buffer_add_str(b, ");\n");
  

  return b;
}

void pcp_export_c_pub_var(Buffer *b, char *var, byte *d, size_t len) {
  buffer_add_str(b, "byte %s[%ld] = {\n  ", var, len);
  size_t i;
  for(i=0; i<len-1; ++i) {
    buffer_add_str(b, "0x%02x, ", (unsigned int)d[i]);
    if (i % 8 == 7) buffer_add_str(b, "\n  ");
  }
  buffer_add_str(b, "0x%02x\n};\n", (unsigned int)d[i]);

}

Buffer *pcp_export_c_pub(pcp_key_t *sk) {
  Buffer *b = buffer_new_str("c-buf");
  struct tm *c;
  time_t t = time(0);
  c = localtime(&t);

  buffer_add_str(b, "/*\n * C export of public key\n");
  buffer_add_str(b, " * Generated on: %04d-%02d-%02dT%02d:%02d:%02d\n",
		 c->tm_year+1900, c->tm_mon+1, c->tm_mday,
		 c->tm_hour, c->tm_min, c->tm_sec);
  buffer_add_str(b, " */\n");

  buffer_add_str(b, "char id[] = \"%s\";\n", sk->id);
  buffer_add_str(b, "char owner[] = \"%s\";\n", sk->owner);
  buffer_add_str(b, "char mail[] = \"%s\";\n", sk->mail);
  buffer_add_str(b, "uint64_t ctime = %ld;\n", sk->ctime);
  buffer_add_str(b, "uint32_t version = 0x%08x;\n", sk->version);
  buffer_add_str(b, "uint32_t serial = 0x%08x;\n", sk->serial);
  buffer_add_str(b, "char[] type = \"public\";\n");

  pcp_export_c_pub_var(b, "cryptpub", sk->pub, 32);
  pcp_export_c_pub_var(b, "sigpub", sk->pub, 32);
  pcp_export_c_pub_var(b, "masterpub", sk->pub, 32);

  return b;
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


Buffer *pcp_export_rfc_pub (pcp_key_t *sk) {
  Buffer *out = buffer_new(320, "exportbuf");
  Buffer *raw = buffer_new(256, "keysigbuf");

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

  /* and that's it. wasn't that easy? :) */
  buffer_free(raw);
  memset(hash, 0, crypto_generichash_BYTES_MAX);
  free(hash);
  memset(sig, 0, crypto_sign_BYTES + crypto_generichash_BYTES_MAX);
  free(sig);

  return out;
}

Buffer *pcp_export_secret(pcp_key_t *sk, char *passphrase) {
  byte *nonce = NULL;
  byte *symkey = NULL;
  byte *cipher = NULL;
  size_t es;

  Buffer *raw = buffer_new(512, "secretbuf");
  Buffer *out = buffer_new(512, "secretciperblob");

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
  symkey = pcp_scrypt(passphrase, strlen(passphrase), nonce, crypto_secretbox_NONCEBYTES);

  es = pcp_sodium_mac(&cipher, buffer_get(raw), buffer_size(raw), nonce, symkey);

  buffer_add(out, nonce, crypto_secretbox_NONCEBYTES);
  buffer_add(out, cipher, es);

  buffer_free(raw);
  ucfree(nonce, crypto_secretbox_NONCEBYTES);
  ucfree(symkey, 64);
  ucfree(cipher, es);

  return out;
}

pcp_key_t *pcp_import_secret(byte *raw, size_t rawsize, char *passphrase) {
  size_t clen;
  byte *bin = NULL;
  char *z85 = NULL;

  if(rawsize == 0) {
    fatal("Input file is empty!\n");
    return NULL;
  }

  Buffer *blob = buffer_new(512, "importskblob");

  /* first, try to decode the input */
  z85 = pcp_readz85string(raw, rawsize);
  if(z85 != NULL)
    bin = pcp_z85_decode(z85, &clen);

  if(bin == NULL) {
    /* treat as binary blob */
    fatals_reset();
    buffer_add(blob, raw, rawsize);
  }
  else {
    /* use decoded */
    buffer_add(blob, bin, clen);
    ucfree(bin, clen);
  }

  /* now we've got the blob, parse it */
  return pcp_import_secret_native(blob, passphrase);
}

pcp_key_t *pcp_import_secret_native(Buffer *cipher, char *passphrase) {
  pcp_key_t *sk = ucmalloc(sizeof(pcp_key_t));
  byte *nonce = ucmalloc(crypto_secretbox_NONCEBYTES);
  byte *symkey = NULL;
  byte *clear = NULL;
  size_t cipherlen = 0;
  size_t minlen = (64 * 2) + (32 * 4) + 8 + 4 + 4;
  uint16_t notationlen = 0;

  Buffer *blob = buffer_new(512, "secretdecryptbuf");

  if(buffer_get_chunk(cipher, nonce, crypto_secretbox_NONCEBYTES) == 0)
    goto impserr1;

  symkey = pcp_scrypt(passphrase, strlen(passphrase), nonce, crypto_secretbox_NONCEBYTES);

  cipherlen = buffer_left(cipher);
  if(cipherlen < minlen) {
    fatal("expected decrypted secret key size %ld is less than minimum len %ld\n", cipherlen, minlen);
    goto impserr1;
  }

  /* decrypt the blob */
  if(pcp_sodium_verify_mac(&clear, buffer_get_remainder(cipher),
			   cipherlen, nonce, symkey) != 0) {
    fatal("failed to decrypt the secret key file\n");
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
  if(notationlen > 0)
    buffer_get_chunk(blob, sk->owner, notationlen);

  notationlen = buffer_get16na(blob);
  if(notationlen > 0)
    buffer_get_chunk(blob, sk->mail, notationlen);

  if(buffer_done(blob) == 1)
    goto impserr2;

  sk->ctime = buffer_get64na(blob);
  sk->version = buffer_get32na(blob);
  sk->serial = buffer_get32na(blob);

  /* ready */
  ucfree(clear, cipherlen - PCP_CRYPTO_ADD);
  ucfree(nonce, crypto_secretbox_NONCEBYTES);
  buffer_free(blob);

  /* fill in the calculated fields */
  memcpy (sk->id, pcp_getkeyid(sk), 17);
  sk->type = PCP_KEY_TYPE_SECRET;

  return sk;

 impserr2:
  ucfree(clear, cipherlen - PCP_CRYPTO_ADD);

 impserr1:
  ucfree(nonce, crypto_secretbox_NONCEBYTES);
  ucfree(sk, sizeof(pcp_key_t));
  buffer_free(blob);
  return NULL;
}
