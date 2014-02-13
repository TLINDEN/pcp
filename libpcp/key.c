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


#include "key.h"
#include "keyhash.h"

/*
 * AS of 16/01/2014 I'm using scrypt() instead of my crafted key
 * derivation function. However, I create a hash from the pcp_scrypt()
 * result anyway because I need a cure25519 secret.
 */
unsigned char *pcp_derivekey(char *passphrase, unsigned char *nonce) {
  unsigned char *key = ucmalloc(crypto_secretbox_KEYBYTES);
  size_t plen = strnlen(passphrase, 255);

  /*  create the scrypt hash */
  unsigned char *scrypted = pcp_scrypt(passphrase, plen, nonce, crypto_secretbox_NONCEBYTES);

  /*  make a hash from the scrypt() result */
  crypto_hash_sha256(key, (unsigned char*)scrypted, 64);

  /*  turn the 32byte hash into a secret key */
  key[0]  &= 248;
  key[31] &= 127;
  key[31] |= 64;

  /* disabled, must be done outside 
     memset(passphrase, 0, plen); */

  return key;
}


char *pcp_getkeyid(pcp_key_t *k) {
  uint32_t s, p;
  p = jen_hash(k->pub, 32, JEN_PSALT);
  s = jen_hash(k->edpub, 32, JEN_SSALT);
  char *id = ucmalloc(17);
  snprintf(id, 17, "%08X%08X", p, s);
  return id;
}

/*  same as above but for imported pbp keys */
char *pcp_getpubkeyid(pcp_pubkey_t *k) {
  uint32_t s, p;
  p = jen_hash(k->pub, 32, JEN_PSALT);
  s = jen_hash(k->edpub, 32, JEN_SSALT);
  char *id = ucmalloc(17);
  snprintf(id, 17, "%08X%08X", p, s);
  return id;
}

void pcp_keypairs(byte *msk, byte *mpk, byte *csk, byte *cpk, byte *esk, byte *epk) {
  /*  generate keypairs from random seed */
  byte *ms = urmalloc(32);
  byte *ss = urmalloc(32);
  byte *cs = urmalloc(32);

  /*  ed25519 master key */
  crypto_sign_seed_keypair(mpk, msk, ms);

  /*  ed25519 signing key */
  crypto_sign_seed_keypair(epk, esk, ss);

  /*  curve25519 secret key */
  memcpy(csk, cs, 32);
  csk[0]  &= 248;
  csk[31] &= 63;
  csk[31] |= 64;

  /*  curve25519 public key */
  crypto_scalarmult_curve25519_base(cpk, csk);

  ucfree(ms, 32);
  ucfree(ss, 32);
  ucfree(cs, 32);
}

pcp_key_t * pcpkey_new () {
  byte *mp = ucmalloc(32);
  byte *ms = ucmalloc(64);
  byte *sp = ucmalloc(32);
  byte *ss = ucmalloc(64);
  byte *cp = ucmalloc(32);
  byte *cs = ucmalloc(32);

  /* generate key material */
  pcp_keypairs(ms, mp, cs, cp, ss, sp);

  /*  fill in our struct */
  pcp_key_t *key = urmalloc(sizeof(pcp_key_t));
  memcpy (key->masterpub, mp, 32);
  memcpy (key->mastersecret, ms, 64);
  memcpy (key->pub, cp, 32);
  memcpy (key->secret, cs, 32);
  memcpy (key->edpub, sp, 32);
  memcpy (key->edsecret, ss, 64);
  memcpy (key->id, pcp_getkeyid(key), 17);
  
  key->ctime = (long)time(0);

  key->version = PCP_KEY_VERSION;
  key->serial  = arc4random();
  key->type    = PCP_KEY_TYPE_SECRET;

  /* clean up */
  ucfree(ms, 64);
  ucfree(ss, 64);
  ucfree(mp, 32);
  ucfree(sp, 32);
  ucfree(cs, 32);
  ucfree(cp, 32);

  return key;
}

unsigned char * pcp_gennonce() {
  unsigned char *nonce = ucmalloc(crypto_secretbox_NONCEBYTES);
  arc4random_buf(nonce, crypto_secretbox_NONCEBYTES);
  return nonce;
}

pcp_key_t *pcpkey_encrypt(pcp_key_t *key, char *passphrase) {
  if(key->nonce[0] == 0) {
    unsigned char *nonce = pcp_gennonce();
    memcpy (key->nonce, nonce, crypto_secretbox_NONCEBYTES);
  }

  unsigned char *encryptkey = pcp_derivekey(passphrase, key->nonce);  

  unsigned char *encrypted;
  size_t es;

  Buffer *both = buffer_new(128, "keypack");
  buffer_add(both, key->mastersecret, 64);
  buffer_add(both, key->edsecret, 64);
  buffer_add(both, key->secret, 32);

  es = pcp_sodium_mac(&encrypted, buffer_get(both), buffer_size(both), key->nonce, encryptkey);

  memset(encryptkey, 0, 32);
  buffer_free(both);
  free(encryptkey);

  if(es == 176) {
    /*  success */
    memcpy(key->encrypted, encrypted, 176);
    arc4random_buf(key->secret, 32);
    arc4random_buf(key->edsecret, 64);
    arc4random_buf(key->mastersecret, 64);
    key->secret[0] = 0;
    key->edsecret[0] = 0;
    key->mastersecret[0] = 0;
  }
  else {
    fatal("failed to encrypt the secret key!\n");
    free(key);
    return NULL;
  }

  return key;
}

pcp_key_t *pcpkey_decrypt(pcp_key_t *key, char *passphrase) {
  unsigned char *encryptkey = pcp_derivekey(passphrase, key->nonce);  

  unsigned char *decrypted;
  size_t es;
  
  es = pcp_sodium_verify_mac(&decrypted, key->encrypted, 176, key->nonce, encryptkey);

  memset(encryptkey, 0, 32);
  free(encryptkey);

  if(es == 0) {
    /*  success */
    memcpy(key->mastersecret, decrypted, 64);
    memcpy(key->edsecret, decrypted + 64, 64);    
    memcpy(key->secret, decrypted +128, 32);
  }
  else {
    fatal("failed to decrypt the secret key (got %d, expected 32)!\n", es);
    free(key);
    return NULL;
  }

  return key;
}

pcp_pubkey_t *pcpkey_pub_from_secret(pcp_key_t *key) {
  /* pcp_dumpkey(key); */
  pcp_pubkey_t *pub = urmalloc(sizeof (pcp_pubkey_t));
  memcpy(pub->masterpub, key->masterpub, 32);
  memcpy(pub->pub, key->pub, 32);
  memcpy(pub->edpub, key->edpub, 32);
  memcpy(pub->owner, key->owner, 255);
  memcpy(pub->mail, key->mail, 255);
  memcpy(pub->id, key->id, 17);
  pub->version = key->version;
  pub->type    = PCP_KEY_TYPE_PUBLIC;
  pub->ctime   = key->ctime;
  pub->serial  = key->serial;
  return pub;
}

char *pcppubkey_get_art(pcp_pubkey_t *k) {
  char *r = key_fingerprint_randomart(k->pub, sizeof(k));
  return r;
}

char *pcpkey_get_art(pcp_key_t *k) {
  char *r = key_fingerprint_randomart(k->pub, sizeof(k));
  return r;
}

unsigned char *pcppubkey_getchecksum(pcp_pubkey_t *k) {
  unsigned char *hash = ucmalloc(32);
  crypto_hash_sha256(hash, k->pub, 32);
  return hash;
}

unsigned char *pcpkey_getchecksum(pcp_key_t *k) {
  unsigned char *hash = ucmalloc(32);
  crypto_hash_sha256(hash, k->pub, 32);
  return hash;
}


pcp_key_t * key2be(pcp_key_t *k) {
#ifdef __CPU_IS_BIG_ENDIAN
  return k;
#else
  uint32_t version = k->version;
  unsigned char* p = (unsigned char*)&version;
  if(p[0] != 0) {
    k->version = htobe32(k->version);
    k->serial  = htobe32(k->serial);
    k->ctime   = htobe64(k->ctime);
  }
  return k;
#endif
}

pcp_key_t *key2native(pcp_key_t *k) {
#ifdef __CPU_IS_BIG_ENDIAN
  return k;
#else
  k->version = be32toh(k->version);
  k->serial  = be32toh(k->serial);
  k->ctime   = be64toh(k->ctime);
  return k;
#endif
}

pcp_pubkey_t * pubkey2be(pcp_pubkey_t *k) {
#ifdef __CPU_IS_BIG_ENDIAN
  return k;
#else
  uint32_t version = k->version;
  unsigned char* p = (unsigned char*)&version;
  if(p[0] != 0) {
    k->version = htobe32(k->version);
    k->serial  = htobe32(k->serial);
    k->ctime   = htobe64(k->ctime);
  }
  return k;
#endif
}

pcp_pubkey_t *pubkey2native(pcp_pubkey_t *k) {
#ifdef __CPU_IS_BIG_ENDIAN
  return k;
#else
  k->version = be32toh(k->version);
  k->serial  = be32toh(k->serial);
  k->ctime   = be64toh(k->ctime);
  return k;
#endif
}

void pcp_seckeyblob(void *blob, pcp_key_t *k) {
  memcpy(blob, k, PCP_RAW_KEYSIZE);
}

void pcp_pubkeyblob(void *blob, pcp_pubkey_t *k) {
  memcpy(blob, k, PCP_RAW_PUBKEYSIZE);
}

void *pcp_keyblob(void *k, int type) {
  void *blob;
  if(type == PCP_KEY_TYPE_PUBLIC) {
    blob = ucmalloc(PCP_RAW_PUBKEYSIZE);
    pcp_pubkeyblob(blob, (pcp_pubkey_t *)k);
  }
  else {
    blob = ucmalloc(PCP_RAW_KEYSIZE);
    pcp_seckeyblob(blob, (pcp_key_t *)k);
  }
  return blob;
}


int pcp_sanitycheck_pub(pcp_pubkey_t *key) {
  if(key->pub[0] == 0) {
    fatal("Pubkey sanity check: public key contained in key seems to be empty!\n");
    return 1;
  }

  if(key->type != PCP_KEY_TYPE_PUBLIC) {
    fatal("Pubkey sanity check: key type is not PUBLIC (expected: %02x, got: %02x)!\n",
	  PCP_KEY_TYPE_PUBLIC, key->type);
    return 1;
  }

  if(key->version != PCP_KEY_VERSION) {
    fatal("Pubkey sanity check: unknown key version (expected: %08X, got: %08X)!\n",
	  PCP_KEY_VERSION, key->version);
    return 1;
  }
  
  if(key->serial <= 0) {
    fatal("Pubkey sanity check: invalid serial number: %08X!\n", key->serial);
    return 1;
  }

  if(key->id[16] != '\0') {
    char *got = ucmalloc(17);
    memcpy(got, key->id, 17);
    got[16] = '\0';
    fatal("Pubkey sanity check: invalid key id (expected 16 bytes, got: %s)!\n", got);
    free(got);
    return 1;
  }

  struct tm *c;
  time_t t = (time_t)key->ctime;
  c = localtime(&t);
  if(c->tm_year <= 0 || c->tm_year > 1100) {
    /*  well, I'm perhaps overacting here :) */
    fatal("Pubkey sanity check: invalid creation timestamp (got year %04d)!\n", c->tm_year + 1900);
    return 1;
  }

  pcp_pubkey_t *maybe = pcphash_pubkeyexists(key->id);
  if(maybe != NULL) {
    fatal("Pubkey sanity check: there already exists a key with the id 0x%s\n", key->id);
    return 1;
  }

  return 0;
}


int pcp_sanitycheck_key(pcp_key_t *key) {
  if(key->encrypted[0] == 0) {
    fatal("Secretkey sanity check: secret key contained in key seems to be empty!\n");
    return 1;
  }

  if(key->type != PCP_KEY_TYPE_SECRET && key->type != PCP_KEY_TYPE_MAINSECRET) {
    fatal("Secretkey sanity check: key type is not SECRET (expected: %02x, got: %02x)!\n",
	  PCP_KEY_TYPE_SECRET, key->type);
    return 1;
  }

  if(key->version != PCP_KEY_VERSION) {
    fatal("Secretkey sanity check: unknown key version (expected: %08X, got: %08X)!\n",
	  PCP_KEY_VERSION, key->version);
    return 1;
  }
  
  if(key->serial <= 0) {
    fatal("Secretkey sanity check: invalid serial number: %08X!\n", key->serial);
    return 1;
  }

  if(key->id[16] != '\0') {
    char *got = ucmalloc(17);
    memcpy(got, key->id, 17);
    got[16] = '\0';
    fatal("Secretkey sanity check: invalid key id (expected 16 bytes, got: %s)!\n", got);
    free(got);
    return 1;
  }

  struct tm *c;
  time_t t = (time_t)key->ctime;
  c = localtime(&t);
  if(c->tm_year <= 0 || c->tm_year > 1100) {
    /*  well, I'm perhaps overacting here :) */
    fatal("Secretkey sanity check: invalid creation timestamp (got year %04d)!\n", c->tm_year + 1900);
    return 1;
  }

  pcp_key_t *maybe = pcphash_keyexists(key->id);
  if(maybe != NULL) {
    fatal("Secretkey sanity check: there already exists a key with the id 0x%s\n", key->id);
    return 1;
  }

  return 0;
}

