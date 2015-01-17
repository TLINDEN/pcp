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
#include "context.h"

/*
 * AS of 16/01/2014 I'm using scrypt() instead of my crafted key
 * derivation function. However, I create a hash from the pcp_scrypt()
 * result anyway because I need a curve25519 secret.
 */
byte *pcp_derivekey(PCPCTX *ptx, char *passphrase, byte *nonce) {
  byte *key = smalloc(crypto_secretbox_KEYBYTES);
  size_t plen = strnlen(passphrase, 255);

  /*  create the scrypt hash */
  byte *scrypted = pcp_scrypt(ptx, passphrase, plen, nonce, crypto_secretbox_NONCEBYTES);

  /*  make a hash from the scrypt() result */
  crypto_hash_sha256(key, (byte*)scrypted, 64);

  /*  turn the 32byte hash into a secret key */
  key[0]  &= 248;
  key[31] &= 127;
  key[31] |= 64;

  /* done */
  sfree(scrypted);
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

  char *id = pcp_getkeyid(key);
  memcpy (key->id, id, 17);
  free(id);

  key->ctime = (long)time(0);

  key->version = PCP_KEY_VERSION;
  key->serial  = arc4random();
  key->type    = PCP_KEY_TYPE_SECRET;

  key->owner[0] = '\0';
  key->mail[0] = '\0';

  /* clean up */
  ucfree(ms, 64);
  ucfree(ss, 64);
  ucfree(mp, 32);
  ucfree(sp, 32);
  ucfree(cs, 32);
  ucfree(cp, 32);

  return key;
}

byte * pcp_gennonce() {
  byte *nonce = ucmalloc(crypto_secretbox_NONCEBYTES);
  arc4random_buf(nonce, crypto_secretbox_NONCEBYTES);
  return nonce;
}

void pcpkey_setowner(pcp_key_t *key, char *owner, char *mail) {
  strcpy(key->owner, owner);
  strcpy(key->mail, mail);
}

pcp_key_t *pcpkey_encrypt(PCPCTX *ptx, pcp_key_t *key, char *passphrase) {
  if(key->nonce[0] == 0) {
    byte *nonce = pcp_gennonce();
    memcpy (key->nonce, nonce, crypto_secretbox_NONCEBYTES);
    ucfree(nonce, crypto_secretbox_NONCEBYTES);
  }

  byte *encryptkey = pcp_derivekey(ptx, passphrase, key->nonce);  

  byte *encrypted;
  size_t es;

  Buffer *both = buffer_new(128, "keypack");
  buffer_add(both, key->mastersecret, 64);
  buffer_add(both, key->edsecret, 64);
  buffer_add(both, key->secret, 32);

  es = pcp_sodium_mac(&encrypted, buffer_get(both), buffer_size(both), key->nonce, encryptkey);

  buffer_free(both);
  sfree(encryptkey);

  if(es == 176) { /* FIXME: calc! */
    /*  success */
    memcpy(key->encrypted, encrypted, 176);
    ucfree(encrypted, es);
    arc4random_buf(key->secret, 32);
    arc4random_buf(key->edsecret, 64);
    arc4random_buf(key->mastersecret, 64);
    key->secret[0] = 0;
    key->edsecret[0] = 0;
    key->mastersecret[0] = 0;
  }
  else {
    fatal(ptx, "failed to encrypt the secret key!\n");
    ucfree(encrypted, es);
    ucfree(key, sizeof(pcp_key_t));
    return NULL;
  }

  return key;
}

pcp_key_t *pcpkey_decrypt(PCPCTX *ptx, pcp_key_t *key, char *passphrase) {
  byte *encryptkey = pcp_derivekey(ptx, passphrase, key->nonce);  

  byte *decrypted;
  size_t es;
  
  es = pcp_sodium_verify_mac(&decrypted, key->encrypted, 176, key->nonce, encryptkey);

  sfree(encryptkey);

  if(es == 0) {
    /*  success */
    memcpy(key->mastersecret, decrypted, 64);
    memcpy(key->edsecret, decrypted + 64, 64);    
    memcpy(key->secret, decrypted +128, 32);
    ucfree(decrypted, 160);
  }
  else {
    fatal(ptx, "failed to decrypt the secret key (got %d, expected 32)!\n", es);
    ucfree(decrypted, 160);
    return NULL;
  }

  return key;
}

pcp_pubkey_t *pcpkey_pub_from_secret(pcp_key_t *key) {
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

byte *pcppubkey_getchecksum(pcp_pubkey_t *k) {
  byte *hash = ucmalloc(32);
  crypto_hash_sha256(hash, k->pub, 32);
  return hash;
}

byte *pcpkey_getchecksum(pcp_key_t *k) {
  byte *hash = ucmalloc(32);
  crypto_hash_sha256(hash, k->pub, 32);
  return hash;
}


pcp_key_t * key2be(pcp_key_t *k) {
#ifdef __CPU_IS_BIG_ENDIAN
  return k;
#else
  uint32_t version = k->version;
  byte* p = (byte*)&version;
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
  byte* p = (byte*)&version;
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

void pcp_seckeyblob(Buffer *b, pcp_key_t *k) {
  buffer_add(b, k->masterpub, 32);
  buffer_add(b, k->mastersecret, 64);

  buffer_add(b, k->pub, 32);
  buffer_add(b, k->secret, 32);

  buffer_add(b, k->edpub, 32);
  buffer_add(b, k->edsecret, 64);

  buffer_add(b, k->nonce, 24);

  buffer_add(b, k->encrypted, 176);

  buffer_add(b, k->owner, 255);
  buffer_add(b, k->mail, 255);
  buffer_add(b, k->id, 17);

  buffer_add8(b, k->type);
  buffer_add64(b, k->ctime);
  buffer_add32(b, k->version);
  buffer_add32(b, k->serial);
}

void pcp_pubkeyblob(Buffer *b, pcp_pubkey_t *k) {
  buffer_add(b, k->masterpub, 32);
  buffer_add(b, k->sigpub, 32);
  buffer_add(b, k->pub, 32);
  buffer_add(b, k->edpub, 32);

  buffer_add(b, k->owner, 255);
  buffer_add(b, k->mail, 255);
  buffer_add(b, k->id, 17);

  buffer_add8(b, k->type);
  buffer_add64(b, k->ctime);
  buffer_add32(b, k->version);
  buffer_add32(b, k->serial);
  buffer_add8(b, k->valid);
}

Buffer *pcp_keyblob(void *k, int type) {
  if(type == PCP_KEY_TYPE_PUBLIC) {
    Buffer *b = buffer_new(PCP_RAW_PUBKEYSIZE, "bp");
    pcp_pubkeyblob(b, (pcp_pubkey_t *)k);
    return b;
  }
  else {
    Buffer *b = buffer_new(PCP_RAW_KEYSIZE, "bs");
    pcp_seckeyblob(b, (pcp_key_t *)k);
    return b;
  }
}


int pcp_sanitycheck_pub(PCPCTX *ptx, pcp_pubkey_t *key) {
  if(key->pub[0] == 0) {
    fatal(ptx, "Pubkey sanity check: public key contained in key seems to be empty!\n");
    return 1;
  }

  if(key->type != PCP_KEY_TYPE_PUBLIC) {
    fatal(ptx, "Pubkey sanity check: key type is not PUBLIC (expected: %02x, got: %02x)!\n",
	  PCP_KEY_TYPE_PUBLIC, key->type);
    return 1;
  }

  if(key->version != PCP_KEY_VERSION) {
    fatal(ptx, "Pubkey sanity check: unknown key version (expected: %08X, got: %08X)!\n",
	  PCP_KEY_VERSION, key->version);
    return 1;
  }
  
  if(key->serial <= 0) {
    fatal(ptx, "Pubkey sanity check: invalid serial number: %08X!\n", key->serial);
    return 1;
  }

  if(key->id[16] != '\0') {
    char *got = ucmalloc(17);
    memcpy(got, key->id, 17);
    got[16] = '\0';
    fatal(ptx, "Pubkey sanity check: invalid key id (expected 16 bytes, got: %s)!\n", got);
    free(got);
    return 1;
  }

  struct tm *c;
  time_t t = (time_t)key->ctime;
  c = localtime(&t);
  if(c->tm_year <= 0 || c->tm_year > 1100) {
    /*  well, I'm perhaps overacting here :) */
    fatal(ptx, "Pubkey sanity check: invalid creation timestamp (got year %04d)!\n", c->tm_year + 1900);
    return 1;
  }

  pcp_pubkey_t *maybe = pcphash_pubkeyexists(ptx, key->id);
  if(maybe != NULL) {
    fatal(ptx, "Pubkey sanity check: there already exists a key with the id 0x%s\n", key->id);
    return 1;
  }

  return 0;
}


int pcp_sanitycheck_key(PCPCTX *ptx, pcp_key_t *key) {
  if(key->encrypted[0] == 0) {
    fatal(ptx, "Secretkey sanity check: secret key contained in key seems to be empty!\n");
    return 1;
  }

  if(key->type != PCP_KEY_TYPE_SECRET && key->type != PCP_KEY_TYPE_MAINSECRET) {
    fatal(ptx, "Secretkey sanity check: key type is not SECRET (expected: %02x, got: %02x)!\n",
	  PCP_KEY_TYPE_SECRET, key->type);
    return 1;
  }

  if(key->version != PCP_KEY_VERSION) {
    fatal(ptx, "Secretkey sanity check: unknown key version (expected: %08X, got: %08X)!\n",
	  PCP_KEY_VERSION, key->version);
    return 1;
  }
  
  if(key->serial <= 0) {
    fatal(ptx, "Secretkey sanity check: invalid serial number: %08X!\n", key->serial);
    return 1;
  }

  if(key->id[16] != '\0') {
    char *got = ucmalloc(17);
    memcpy(got, key->id, 17);
    got[16] = '\0';
    fatal(ptx, "Secretkey sanity check: invalid key id (expected 16 bytes, got: %s)!\n", got);
    free(got);
    return 1;
  }

  struct tm *c;
  time_t t = (time_t)key->ctime;
  c = localtime(&t);
  if(c->tm_year <= 70 || c->tm_year > 1100) {
    /*  well, I'm perhaps overacting here :) */
    fatal(ptx, "Secretkey sanity check: invalid creation timestamp (got year %04d)!\n", c->tm_year + 1900);
    return 1;
  }

  pcp_key_t *maybe = pcphash_keyexists(ptx, key->id);
  if(maybe != NULL) {
    fatal(ptx, "Secretkey sanity check: there already exists a key with the id 0x%s\n", key->id);
    return 1;
  }

  return 0;
}

void pcp_dumpkey(pcp_key_t *k) {
  int i;

  printf("Dumping pcp_key_t raw values:\n");

  printf("masterpub: ");
  for ( i = 0;i < 32;++i) printf("%02x",(unsigned int) k->masterpub[i]);
  printf("\n");

  printf("   public: ");
  for ( i = 0;i < 32;++i) printf("%02x",(unsigned int) k->pub[i]);
  printf("\n");

  printf("    edpub: ");
  for ( i = 0;i < 32;++i) printf("%02x",(unsigned int) k->edpub[i]);
  printf("\n");

  printf("mastersec: ");
  for ( i = 0;i < 32;++i) printf("%02x",(unsigned int) k->mastersecret[i]);
  printf("\n");

  printf("   secret: ");
  for ( i = 0;i < 32;++i) printf("%02x",(unsigned int) k->secret[i]);
  printf("\n");

  printf(" edsecret: ");
  for ( i = 0;i < 64;++i) printf("%02x",(unsigned int) k->edsecret[i]);
  printf("\n");

  printf("    nonce: ");
  for ( i = 0;i < 24;++i) printf("%02x",(unsigned int) k->nonce[i]);
  printf("\n");

  printf("encrypted: ");
  for ( i = 0;i < 80;++i) printf("%02x",(unsigned int) k->encrypted[i]);
  printf("\n");

  printf("    owner: %s\n", k->owner);

  printf("     mail: %s\n", k->mail);

  printf("       id: %s\n", k->id);

  printf("    ctime: %ld\n", (long int)k->ctime);

  printf("  version: 0x%08X\n", k->version);

  printf("   serial: 0x%08X\n", k->serial);

  printf("     type: 0x%02X\n", k->type);
}


void pcp_dumppubkey(pcp_pubkey_t *k) {
  int i;
  printf("Dumping pcp_pubkey_t raw values:\n");

  printf("masterpub: ");
  for ( i = 0;i < 32;++i) printf("%02x",(unsigned int) k->masterpub[i]);
  printf("\n");

  printf("   public: ");
  for ( i = 0;i < 32;++i) printf("%02x",(unsigned int) k->pub[i]);
  printf("\n");

  printf("    edpub: ");
  for ( i = 0;i < 32;++i) printf("%02x",(unsigned int) k->edpub[i]);
  printf("\n");

  printf("    owner: %s\n", k->owner);

  printf("     mail: %s\n", k->mail);

  printf("       id: %s\n", k->id);

  printf("    ctime: %ld\n", (long int)k->ctime);

  printf("  version: 0x%08X\n", k->version);

  printf("   serial: 0x%08X\n", k->serial);

  printf("     type: 0x%02X\n", k->type);
}
