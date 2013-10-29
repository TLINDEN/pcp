#include "key.h"

char *pcp_getkeyid(pcp_key_t *k) {
  uint32_t s, p;
  p = jen_hash(k->public, 32, JEN_PSALT);
  s = jen_hash(k->secret, 32, JEN_SSALT);
  char *id = ucmalloc(17);
  snprintf(id, 17, "%08X%08X", p, s);
  return id;
}

pcp_key_t * pcpkey_new () {
  byte public[32] = { 0 };
  byte secret[32] = { 0 };

  // generate curve 25519 keypair
  if(crypto_box_keypair (public, secret) != 0) {
    fatal("Failed to generate a CURVE25519 keypair!\n");
    return NULL;
  }

  // fill in our struct
  pcp_key_t *key = urmalloc(sizeof(pcp_key_t));
  memcpy (key->public, public, 32);
  memcpy (key->secret, secret, 32);
  memcpy (key->id, pcp_getkeyid(key), 17);
  
  key->ctime = (long)time(0);

  key->version = PCP_KEY_VERSION;
  key->serial  = arc4random();
  key->type    = PCP_KEY_TYPE_SECRET;
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

  unsigned char *encryptkey = pcp_derivekey(passphrase);  

  unsigned char *encrypted;
  size_t es;

  es = pcp_sodium_mac(&encrypted, key->secret, 32, key->nonce, encryptkey);

  memset(encryptkey, 0, 32);
  free(encryptkey);

  if(es == 48) {
    // success
    memcpy(key->encrypted, encrypted, 48);
    arc4random_buf(key->secret, 32);
    key->secret[0] = 0;
  }
  else {
    fatal("failed to encrypt the secret key!\n");
    free(key);
    return NULL;
  }

  return key;
}

pcp_key_t *pcpkey_decrypt(pcp_key_t *key, char *passphrase) {
  unsigned char *encryptkey = pcp_derivekey(passphrase);  
  unsigned char *decrypted;
  size_t es;
  
  es = pcp_sodium_verify_mac(&decrypted, key->encrypted, 48, key->nonce, encryptkey);

  memset(encryptkey, 0, 32);
  free(encryptkey);

  if(es == 0) {
    // success
    memcpy(key->secret, decrypted, 32);
  }
  else {
    fatal("failed to decrypt the secret key (got %d, expected 32)!\n", es);
    free(key);
    return NULL;
  }

  return key;
}

pcp_pubkey_t *pcpkey_pub_from_secret(pcp_key_t *key) {
  //pcp_dumpkey(key);
  pcp_pubkey_t *pub = urmalloc(sizeof (pcp_pubkey_t));
  memcpy(pub->public, key->public, 32);
  memcpy(pub->owner, key->owner, 255);
  memcpy(pub->mail, key->mail, 255);
  memcpy(pub->id, key->id, 17);
  pub->version = key->version;
  pub->type    = PCP_KEY_TYPE_PUBLIC;
  pub->ctime = key->ctime;
  return pub;
}

char *pcppubkey_get_art(pcp_pubkey_t *k) {
  char *r = key_fingerprint_randomart(k->public, sizeof(k));
  return r;
}

char *pcpkey_get_art(pcp_key_t *k) {
  char *r = key_fingerprint_randomart(k->public, sizeof(k));
  return r;
}

unsigned char *pcppubkey_getchecksum(pcp_pubkey_t *k) {
  unsigned char *hash = ucmalloc(32);
  crypto_hash_sha256(hash, k->public, 32);
  return hash;
}

unsigned char *pcpkey_getchecksum(pcp_key_t *k) {
  unsigned char *hash = ucmalloc(32);
  crypto_hash_sha256(hash, k->public, 32);
  return hash;
}



void pcp_inithashes() {
  pcpkey_hash = NULL;
  pcppubkey_hash = NULL;
}

void pcp_cleanhashes() {
  if(pcpkey_hash != NULL) {
    pcp_key_t *current_key, *tmp;
    HASH_ITER(hh, pcpkey_hash, current_key, tmp) {
      HASH_DEL(pcpkey_hash,current_key);
      memset(current_key, 0, sizeof(pcp_key_t));
      free(current_key); // FIXME: coredumps here after n-th secret keys has been added
    }
  }

  if(pcppubkey_hash != NULL) {
    pcp_pubkey_t *current_pub, *ptmp;
    HASH_ITER(hh, pcppubkey_hash, current_pub, ptmp) {
      HASH_DEL(pcppubkey_hash,current_pub);
      memset(current_pub, 0, sizeof(pcp_pubkey_t));
      free(current_pub);
    }
  }
  pcp_inithashes();
}

pcp_key_t *pcpkey_exists(char *id) {
  pcp_key_t *key = NULL;
  HASH_FIND_STR(pcpkey_hash, id, key);
  return key; // maybe NULL!
}

pcp_pubkey_t *pcppubkey_exists(char *id) {
  pcp_pubkey_t *key = NULL;
  HASH_FIND_STR(pcppubkey_hash, id, key);
  return key; // maybe NULL!
}

pcp_key_t * key2be(pcp_key_t *k) {
  k->version = htobe32(k->version);
  k->serial  = htobe32(k->serial);
  k->ctime   = htobe64(k->ctime);
  return k;
}

pcp_key_t *key2native(pcp_key_t *k) {
  k->version = be32toh(k->version);
  k->serial  = be32toh(k->serial);
  k->ctime   = be64toh(k->ctime);
  return k;
}

pcp_pubkey_t * pubkey2be(pcp_pubkey_t *k) {
  k->version = htobe32(k->version);
  k->serial  = htobe32(k->serial);
  k->ctime   = htobe64(k->ctime);
  return k;
}

pcp_pubkey_t *pubkey2native(pcp_pubkey_t *k) {
  k->version = be32toh(k->version);
  k->serial  = be32toh(k->serial);
  k->ctime   = be64toh(k->ctime);
  return k;
}


