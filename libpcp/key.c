/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013 T.Linden.

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

    You can contact me by mail: <tlinden AT cpan DOT org>.
*/


#include "key.h"


unsigned char *pcp_derivekey(char *passphrase) {
  unsigned char *hash32 = ucmalloc(crypto_hash_sha256_BYTES);
  unsigned char *key = ucmalloc(crypto_secretbox_KEYBYTES);

  size_t plen = strnlen(passphrase, 255);
  unsigned char *temp = ucmalloc(crypto_hash_sha256_BYTES);
  int i;

  // make a hash from the passphrase and then HCYCLES times from the result
  crypto_hash_sha256(temp, (unsigned char*)passphrase, plen);

  for(i=0; i<HCYCLES; ++i) {
    if(crypto_hash_sha256(hash32, temp, crypto_hash_sha256_BYTES) == 0) {
      memcpy(temp, hash32, crypto_hash_sha256_BYTES);
    }
  }

  // turn the 32byte hash into a secret key
  temp[0]  &= 248;
  temp[31] &= 127;
  temp[31] |= 64;

  memcpy(key, temp, crypto_secretbox_KEYBYTES);

  memset(passphrase, 0, plen);
  memset(temp, 0, crypto_hash_sha256_BYTES);
  free(passphrase);
  free(temp);
  free(hash32);

  return key;
}


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
  byte edpub[32] = { 0 };
  byte edsec[64] = { 0 };


  // generate curve 25519 keypair
  if(crypto_box_keypair (public, secret) != 0) {
    fatal("Failed to generate a CURVE25519 keypair!\n");
    return NULL;
  }

  // generate ed25519 keypair from box secret
  crypto_sign_seed_keypair(edpub, edsec, secret);

  // fill in our struct
  pcp_key_t *key = urmalloc(sizeof(pcp_key_t));
  memcpy (key->public, public, 32);
  memcpy (key->secret, secret, 32);
  memcpy (key->id, pcp_getkeyid(key), 17);
  memcpy (key->edpub, edpub, 32);
  
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
  memcpy(pub->edpub, key->edpub, 32);
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

pcp_key_t *pcp_derive_pcpkey (pcp_key_t *ours, char *theirs) {
  byte edpub[32] = { 0 };
  byte edsec[64] = { 0 };
  size_t thlen = strnlen(theirs, 255);
  size_t inlen = 32 + thlen;
  unsigned char *both = ucmalloc(inlen);
  unsigned char *hash = ucmalloc(crypto_hash_BYTES);

  memcpy(both, ours->secret, 32);
  memcpy(&both[32], theirs, thlen);

  if(crypto_hash(hash, both, inlen) != 0) {
    fatal("Failed to generate a hash of our pub key and recipient id!\n");
    goto errdp1;
  }

  unsigned char *xor    = ucmalloc(crypto_secretbox_KEYBYTES);
  unsigned char *secret = ucmalloc(crypto_secretbox_KEYBYTES);
  int i;

  for(i=0; i<crypto_secretbox_KEYBYTES; ++i) {
    xor[i] = hash[i] ^ hash[i + crypto_secretbox_KEYBYTES];
  }

  xor[0]  &= 248;
  xor[31] &= 127;
  xor[31] |= 64;

  memcpy(secret, xor, crypto_secretbox_KEYBYTES);

  pcp_key_t * tmp = pcpkey_new ();
  
  memcpy(tmp->secret, secret, 32);

  // calculate pub from secret
  crypto_scalarmult_curve25519_base(tmp->public, tmp->secret); 

  // generate ed25519 keypair from box secret
  crypto_sign_seed_keypair(edpub, edsec, tmp->secret);

  memcpy(tmp->owner, ours->owner, 255);
  memcpy(tmp->mail, ours->mail, 255);
  memcpy(tmp->id, pcp_getkeyid(tmp), 17);
  memcpy(tmp->edpub, edpub, 32);

  memset(both, 0, inlen);
  memset(xor, 0, crypto_secretbox_KEYBYTES);
  memset(hash, 0, crypto_hash_BYTES);

  free(both);
  free(xor);
  free(hash);

  return tmp;

 errdp1:
  memset(both, 0, inlen);
  free(both);
  
  return NULL;
}
