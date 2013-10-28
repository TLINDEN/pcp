#include "crypto.h"

size_t pcp_sodium_box(unsigned char **cipher,
		      unsigned char *cleartext,
		      size_t clearsize,
		      unsigned char *nonce,
		      unsigned char *secret,
		      unsigned char *public) {

  unsigned char *pad_clear;
  unsigned char *pad_cipher;

  size_t ciphersize = (clearsize + crypto_box_ZEROBYTES) - crypto_box_BOXZEROBYTES; // $s + 32 -16

  pad_cipher = ucmalloc(crypto_box_ZEROBYTES + clearsize);
  pcp_pad_prepend(&pad_clear, cleartext, crypto_box_ZEROBYTES, clearsize);
  
  // crypto_box(c,m,mlen,n,pk,sk);
  crypto_box(pad_cipher, pad_clear,
	     clearsize + crypto_box_ZEROBYTES, nonce, public, secret);

  pcp_pad_remove(cipher, pad_cipher, crypto_secretbox_BOXZEROBYTES, ciphersize);

  free(pad_clear);
  free(pad_cipher);

  return ciphersize;
}




int pcp_sodium_verify_box(unsigned char **cleartext, unsigned char* message,
			  size_t messagesize, unsigned char *nonce,
			  unsigned char *secret, unsigned char *public) {
  // verify/decrypt the box
  unsigned char *pad_cipher;
  unsigned char *pad_clear;
  int success = -1;

  pcp_pad_prepend(&pad_cipher, message, crypto_box_BOXZEROBYTES, messagesize);
  pad_clear = (unsigned char *)ucmalloc((crypto_box_ZEROBYTES+ messagesize));

  // crypto_box_open(m,c,clen,n,pk,sk);
  if (crypto_box_open(pad_clear, pad_cipher,
		      messagesize + crypto_box_BOXZEROBYTES,
		      nonce, public, secret) == 0) {
    success = 0;
  }

  pcp_pad_remove(cleartext, pad_clear, crypto_box_ZEROBYTES, messagesize);

  free(pad_clear);
  free(pad_cipher);

  return success;
}




unsigned char *pcp_box_encrypt(pcp_key_t *secret, pcp_pubkey_t *public,
			       unsigned char *message, size_t messagesize,
			       size_t *csize) {

  unsigned char *nonce = pcp_gennonce();
  unsigned char *cipher;

  size_t es = pcp_sodium_box(&cipher, message, messagesize, nonce,
		 secret->secret, public->public);

  if(es <= messagesize) {
    fatal("failed to encrypt message!\n");
    goto errbec;
  }

  // put nonce and cipher together
  unsigned char *combined = ucmalloc(es + crypto_secretbox_NONCEBYTES);
  memcpy(combined, nonce, crypto_secretbox_NONCEBYTES);
  memcpy(&combined[crypto_secretbox_NONCEBYTES], cipher, es);

  free(cipher);
  free(nonce);

  *csize = es + crypto_secretbox_NONCEBYTES;

  return combined;

 errbec:
  if(cipher != NULL)
    free(cipher);
  free(nonce);

  return NULL;
}


unsigned char *pcp_box_decrypt(pcp_key_t *secret, pcp_pubkey_t *public,
			       unsigned char *cipher, size_t ciphersize,
			       size_t *dsize) {

  unsigned char *message = NULL;

  unsigned char *nonce = ucmalloc(crypto_secretbox_NONCEBYTES);
  unsigned char *cipheronly = ucmalloc(ciphersize - crypto_secretbox_NONCEBYTES);

  memcpy(nonce, cipher, crypto_secretbox_NONCEBYTES);
  memcpy(cipheronly, &cipher[crypto_secretbox_NONCEBYTES],
	 ciphersize - crypto_secretbox_NONCEBYTES);

  if(pcp_sodium_verify_box(&message, cipheronly,
			   ciphersize - crypto_secretbox_NONCEBYTES,
			   nonce, secret->secret, public->public) != 0){
    fatal("failed to decrypt message!\n");
    goto errbed;
  }

  free(nonce);
  free(cipheronly);

  // resulting size:
  // ciphersize - crypto_secretbox_ZEROBYTES
  *dsize = ciphersize - crypto_secretbox_ZEROBYTES;
  return message;

 errbed:
  free(nonce);
  free(cipheronly);
  if(message != NULL)
    free(message);

  return NULL;
}
