#include "mac.h"



size_t pcp_sodium_mac(unsigned char **cipher,
		unsigned char *cleartext,
		size_t clearsize,
		unsigned char *nonce,
		unsigned char *key) {
  unsigned char *pad_clear;
  unsigned char *pad_cipher;

  pad_cipher = ucmalloc(crypto_secretbox_ZEROBYTES + clearsize);

  pcp_pad_prepend(&pad_clear, cleartext, crypto_secretbox_ZEROBYTES, clearsize);

  crypto_secretbox(pad_cipher, pad_clear,
		   clearsize + crypto_secretbox_ZEROBYTES, nonce, key);

  pcp_pad_remove(cipher, pad_cipher, crypto_secretbox_BOXZEROBYTES,
     (clearsize + crypto_secretbox_ZEROBYTES) - crypto_secretbox_BOXZEROBYTES);

  free(pad_clear);
  free(pad_cipher);

  return (clearsize + crypto_secretbox_ZEROBYTES) - crypto_secretbox_BOXZEROBYTES;
}

int pcp_sodium_verify_mac(unsigned char **cleartext, unsigned char* message,
			  size_t messagesize, unsigned char *nonce,
			  unsigned char *key) {
  // verify the mac
  unsigned char *pad_cipher;
  unsigned char *pad_clear;
  int success = -1;

  pcp_pad_prepend(&pad_cipher, message, crypto_secretbox_BOXZEROBYTES, messagesize);

  pad_clear = (unsigned char *)ucmalloc((crypto_secretbox_BOXZEROBYTES + messagesize));

  if (crypto_secretbox_open(pad_clear,
			    pad_cipher,
			    messagesize + crypto_secretbox_BOXZEROBYTES,
			    nonce, key) == 0) {
    success = 0;
  }

  pcp_pad_remove(cleartext, pad_clear, crypto_secretbox_ZEROBYTES, messagesize);

  free(pad_clear);
  free(pad_cipher);

  return success;
}
