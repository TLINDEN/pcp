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

  pad_clear = (unsigned char *)ucmalloc((crypto_secretbox_ZEROBYTES + messagesize));

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
