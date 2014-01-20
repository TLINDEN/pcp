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


#include "crypto.h"

size_t pcp_sodium_box(unsigned char **cipher,
		      unsigned char *cleartext,
		      size_t clearsize,
		      unsigned char *nonce,
		      unsigned char *secret,
		      unsigned char *pub) {

  unsigned char *pad_clear;
  unsigned char *pad_cipher;

  size_t ciphersize = (clearsize + crypto_box_ZEROBYTES) - crypto_box_BOXZEROBYTES;

  pad_cipher = ucmalloc(crypto_box_ZEROBYTES + clearsize);
  pcp_pad_prepend(&pad_clear, cleartext, crypto_box_ZEROBYTES, clearsize);
  
  // crypto_box(c,m,mlen,n,pk,sk);
  crypto_box(pad_cipher, pad_clear,
	     clearsize + crypto_box_ZEROBYTES, nonce, pub, secret);

  pcp_pad_remove(cipher, pad_cipher, crypto_secretbox_BOXZEROBYTES, ciphersize);

  free(pad_clear);
  free(pad_cipher);

  return ciphersize;
}




int pcp_sodium_verify_box(unsigned char **cleartext, unsigned char* message,
			  size_t messagesize, unsigned char *nonce,
			  unsigned char *secret, unsigned char *pub) {
  // verify/decrypt the box
  unsigned char *pad_cipher;
  unsigned char *pad_clear;
  int success = -1;

  pcp_pad_prepend(&pad_cipher, message, crypto_box_BOXZEROBYTES, messagesize);
  pad_clear = (unsigned char *)ucmalloc((crypto_box_ZEROBYTES+ messagesize));

  // crypto_box_open(m,c,clen,n,pk,sk);
  if (crypto_box_open(pad_clear, pad_cipher,
		      messagesize + crypto_box_BOXZEROBYTES,
		      nonce, pub, secret) == 0) {
    success = 0;
  }

  pcp_pad_remove(cleartext, pad_clear, crypto_box_ZEROBYTES, messagesize);

  free(pad_clear);
  free(pad_cipher);

  return success;
}




unsigned char *pcp_box_encrypt(pcp_key_t *secret, pcp_pubkey_t *pub,
			       unsigned char *message, size_t messagesize,
			       size_t *csize) {

  unsigned char *nonce = pcp_gennonce();

  unsigned char *cipher;

  size_t es = pcp_sodium_box(&cipher, message, messagesize, nonce,
		 secret->secret, pub->pub);

  if(es <= messagesize) {
    fatal("failed to encrypt message!\n");
    goto errbec;
  }

  // scip
  //fprintf(stderr, "public: "); pcpprint_bin(stderr, pub->pub, 32); fprintf(stderr, "\n");
  //fprintf(stderr, "secret: "); pcpprint_bin(stderr, secret->secret, 32); fprintf(stderr, "\n");
  //fprintf(stderr, "cipher: "); pcpprint_bin(stderr, cipher, es); fprintf(stderr, "\n");
  //fprintf(stderr, " nonce: "); pcpprint_bin(stderr, nonce, crypto_secretbox_NONCEBYTES); fprintf(stderr, "\n");

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


unsigned char *pcp_box_decrypt(pcp_key_t *secret, pcp_pubkey_t *pub,
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
			   nonce, secret->secret, pub->pub) != 0){
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

size_t pcp_decrypt_file(FILE *in, FILE* out, pcp_key_t *s) {
  pcp_pubkey_t *p;
  size_t clen;
  size_t dlen = 0;

  char *encoded = pcp_readz85file(in);
  if(encoded == NULL)
    return 0;

  unsigned char *combined = pcp_z85_decode((char *)encoded, &clen);
  clen = clen - crypto_secretbox_KEYBYTES;

  if(combined == NULL)
    goto errdf1;

  // extract the sender's public key from the cipher
  p = ucmalloc(sizeof(pcp_pubkey_t));
  memcpy(p->pub, combined, crypto_secretbox_KEYBYTES);

  unsigned char *encrypted = ucmalloc(clen);
  memcpy(encrypted, &combined[crypto_secretbox_KEYBYTES], clen);

  unsigned char *decrypted = pcp_box_decrypt(s, p,
					     encrypted,
					     clen, &dlen);

  if(decrypted == NULL) {
    // maybe self encryption?
    pcp_pubkey_t *mypub = pcpkey_pub_from_secret(s);
    decrypted = pcp_box_decrypt(s, mypub,
				encrypted,
				clen, &dlen);
    free(mypub);
  }

  if(decrypted != NULL) {
    fatals_reset();
    fwrite(decrypted, dlen, 1, out);
    fclose(out);

    if(ferror(out) != 0) {
      fatal("Failed to write decrypted output!\n");
      dlen = 0;
      goto errdf2;
    }
  }

 errdf2:
  free(decrypted);
  free(combined);
  free(p);

 errdf1:
  free(encoded);

  return dlen;
}


size_t pcp_encrypt_file(FILE *in, FILE* out, pcp_key_t *s, pcp_pubkey_t *p, int self) {
  unsigned char *input = NULL;
  size_t inputBufSize = 0;
  unsigned char byte[1];
  size_t ciphersize;
  size_t clen = 0;
  size_t zlen = 0;
  unsigned char *cipher;
  unsigned char *combined;

  while(!feof(in)) {
    if(!fread(&byte, 1, 1, in))
      break;
    unsigned char *tmp = realloc(input, inputBufSize + 1);
    input = tmp;
    memmove(&input[inputBufSize], byte, 1);
    inputBufSize ++;
  }
  fclose(in);

  if(inputBufSize == 0) {
    fatal("Input file is empty!\n");
    goto erref1;
  }

  cipher = pcp_box_encrypt(s, p, input, inputBufSize, &ciphersize);
  if(cipher == NULL)
    goto erref2;

  clen = ciphersize + crypto_secretbox_KEYBYTES;
  combined = ucmalloc(clen);

  if(self == 1) {
    unsigned char *fakepub = urmalloc(crypto_secretbox_KEYBYTES);
    memcpy(combined, fakepub, crypto_secretbox_KEYBYTES);
    free(fakepub);
  }
  else {
    memcpy(combined, s->pub, crypto_secretbox_KEYBYTES);
  }

  memcpy(&combined[crypto_secretbox_KEYBYTES], cipher, ciphersize);

  // combined consists of:
  // our-public-key|nonce|cipher
  char *encoded = pcp_z85_encode(combined, clen, &zlen);

  if(encoded == NULL)
    goto erref3;
  
  fprintf(out, "%s\n%s\n%s\n", PCP_ENFILE_HEADER, encoded, PCP_ENFILE_FOOTER);
  if(ferror(out) != 0) {
    fatal("Failed to write encrypted output!\n");
    inputBufSize = 0;
  }

  fclose(out);
  free(encoded);
  free(combined);
  free(cipher);

  return inputBufSize;

 erref3:
  free(combined);
  free(cipher);

 erref2:
  free(input);

 erref1:
  
  return 0;
}
