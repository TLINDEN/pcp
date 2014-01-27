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
  *dsize = ciphersize - crypto_secretbox_NONCEBYTES - PCP_CRYPTO_ADD;
  return message;

 errbed:
  free(nonce);
  free(cipheronly);
  if(message != NULL)
    free(message);

  return NULL;
}


size_t pcp_decrypt_file(FILE *in, FILE* out, pcp_key_t *s, unsigned char *symkey) {
  pcp_pubkey_t *cur, *sender;
  int nrec, recmatch;
  uint32_t lenrec;
  uint8_t head;
  size_t cur_bufsize, rec_size;
  
  unsigned char rec_buf[PCP_ASYM_RECIPIENT_SIZE];

#ifdef PCP_ASYM_ADD_SENDER_PUB
  unsigned char *senderpub;
#endif
  int self = 0;

  if(ftell(in) == 1) {
    // header has already been determined outside the lib
    if(symkey != NULL)
      self = 1;
  }
  else {
    // step 1, check header
    cur_bufsize = fread(&head, 1, 1, in);
    if(cur_bufsize != 1 && !feof(in) && !ferror(in)) {
      if(head == PCP_SYM_CIPHER) {
	if(symkey != NULL)
	  self = 1;
	else {
	  fatal("Input is symetrically encrypted but no key have been specified (lib usage failure)\n");
	  goto errdef1;
	}
      }
      else if(head == PCP_ASYM_CIPHER) {
	self = 0;
      }
    }
  }

  if(self) {
    // just decrypt symetrically and go outa here
    return pcp_decrypt_file_sym(in, out, symkey);
  }

#ifdef PCP_ASYM_ADD_SENDER_PUB
  // step 2, sender's pubkey
  cur_bufsize = fread(&in_buf, 1, crypto_box_PUBLICKEYBYTES, in);
  if(cur_bufsize !=  crypto_box_PUBLICKEYBYTES && !feof(in) && !ferror(in)) {
    fatal("Error: input file doesn't contain senders public key\n");
    goto errdef1;
  }
#endif

  // step 3, check len recipients
  cur_bufsize = fread(&lenrec, 1, 4, in);
  if(cur_bufsize != 4 && !feof(in) && !ferror(in)) {
    fatal("Error: input file doesn't contain recipient count\n");
    goto errdef1;
  }
  lenrec = be32toh(lenrec);
  
  // step 4, fetch recipient list and try to decrypt it for us
  for(nrec=0; nrec<lenrec; nrec++) {
    cur_bufsize = fread(&rec_buf, 1, PCP_ASYM_RECIPIENT_SIZE, in);
    if(cur_bufsize != PCP_ASYM_RECIPIENT_SIZE && !feof(in) && !ferror(in)) {
      fatal("Error: input file corrupted, incomplete or no recipients\n");
      goto errdef1;
    }
    recmatch = 0;
    pcphash_iteratepub(cur) {
      unsigned char *recipient;
      recipient = pcp_box_decrypt(s, cur, rec_buf, PCP_ASYM_RECIPIENT_SIZE, &rec_size);
      if(recipient != NULL && rec_size == crypto_secretbox_KEYBYTES) {
	// found a match
	recmatch = 1;
	sender = cur;
	symkey = ucmalloc(crypto_secretbox_KEYBYTES);
	memcpy(symkey, recipient, crypto_secretbox_KEYBYTES);
	free(recipient);
	break;
      }
    }
    if(recmatch == 0) {
      fatal("Sorry, there's no matching public key in your vault for decryption\n");
      goto errdef1;
    }
  }
  
  // step 5, actually decrypt the file, finally
  return pcp_decrypt_file_sym(in, out, symkey);


 errdef1:
  return 0;
}

size_t pcp_encrypt_file(FILE *in, FILE* out, pcp_key_t *s, pcp_pubkey_t *p) {
  unsigned char *symkey;
  int recipient_count;
  unsigned char *recipients_cipher;
  pcp_pubkey_t *cur, *t;
  size_t es;
  int nrec;
  uint32_t lenrec;
  size_t rec_size, out_size;
 
 

  /*
    Correct format should be:
      6[1]|temp_keypair.pubkey|len(recipients)[4]|(recipients...)|(secretboxes...)
    where recipients is a concatenated list of
      random_nonce|box(temp_keypair.privkey, recipient crypto pk, random_nonce, packet key)
  */

  // preparation
  // A, generate sym key
  symkey = urmalloc(crypto_secretbox_KEYBYTES);

  // B, encrypt it asymetrically for each recipient
  recipient_count = HASH_COUNT(p);
  rec_size = PCP_ASYM_RECIPIENT_SIZE;
  recipients_cipher = ucmalloc(rec_size * recipient_count);
  nrec = 0;
  HASH_ITER(hh, p, cur, t) {
    unsigned char *rec_cipher;
    rec_cipher = pcp_box_encrypt(s, cur, symkey, crypto_secretbox_KEYBYTES, &es);
    if(es != rec_size) {
      fatal("invalid rec_size, expected %dl, got %dl\n", rec_size, es);
      if(rec_cipher != NULL)
	free(rec_cipher);
      goto errec1;
    }
    memcpy(&recipients_cipher[nrec * rec_size], rec_cipher, rec_size); // already includes the nonce
    nrec++;
    free(rec_cipher);
  }

  // step 1, file header
  uint8_t head = PCP_ASYM_CIPHER;
  fwrite(&head, 1, 1, out);
  //fprintf(stderr, "D: header - 1\n");
  if(ferror(out) != 0) {
    fatal("Failed to write encrypted output!\n");
    goto errec1;
  }

#ifdef PCP_ASYM_ADD_SENDER_PUB
  // step 2, sender's pubkey
  fwrite(s->pub, crypto_box_PUBLICKEYBYTES, 1, out);
  //fprintf(stderr, "D: sender pub - %d\n", crypto_box_PUBLICKEYBYTES);
  if(ferror(out) != 0)
    goto errec1;
#endif

  // step 3, len recipients, big endian
  lenrec = recipient_count;
  lenrec = htobe32(lenrec);
  fwrite(&lenrec, 4, 1, out);
  //fprintf(stderr, "D: %d recipients - 4\n", recipient_count);
  if(ferror(out) != 0)
    goto errec1;

  // step 4, recipient list
  fwrite(recipients_cipher, rec_size * recipient_count, 1, out);
  //fprintf(stderr, "D: recipients - %ld * %d\n",  rec_size, recipient_count);
  if(ferror(out) != 0)
    goto errec1;

  out_size = 5 + (rec_size * recipient_count) + crypto_box_PUBLICKEYBYTES;

  // step 5, actual encrypted data
  size_t sym_size = pcp_encrypt_file_sym(in, out, symkey, 1);
  if(sym_size == 0)
    goto errec1;


  return out_size + sym_size;

  

 errec1:
  memset(symkey, 0, crypto_secretbox_KEYBYTES);
  free(symkey);
  free(recipients_cipher);

  if(fileno(in) != 0)
    fclose(in);
  if(fileno(out) != 1)
    fclose(out);

  return 0;
}

size_t pcp_encrypt_file_sym(FILE *in, FILE* out, unsigned char *symkey, int havehead) {
  /*
    havehead = 0: write the whole thing from here
    havehead = 1: no header, being called from asym...
  */

  unsigned char *buf_nonce;
  unsigned char *buf_cipher;
  unsigned char in_buf[PCP_BLOCK_SIZE];
  size_t cur_bufsize = 0;
  size_t out_size = 0;
  size_t es;

  if(havehead == 0) {
    uint8_t head = PCP_SYM_CIPHER;
    fwrite(&head, 1, 1, out);
    if(ferror(out) != 0) {
      fatal("Failed to write encrypted output!\n");
      return 0;
    }
  }



  while(!feof(in)) {
    cur_bufsize = fread(&in_buf, 1, PCP_BLOCK_SIZE, in);
    if(cur_bufsize <= 0)
      break;
    buf_nonce = pcp_gennonce();
    es = pcp_sodium_mac(&buf_cipher, in_buf, cur_bufsize, buf_nonce, symkey);
    fwrite(buf_nonce, crypto_secretbox_NONCEBYTES, 1, out);
    //fprintf(stderr, "D: 32k buf nonce - %d\n",  crypto_secretbox_NONCEBYTES);
    fwrite(buf_cipher, es, 1, out);
    //fprintf(stderr, "D: 32k buf cipher - %ld\n", es);
    free(buf_nonce);
    free(buf_cipher);
    out_size += crypto_secretbox_NONCEBYTES + es;
  }

  if(ferror(out) != 0) {
    fatal("Failed to write encrypted output!\n");
    return 0;
  }

  if(fileno(in) != 0)
    fclose(in);
  if(fileno(out) != 1)
    fclose(out);

  return out_size;
}

size_t pcp_decrypt_file_sym(FILE *in, FILE* out, unsigned char *symkey) {
  unsigned char *buf_nonce;
  unsigned char *buf_cipher;
  unsigned char *buf_clear;
  size_t out_size, cur_bufsize, es;
  size_t ciphersize = (PCP_BLOCK_SIZE_IN) - crypto_secretbox_NONCEBYTES;
  unsigned char in_buf[PCP_BLOCK_SIZE_IN];

  buf_nonce  = ucmalloc(crypto_secretbox_NONCEBYTES);
  buf_cipher = ucmalloc(ciphersize);
  out_size = 0;

  while(!feof(in)) {
    cur_bufsize = fread(&in_buf, 1, PCP_BLOCK_SIZE_IN, in);
    if(cur_bufsize <= PCP_CRYPTO_ADD)
      break; // no valid cipher block

    ciphersize = cur_bufsize - crypto_secretbox_NONCEBYTES;
    memcpy(buf_nonce, in_buf, crypto_secretbox_NONCEBYTES);
    memcpy(buf_cipher, &in_buf[crypto_secretbox_NONCEBYTES], ciphersize);

    es = pcp_sodium_verify_mac(&buf_clear, buf_cipher, ciphersize, buf_nonce, symkey);
    out_size += ciphersize - PCP_CRYPTO_ADD;

    if(es == 0) {
      fwrite(buf_clear, ciphersize - PCP_CRYPTO_ADD, 1, out);
      free(buf_clear);
      if(ferror(out) != 0) {
	fatal("Failed to write decrypted output!\n");
	out_size = 0;
	break;
      }
    }
    else {
      fatal("Failed to decrypt file content!\n");
      free(buf_clear);
      out_size = 0;
      break;
    }
  }

  free(buf_nonce);
  free(buf_cipher);

  if(fileno(in) != 0)
    fclose(in);
  if(fileno(out) != 1)
    fclose(out);

  return out_size;
}
