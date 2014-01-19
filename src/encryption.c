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


#include "encryption.h"

int pcpdecrypt(char *id, int useid, char *infile, char *outfile, char *passwd) {
  FILE *in = NULL;
  FILE *out = NULL;
  pcp_pubkey_t *pub = NULL;
  pcp_key_t *secret = NULL;

  if(useid) {
    HASH_FIND_STR(pcpkey_hash, id, secret);
    if(secret == NULL) {
      fatal("Could not find a secret key with id 0x%s in vault %s!\n",
	    id, vault->filename);
      goto errde3;
    }
  }
  else {
    secret = pcp_find_primary_secret();
    if(secret == NULL) {
      fatal("Could not find a secret key in vault %s!\n", id, vault->filename);
      goto errde3;
    }
  }

  if(infile == NULL)
    in = stdin;
  else {
    if((in = fopen(infile, "rb")) == NULL) {
      fatal("Could not open input file %s\n", infile);
      goto errde2;
    }
  }

  if(outfile == NULL)
    out = stdout;
  else {
    if((out = fopen(outfile, "wb+")) == NULL) {
      fatal("Could not open output file %s\n", outfile);
      goto errde2;
    }
  }

  if(secret->secret[0] == 0) {
    // encrypted, decrypt it
    char *passphrase;
    if(passwd == NULL) {
      pcp_readpass(&passphrase,
		   "Enter passphrase to decrypt your secret key", NULL, 1);
    }
    else {
      passphrase = ucmalloc(strlen(passwd)+1);
      strncpy(passphrase, passwd, strlen(passwd)+1);
    }

    secret = pcpkey_decrypt(secret, passphrase);
    if(secret == NULL)
      goto errde3;
  }

  char *encoded = pcp_readz85file(in);
  if(encoded == NULL)
    goto errde2;

  size_t clen;
  unsigned char *combined = pcp_z85_decode((char *)encoded, &clen);
  clen = clen - crypto_secretbox_KEYBYTES;


  if(combined == NULL)
    goto errde1;

  // extract the sender's public key from the cipher
  pub = ucmalloc(sizeof(pcp_pubkey_t));
  memcpy(pub->pub, combined, crypto_secretbox_KEYBYTES);


  if(debug) {
    fprintf(stderr, "Using secret key:\n");
    pcpkey_printshortinfo(secret);
    fprintf(stderr, "Using public key:\n");
    pcpprint_bin(stderr, pub->pub, 32);
    fprintf(stderr, "\n");
 }

  unsigned char *encrypted = ucmalloc(clen);
  memcpy(encrypted, &combined[crypto_secretbox_KEYBYTES], clen);

  size_t dlen;
  unsigned char *decrypted = pcp_box_decrypt(secret, pub,
					     encrypted,
					     clen, &dlen);

  if(decrypted == NULL) {
    // maybe self encryption?
    pcp_pubkey_t *mypub = pcpkey_pub_from_secret(secret);
    decrypted = pcp_box_decrypt(secret, mypub,
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
    }
    free(decrypted);

    fprintf(stderr, "Decrypted %d bytes successfully\n",
	    (int)dlen);
  }
  

  free(encrypted);
  free(pub);
  free(combined);

 errde1:
  free(encoded);

 errde2:

 errde3:
  return 1;
}



int pcpencrypt(char *id, char *infile, char *outfile, char *passwd, char *recipient) {
  FILE *in = NULL;
  FILE *out = NULL;
  pcp_pubkey_t *pub = NULL;
  pcp_key_t *secret = NULL;
  int selfcipher = 0;

  // look if we've got that key
  HASH_FIND_STR(pcppubkey_hash, id, pub);
  if(pub == NULL) {
    // FIXME: use recipient to lookup by name or email
    // self-encryption: look if its a secret one
    pcp_key_t *s = NULL;
    HASH_FIND_STR(pcpkey_hash, id, s);
    if(s != NULL) {
      pub = pcpkey_pub_from_secret(s);
      selfcipher = 1;
    }
    else {
      fatal("Could not find a public key with id 0x%s in vault %s!\n",
	  id, vault->filename);
      goto erren3;
    }
  }

  secret = pcpkey_new(); // DEPRECATED: pcp_find_primary_secret();

  if(infile == NULL)
    in = stdin;
  else {
    if((in = fopen(infile, "rb")) == NULL) {
      fatal("Could not open input file %s\n", infile);
      goto erren1;
    }
  }

  if(outfile == NULL)
    out = stdout;
  else {
    if((out = fopen(outfile, "wb+")) == NULL) {
      fatal("Could not open output file %s\n", outfile);
      goto erren1;
    }
  }

  if(debug) {
    fprintf(stderr, "Using secret key:\n");
    pcp_dumpkey(secret);
    fprintf(stderr, "Using publickey:\n");
    pcp_dumppubkey(pub);
  }

  unsigned char *input = NULL;
  size_t inputBufSize = 0;
  unsigned char byte[1];
  
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
    goto erren1;
  }

  size_t ciphersize;
  unsigned char *cipher = pcp_box_encrypt(secret, pub, input,
					  inputBufSize, &ciphersize);
  if(cipher == NULL)
    goto erren1;

  size_t zlen;
  size_t clen = ciphersize + crypto_secretbox_KEYBYTES;
  unsigned char *combined = ucmalloc(clen);

  if(selfcipher == 1) {
    unsigned char *fakepub = urmalloc(crypto_secretbox_KEYBYTES);
    memcpy(combined, fakepub, crypto_secretbox_KEYBYTES);
    free(fakepub);
  }
  else {
    memcpy(combined, secret->pub, crypto_secretbox_KEYBYTES);
  }

 if(debug) {
    fprintf(stderr, "Using public key:\n");
    pcpprint_bin(stderr, combined, 32);
    fprintf(stderr, "\n");
  }

  memcpy(&combined[crypto_secretbox_KEYBYTES], cipher, ciphersize);

  // combined consists of:
  // our-public-key|nonce|cipher
  char *encoded = pcp_z85_encode(combined, clen, &zlen);

  if(encoded == NULL)
    goto erren0;
  
  fprintf(out, "%s\n%s\n%s\n", PCP_ENFILE_HEADER, encoded, PCP_ENFILE_FOOTER);
  if(ferror(out) != 0) {
    fatal("Failed to write encrypted output!\n");
  }

  fprintf(stderr, "Encrypted %d bytes for 0x%s successfully\n",
	  (int)inputBufSize, id);

  fclose(out);
  free(encoded);
  free(combined);
  free(cipher);
  return 0;

 erren0:
  free(cipher);

 erren1:

 erren3:

  return 1;
}
