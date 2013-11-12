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
  pcp_pubkey_t *public = NULL;
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

  if(combined == NULL)
    goto errde1;

  unsigned char *hash = ucmalloc(crypto_hash_BYTES);
  unsigned char *check = ucmalloc(crypto_hash_BYTES);
  memcpy(hash, combined, crypto_hash_BYTES);

  for(public=pcppubkey_hash;
      public != NULL;
      public=(pcp_pubkey_t*)(public->hh.next)) {
    crypto_hash(check, (unsigned char*)public->id, 16);
    if(memcmp(check, hash, crypto_hash_BYTES) == 0) {
      // found one
      break;
    }
  }
  if(public == NULL) {
    // maybe self encryption, try secrets
    pcp_key_t *s = NULL;
    for(s=pcpkey_hash; s != NULL; s=(pcp_key_t*)(s->hh.next)) {
      crypto_hash(check, (unsigned char*)s->id, 16);
      if(memcmp(check, hash, crypto_hash_BYTES) == 0) {
        // matching secret
        public = pcpkey_pub_from_secret(s);
      }
    }
    if(public == NULL) {
      fatal("Could not find a usable public key in vault %s!\n",
	  vault->filename);
      goto errde0;
    }
  }

  if(debug) {
    fprintf(stderr, "Using secret key:\n");
    pcpkey_printshortinfo(secret);
    fprintf(stderr, "Using publickey:\n");
    pcppubkey_printshortinfo(public);
  }

  unsigned char *encrypted = ucmalloc(clen - crypto_hash_BYTES);
  memcpy(encrypted, &combined[crypto_hash_BYTES], clen - crypto_hash_BYTES);

  size_t dlen;
  unsigned char *decrypted = pcp_box_decrypt(secret, public,
					     encrypted,
					     clen - crypto_hash_BYTES, &dlen);

  if(decrypted == NULL) {
    // try it with a derived secret from the sender id
    pcp_key_t *s = pcp_derive_pcpkey(secret, public->id);
    decrypted = pcp_box_decrypt(s, public,
				encrypted,
				clen - crypto_hash_BYTES, &dlen);
    if(decrypted == NULL) {
      // now try the senders key mail address
      s = pcp_derive_pcpkey(secret, public->mail);
      decrypted = pcp_box_decrypt(s, public,
				  encrypted,
				  clen - crypto_hash_BYTES, &dlen);
      if(decrypted == NULL) {
	// try the name
	s = pcp_derive_pcpkey(secret, public->owner);
	decrypted = pcp_box_decrypt(s, public,
				    encrypted,
				    clen - crypto_hash_BYTES, &dlen);
      }
    }
  }

  if(decrypted != NULL) {
    fatals_reset();
    fwrite(decrypted, dlen, 1, out);
    fclose(out);
    if(ferror(out) != 0) {
      fatal("Failed to write decrypted output!\n");
    }
    free(decrypted);

    fprintf(stderr, "Decrypted %d bytes from 0x%s successfully\n",
	    (int)dlen, public->id);
  }

  free(encrypted);

 errde0:
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
  pcp_pubkey_t *public = NULL;
  pcp_key_t *secret = NULL;

  // look if we've got that key
  HASH_FIND_STR(pcppubkey_hash, id, public);
  if(public == NULL) {
    // self-encryption: look if its a secret one
    pcp_key_t *s = NULL;
    HASH_FIND_STR(pcpkey_hash, id, s);
    if(s != NULL) {
      public = pcpkey_pub_from_secret(s);
    }
    else {
      fatal("Could not find a public key with id 0x%s in vault %s!\n",
	  id, vault->filename);
      goto erren3;
    }
  }

  secret = pcp_find_primary_secret();
  if(secret == NULL) {
    fatal("Could not find a secret key in vault %s!\n", id, vault->filename);
    goto erren2;
  }

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
      goto erren2;
  }

  if(recipient != NULL) {
    pcp_key_t *derived = pcp_derive_pcpkey(secret, recipient);
    memcpy(secret, derived, sizeof(pcp_key_t));
    free(derived);
  }

  if(debug) {
    fprintf(stderr, "Using secret key:\n");
    pcp_dumpkey(secret);
    fprintf(stderr, "Using publickey:\n");
    pcp_dumppubkey(public);
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
  unsigned char *cipher = pcp_box_encrypt(secret, public, input,
					  inputBufSize, &ciphersize);
  if(cipher == NULL)
    goto erren1;

  size_t zlen;
  size_t clen = ciphersize + crypto_hash_BYTES;
  unsigned char *combined = ucmalloc(clen);
  unsigned char *hash = ucmalloc(crypto_hash_BYTES);
  crypto_hash(hash, (unsigned char*)secret->id, 16);
  memcpy(combined, hash, crypto_hash_BYTES);
  memcpy(&combined[crypto_hash_BYTES], cipher, clen - crypto_hash_BYTES);

  // combined consists of:
  // keyid|nonce|cipher
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

 erren2:

 erren3:

  return 1;
}
