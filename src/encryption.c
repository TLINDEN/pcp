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

  char *senderid = ucmalloc(17);
  memcpy(senderid, combined, 16);
  senderid[16] = '\0';

  HASH_FIND_STR(pcppubkey_hash, senderid, public);
  if(public == NULL) {
    fatal("Could not find a public key with id 0x%s in vault %s!\n",
	  senderid, vault->filename);
    goto errde0;
  }

  if(debug) {
    fprintf(stderr, "Using secret key:\n");
    pcpkey_printshortinfo(secret);
    fprintf(stderr, "Using publickey:\n");
    pcppubkey_printshortinfo(public);
  }

  unsigned char *encrypted = ucmalloc(clen - 16);
  memcpy(encrypted, &combined[16], clen - 16);

  size_t dlen;
  unsigned char *decrypted = pcp_box_decrypt(secret, public,
					     encrypted, clen - 16, &dlen);

  if(decrypted != NULL) {
    fwrite(decrypted, dlen, 1, out);
    fclose(out);
    if(ferror(out) != 0) {
      fatal("Failed to write decrypted output!\n");
    }
    free(decrypted);
  }

  fprintf(stderr, "Decrypted %d bytes from 0x%s successfully\n",
	  (int)dlen, senderid);

  free(encrypted);

 errde0:
  free(senderid);
  free(combined);

 errde1:
  free(encoded);

 errde2:

 errde3:
  return 1;
}



int pcpencrypt(char *id, char *infile, char *outfile, char *passwd) {
  FILE *in = NULL;
  FILE *out = NULL;
  pcp_pubkey_t *public = NULL;
  pcp_key_t *secret = NULL;

  // look if we've got that key
  HASH_FIND_STR(pcppubkey_hash, id, public);
  if(public == NULL) {
    fatal("Could not find a public key with id 0x%s in vault %s!\n",
	  id, vault->filename);
    goto erren3;
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

  if(debug) {
    fprintf(stderr, "Using secret key:\n");
    pcpkey_printshortinfo(secret);
    fprintf(stderr, "Using publickey:\n");
    pcppubkey_printshortinfo(public);
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
  size_t clen = ciphersize + 16;
  unsigned char *combined = ucmalloc(clen);
  memcpy(combined, secret->id, 16);
  memcpy(&combined[16], cipher, clen - 16);

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
