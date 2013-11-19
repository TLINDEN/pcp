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


#include "signature.h"
#include "defines.h"

int pcpsign(char *infile, char *outfile, char *recipient, char *passwd) {
  FILE *in = NULL;
  FILE *out = NULL;
  pcp_key_t *secret = NULL;

  secret = pcp_find_primary_secret();
  if(secret == NULL) {
    fatal("Could not find a secret key in vault %s!\n", vault->filename);
    goto errs1;
  }
  


  if(infile == NULL)
    in = stdin;
  else {
    if((in = fopen(infile, "rb")) == NULL) {
      fatal("Could not open input file %s\n", infile);
      goto errs2;
    }
  }

  if(outfile == NULL)
    out = stdout;
  else {
    if((out = fopen(outfile, "wb+")) == NULL) {
      fatal("Could not open output file %s\n", outfile);
      goto errs2;
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
      goto errs3;
  }

  if(recipient != NULL) {
    secret = pcp_derive_pcpkey(secret, recipient);
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
    goto errs4;
  }

  size_t zlen;
  pcp_sig_t *signature = pcp_ed_sign(input, inputBufSize, secret);

  // scip
  //printf("sigsize: %d\n", (int)sizeof(pcp_sig_t));
  //pcp_dumpsig(signature);

  if(signature == NULL)
    goto errs5;

  sig2be(signature);
  char *encoded = pcp_z85_encode((unsigned char *)signature, sizeof(pcp_sig_t), &zlen);

  if(encoded == NULL)
    goto errs6;

  fprintf(out, "%s\n%s\n%s\n", PCP_SIG_HEADER, encoded, PCP_SIG_FOOTER);
  if(ferror(out) != 0) {
    fatal("Failed to write encrypted output!\n");
    goto errs7;
  }

  fprintf(stderr, "Signed %d bytes successfully\n",
	  (int)inputBufSize);

  fclose(out);
  free(encoded);
  free(signature);

  return 0;

 errs7:
  free(encoded);
  
 errs6:
  free(signature);

 errs5:

 errs4:
  free(input);

 errs3:

 errs2:

 errs1:
  return 1;
}

int pcpverify(char *infile, char *sigfile) {
  FILE *in = NULL;
  FILE *sigin = NULL;
  pcp_pubkey_t *public = NULL;

  if(infile == NULL)
    in = stdin;
  else {
    if((in = fopen(infile, "rb")) == NULL) {
      fatal("Could not open input file %s\n", infile);
      goto errv1;
    }
  }

 if((sigin = fopen(sigfile, "rb")) == NULL) {
   fatal("Could not open signature file %s\n", sigfile);
   goto errv1;
 }

  char *encoded = pcp_readz85file(sigin);
  if(encoded == NULL)
    goto errv1;

  size_t clen;
  unsigned char *decoded = pcp_z85_decode((char *)encoded, &clen);

  if(decoded == NULL)
    goto errv2;

  if(clen != sizeof(pcp_sig_t)) {
    fatal("Error: decoded signature file didn't result to a proper sized sig! (got %d bytes)\n", clen);
    goto errv2;
  }

  pcp_sig_t *sig = (pcp_sig_t *)decoded;
  sig2native(sig);

  HASH_FIND_STR(pcppubkey_hash, sig->id, public);
 
  if(public == NULL) {
    fatal("Could not find a usable public key in vault %s!\n",
	  vault->filename);
      goto errv3;
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
    goto errv4;
  }

 
  if(pcp_ed_verify(input, inputBufSize, sig, public) == 0) {
    fprintf(stderr, "Signature verified.\n");
  }

  free(decoded);
  free(encoded);
  free(input);
  return 0;

 errv4:
  free(input);

 errv3:
  free(decoded);

 errv2:
  //  free(encoded); why???

 errv1:
  return 1;
}

void pcp_dumpsig(pcp_sig_t *sig) {
  printf("     ed: ");
  pcpprint_bin(stdout, sig->edsig, crypto_sign_BYTES);printf("\n");

  printf("     id: %s\n", sig->id);

  printf("  ctime: %ld\n", sig->ctime);

  printf("version: %04x\n", sig->version);

}
