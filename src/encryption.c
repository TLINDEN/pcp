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
      goto errde3;
    }
  }

  if(outfile == NULL)
    out = stdout;
  else {
    if((out = fopen(outfile, "wb+")) == NULL) {
      fatal("Could not open output file %s\n", outfile);
      goto errde3;
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

  size_t dlen = pcp_decrypt_file(in, out, secret);

  if(dlen > 0) {
    fprintf(stderr, "Decrypted %d bytes successfully\n",
	    (int)dlen);
    return 0;
  }


 errde3:
  return 1;
}



int pcpencrypt(char *id, char *infile, char *outfile, char *passwd, char *recipient) {
  FILE *in = NULL;
  FILE *out = NULL;
  pcp_pubkey_t *pub = NULL;
  pcp_key_t *secret = NULL;
  int self = 0;

  // look if we've got that key
  HASH_FIND_STR(pcppubkey_hash, id, pub);
  if(pub == NULL) {
    // FIXME: use recipient to lookup by name or email
    // self-encryption: look if its a secret one
    pcp_key_t *s = NULL;
    HASH_FIND_STR(pcpkey_hash, id, s);
    if(s != NULL) {
      pub = pcpkey_pub_from_secret(s);
      self = 1;
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
      goto erren3;
    }
  }

  if(outfile == NULL)
    out = stdout;
  else {
    if((out = fopen(outfile, "wb+")) == NULL) {
      fatal("Could not open output file %s\n", outfile);
      goto erren3;
    }
  }

  if(debug) {
    fprintf(stderr, "Using secret key:\n");
    pcp_dumpkey(secret);
    fprintf(stderr, "Using publickey:\n");
    pcp_dumppubkey(pub);
  }

  size_t clen = pcp_encrypt_file(in, out, secret, pub, self);

  if(clen > 0) {
    fprintf(stderr, "Encrypted %d bytes for 0x%s successfully\n", (int)clen, id);
    return 0;
  }

 erren3:

  return 1;
}
