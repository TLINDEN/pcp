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



int pcpencrypt(char *id, char *infile, char *outfile, char *passwd, plist_t *recipient) {
  FILE *in = NULL;
  FILE *out = NULL;
  pcp_pubkey_t *pubhash = NULL; // FIXME: add free()
  pcp_pubkey_t *tmp = NULL;
  pcp_pubkey_t *pub = NULL;
  pcp_key_t *secret = NULL;
  int self = 0;

  // FIXME: mk id a plist_t with loop as well
  if(id != NULL) {
    // lookup by id
    HASH_FIND_STR(pcppubkey_hash, id, tmp);
    if(tmp == NULL) {
      // FIXME: use recipient to lookup by name or email
      // self-encryption: look if its a secret one
      pcp_key_t *s = NULL;
      HASH_FIND_STR(pcpkey_hash, id, s);
      if(s != NULL) {
	tmp = pcpkey_pub_from_secret(s);
	HASH_ADD_STR( pubhash, id, tmp);
	self = 1;
      }
      else {
	fatal("Could not find a public key with id 0x%s in vault %s!\n",
	      id, vault->filename);
	goto erren3;
      }
    }
    else {
      // found one by id, copy into local hash
      pub = ucmalloc(sizeof(pcp_pubkey_t));
      memcpy(pub, tmp, sizeof(pcp_pubkey_t));
      HASH_ADD_STR( pubhash, id, tmp);
    }
  }
  else if(recipient != NULL) {
    // lookup by recipient list
    // iterate through global hashlist
    // copy matches into temporary pubhash
    plist_t *rec;
    pcphash_iteratepub(tmp) {
      rec = recipient->first;
      while (rec->next != NULL) {
	_lc(rec->value);
	if(strnstr(tmp->mail, rec->value, 255) != NULL || strnstr(tmp->owner, rec->value, 255) != NULL) {
	  pub = ucmalloc(sizeof(pcp_pubkey_t));
	  memcpy(pub, tmp, sizeof(pcp_pubkey_t));
	  HASH_ADD_STR( pubhash, id, tmp);
	  //fprintf(stderr, "  => found a matching key %s\n", tmp->id);
	}
	rec = rec->next;
      }
    }
    if(HASH_COUNT(pubhash) == 0) {
      fatal("no matching key found for specified recipient(s)!\n");
      goto erren3;
    }
  }
  else {
    fatal("id or recipient list required!\n");
    goto erren3;
  }


  // we're using a random secret keypair on our side
  secret = pcpkey_new();

  if(infile == NULL)
    in = stdin;
  else {
    if((in = fopen(infile, "rb")) == NULL) {
      fatal("Could not open input file %s\n", infile);
      goto erren2;
    }
  }

  if(outfile == NULL)
    out = stdout;
  else {
    if((out = fopen(outfile, "wb+")) == NULL) {
      fatal("Could not open output file %s\n", outfile);
      goto erren2;
    }
  }

  size_t clen = pcp_encrypt_file(in, out, secret, pubhash, self);

  if(clen > 0) {
    if(id != NULL)
      fprintf(stderr, "Encrypted %d bytes for 0x%s successfully\n", (int)clen, id);
    else {
      fprintf(stderr, "Encrypted %d bytes for:\n", (int)clen);
      pcp_pubkey_t *cur, *t;
      HASH_ITER(hh, pubhash, cur, t) {
	fprintf(stderr, "%s <%s>\n", cur->owner, cur->mail);
      }
      free(t);
      free(cur);
    }
    return 0;
  }

 erren2:
  free(pubhash); // FIXME: it's a uthash, dont use free() but func instead
  free(tmp);
  free(pub);

 erren3:

  return 1;
}
