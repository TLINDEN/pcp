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


#include "keymgmt.h"


char *pcp_getstdin(const char *prompt) {
  char line[255];
  char *out;

  fprintf(stderr, "%s: ", prompt);

  if (fgets(line, 255, stdin) == NULL) {
    fatal("Cannot read from stdin");
    goto errgst;
  }

  line[strcspn(line, "\r\n")] = '\0';

  if ((out = strdup(line)) == NULL) {
    fatal("Cannot allocate memory");
    goto errgst;
  }

  return out;

 errgst:
  return NULL;
}

int pcp_storekey (pcp_key_t *key) {
  if(vault->isnew == 1 || HASH_COUNT(pcpkey_hash) == 0) {
    key->type = PCP_KEY_TYPE_MAINSECRET;
  }

  if(pcpvault_addkey(vault, key, key->type) == 0) {
    if(vault->isnew)
      fprintf(stderr, "new vault created, ");
    fprintf(stderr, "key 0x%s added to %s.\n", key->id, vault->filename);
    return 0;
  }
  
  return 1;
}

void pcp_keygen(char *passwd) {
  pcp_key_t *k = pcpkey_new ();
  pcp_key_t *key = NULL;

  char *owner =  pcp_getstdin("Enter the name of the key owner");
  memcpy(k->owner, owner, strlen(owner) + 1);

  char *mail = pcp_getstdin("Enter the email address of the key owner");
  memcpy(k->mail, _lc(mail), strlen(mail) + 1);

  if(debug)
      pcp_dumpkey(k);

  char *passphrase;
  if(passwd == NULL) {
    pcp_readpass(&passphrase,
		 "Enter passphrase for key encryption",
		 "Enter the passphrase again", 1);
  }
  else {
    passphrase = ucmalloc(strlen(passwd)+1);
    strncpy(passphrase, passwd, strlen(passwd)+1);
  }

  if(strnlen(passphrase, 1024) > 0)
    key = pcpkey_encrypt(k, passphrase);
  else {
    char *yes = pcp_getstdin("WARNING: secret key will be stored unencrypted. Are you sure [yes|NO]?");
    if(strncmp(yes, "yes", 1024) == 0)
      key = k;
    else {
      memset(key, 0, sizeof(pcp_key_t));
      free(key);
      goto errkg1;
    }
  }

  if(key != NULL) {
    fprintf(stderr, "Generated new secret key:\n");
    if(pcp_storekey(key) == 0) {
      pcpkey_printshortinfo(key);
      memset(key, 0, sizeof(pcp_key_t));
      free(key);
    }
  }

 errkg1:
  free(mail);
  free(owner);
}


void pcp_listkeys() {
  pcp_key_t *k;

  int nkeys = HASH_COUNT(pcpkey_hash) + HASH_COUNT(pcppubkey_hash);

  if(nkeys > 0) {
    printf("Key ID               Type      Creation Time        Owner\n");

    pcphash_iterate(k) {
      pcpkey_printlineinfo(k);
    }

    pcp_pubkey_t *p;
    pcphash_iteratepub(p) {
      pcppubkey_printlineinfo(p);
    }
  }
  else {
    fatal("The key vault file %s doesn't contain any keys so far.\n", vault->filename);
  }
}


char *pcp_normalize_id(char *keyid) {
  char *id = ucmalloc(17);
  int len = strnlen(keyid, 24);

  if(len == 16) {
    memcpy(id, keyid, 17);
  }
  else if(len < 16) {
    fatal("Specified key id %s is too short!\n", keyid);
    free(id);
    return NULL;
  }
  else if(len > 18) {
    fatal("Specified key id %s is too long!\n", keyid);
    free(id);
    return NULL;
  }
  else {
    if(keyid[0] == '0' && keyid[1] == 'x' && len == 18) {
      int i;
      for(i=0; i<16; ++i) {
	id[i] = keyid[i+2];
      }
      id[16] = 0;
    }
    else {
      fatal("Specified key id %s is too long!\n", keyid);
      free(id);
      return NULL;
    }
  }

  return id;
}

pcp_key_t *pcp_find_primary_secret() {
  pcp_key_t *key = NULL;
  pcp_key_t *k;
  pcphash_iterate(k) {
    if(k->type == PCP_KEY_TYPE_MAINSECRET) {
      key = ucmalloc(sizeof(pcp_key_t));
      memcpy(key, k, sizeof(pcp_key_t));
      return key;
    }
  }

  /*  no primary? whoops */
  int nkeys = HASH_COUNT(pcpkey_hash);
  if(nkeys == 1) {
    pcphash_iterate(k) {
      key = ucmalloc(sizeof(pcp_key_t));
      memcpy(key, k, sizeof(pcp_key_t));
      return key;
    }
  }

  return NULL;
}

void pcp_exportsecret(char *keyid, int useid, char *outfile, int armor, char *passwd) {
  pcp_key_t *key = NULL;

  if(useid == 1) {
    /*  look if we've got that one */
    HASH_FIND_STR(pcpkey_hash, keyid, key);
    if(key == NULL) {
      fatal("Could not find a secret key with id 0x%s in vault %s!\n", keyid, vault->filename);
      goto errexpse1;
    }
  }
  else {
    /*  look for our primary key */
    key = pcp_find_primary_secret();
    if(key == NULL) {
      fatal("There's no primary secret key in the vault %s!\n", vault->filename);
      goto errexpse1;
    }
  }

  FILE *out;
  if(outfile == NULL) {
    out = stdout;
  }
  else {
    if((out = fopen(outfile, "wb+")) == NULL) {
      fatal("Could not create output file %s", outfile);
       goto errexpse1;
    }
  }
  
  if(out != NULL) {
    if(debug)
      pcp_dumpkey(key);

    if(key->secret[0] == 0) {
      /* decrypt the secret key */
      if(passwd == NULL) {
	char *passphrase;
	pcp_readpass(&passphrase,
		     "Enter passphrase to decrypt your secret key", NULL, 1);
	key = pcpkey_decrypt(key, passphrase);
	if(key == NULL) {
	  memset(passphrase, 0, strlen(passphrase));
	  free(passphrase);
	  goto errexpse1;
	}
	memset(passphrase, 0, strlen(passphrase));
	free(passphrase);
      }
      else {
	key = pcpkey_decrypt(key, passwd);
	if(key == NULL) {
	  goto errexpse1;
	}
      }
    }

    Buffer *exported_sk;

    if(passwd != NULL) {
      exported_sk = pcp_export_secret(key, passwd);
    }
    else {
      char *passphrase;
      pcp_readpass(&passphrase,
                  "Enter passphrase to encrypt the exported secret key", "Repeat passphrase", 1);
      exported_sk = pcp_export_secret(key, passphrase);
      memset(passphrase, 0, strlen(passphrase));
      free(passphrase);
    }

    if(exported_sk != NULL) {
      if(armor == 1) {
	size_t zlen;
	char *z85 = pcp_z85_encode(buffer_get(exported_sk), buffer_size(exported_sk), &zlen);
	fprintf(out, "%s\r\n%s\r\n%s\r\n", EXP_SK_HEADER, z85, EXP_SK_FOOTER);
	free(z85);
      }
      else {
	fwrite(buffer_get(exported_sk), 1, buffer_size(exported_sk), out);
      }
      buffer_free(exported_sk);
      fprintf(stderr, "secret key exported.\n");
    }

  }

  errexpse1:
  ;
}


/*
  if id given, look if it is already a public and export this,
  else we look for a secret key with that id. without a given
  keyid we use the primary key. if no keyid has been given but
  a recipient instead, we try to look up the vault for a match.
 */
void pcp_exportpublic(char *keyid, char *passwd, char *outfile, int format, int armor) {
  FILE *out;
  int is_foreign = 0;
  pcp_pubkey_t *pk = NULL;
  pcp_key_t *sk = NULL;
  Buffer *exported_pk = NULL;

  if(outfile == NULL) {
    out = stdout;
  }
  else {
    if((out = fopen(outfile, "wb+")) == NULL) {
      fatal("Could not create output file %s", outfile);
      goto errpcpexpu1;
    }
  }

  if(keyid != NULL) {
    /* keyid specified, check if it exists and if yes, what type it is */
    HASH_FIND_STR(pcppubkey_hash, keyid, pk);
    if(pk == NULL) {
      /* ok, so, then look for a secret key with that id */
      HASH_FIND_STR(pcpkey_hash, keyid, sk);
      if(sk == NULL) {
	fatal("Could not find a key with id 0x%s in vault %s!\n",
		keyid, vault->filename);
	goto errpcpexpu1;
      }
      else {
	/* ok, so it's our own key */
	is_foreign = 0;
      }
    }
    else {
      /* it's a foreign public key, we cannot sign it ourselfes */
      is_foreign = 1;
    }
  }
  else {
    /* we use our primary key anyway */
    sk = pcp_find_primary_secret();
    if(sk == NULL) {
      fatal("There's no primary secret key in the vault %s!\n", vault->filename);
      goto errpcpexpu1;
    }
    is_foreign = 0;
  }


  if(is_foreign == 0 && sk->secret[0] == 0 && format <=  EXP_FORMAT_PBP) {
    /* decrypt the secret key */
    if(passwd != NULL) {
      sk = pcpkey_decrypt(sk, passwd);
    }
    else {
      char *passphrase;
      pcp_readpass(&passphrase,
		   "Enter passphrase to decrypt your secret key", NULL, 1);
      sk = pcpkey_decrypt(sk, passphrase);
      memset(passphrase, 0, strlen(passphrase));
      free(passphrase);
    }
    if(sk == NULL) {
      goto errpcpexpu1;
    }
  }

  /* now, we're ready for the actual export */
  if(format == EXP_FORMAT_NATIVE) {
    if(is_foreign == 0) {
      exported_pk = pcp_export_rfc_pub(sk);
      if(exported_pk != NULL) {
	if(armor == 1) {
	  size_t zlen;
	  char *z85 = pcp_z85_encode(buffer_get(exported_pk), buffer_size(exported_pk), &zlen);
	  fprintf(out, "%s\r\n%s\r\n%s\r\n", EXP_PK_HEADER, z85, EXP_PK_FOOTER);
	  free(z85);
	}
	else
	  fwrite(buffer_get(exported_pk), 1, buffer_size(exported_pk), out);
	buffer_free(exported_pk);
	fprintf(stderr, "public key exported.\n");
      }
    }
    else {
      /* FIXME: export foreign keys unsupported yet */
      fatal("Exporting foreign public keys in native format unsupported yet");
      goto errpcpexpu1;
    }
  }
  else if(format == EXP_FORMAT_PBP) {
    if(is_foreign == 0) {
      exported_pk = pcp_export_pbp_pub(sk);
      if(exported_pk != NULL) {
	/* PBP format requires armoring always */
	size_t zlen;
	char *z85pbp = pcp_z85_encode(buffer_get(exported_pk), buffer_size(exported_pk), &zlen);
	fprintf(out, "%s", z85pbp);
	free(z85pbp);
	buffer_free(exported_pk);
	fprintf(stderr, "public key exported in PBP format.\n");
      }
    }
    else {
      fatal("Exporting foreign public keys in PBP format not possible");
      goto errpcpexpu1;
    }
  }
  else if(format == EXP_FORMAT_YAML) {
    exported_pk = pcp_export_yaml_pub(sk);
    if(exported_pk != NULL) {
      fprintf(out, "%s", buffer_get_str(exported_pk));
    }
  }
  else if(format == EXP_FORMAT_PERL) {
    exported_pk = pcp_export_perl_pub(sk);
    if(exported_pk != NULL) {
      fprintf(out, "%s", buffer_get_str(exported_pk));
    }
  }
  else if(format == EXP_FORMAT_C) {
    exported_pk = pcp_export_c_pub(sk);
    if(exported_pk != NULL) {
      fprintf(out, "%s", buffer_get_str(exported_pk));
    }
  }

 errpcpexpu1:
  buffer_free(exported_pk);
}



int pcp_importsecret (vault_t *vault, FILE *in, char *passwd) {
  unsigned char *buf = ucmalloc(2048);
  size_t buflen = fread(buf, 1, 2048, in);
  pcp_key_t *sk = NULL;

  if(buflen > 0) {
    /* decrypt the input */
    if(passwd != NULL) {
      sk = pcp_import_secret(buf, buflen, passwd);
    }
    else {
      char *passphrase;
      pcp_readpass(&passphrase,
		   "Enter passphrase to decrypt the secret key file", NULL, 1);
      sk = pcp_import_secret(buf, buflen, passphrase);
      memset(passphrase, 0, strlen(passphrase));
      free(passphrase);
    }
    if(sk == NULL) {
      goto errpcsexpu1;
    }

    if(debug)
      pcp_dumpkey(sk);

    pcp_key_t *maybe = pcphash_keyexists(sk->id);
    if(maybe != NULL) {
      fatal("Secretkey sanity check: there already exists a key with the id 0x%s\n", sk->id);
      goto errpcsexpu1;
    }


    /* store it */
    if(passwd != NULL) {
      sk = pcpkey_encrypt(sk, passwd);
    }
    else {
      char *passphrase;
      pcp_readpass(&passphrase,
		   "Enter passphrase for key encryption",
		   "Enter the passphrase again", 1);
    
      if(strnlen(passphrase, 1024) > 0) {
	/* encrypt the key */
	sk = pcpkey_encrypt(sk, passphrase);
      }
      else {
	/* ask for confirmation if we shall store it in the clear */
	char *yes = pcp_getstdin(
		 "WARNING: secret key will be stored unencrypted. Are you sure [yes|NO]?");
	if(strncmp(yes, "yes", 1024) != 0) {
	  memset(sk, 0, sizeof(pcp_key_t));
	  free(sk);
	  memset(passphrase, 0, strlen(passphrase));
	  goto errpcsexpu1;
	}
      }
    }

    if(sk != NULL) {
      /* store it to the vault if we got it til here */
      if(pcp_sanitycheck_key(sk) == 0) {
	if(pcp_storekey(sk) == 0) {
	  pcpkey_printshortinfo(sk);
	  memset(sk, 0, sizeof(pcp_key_t));
	  free(sk);
	  return 0;
	}
      }
    }
  }
  else {
    fatal("Input file is empty!\n");
    goto errpcsexpu1;
  }

 errpcsexpu1:
  ucfree(buf, 2048);

  return 1;
}

int pcp_importpublic (vault_t *vault, FILE *in) {
  unsigned char *buf = ucmalloc(2048);
  size_t buflen = fread(buf, 1, 2048, in);
  pcp_keysig_t *sk = NULL;
  pcp_pubkey_t *pub = NULL;

  if(buflen > 0) {
    pcp_ks_bundle_t *bundle = pcp_import_pub(buf, buflen);

    if(bundle == NULL)
      goto errip1;

    pcp_keysig_t *sk = bundle->s;

    if(bundle != NULL) {
      pcp_pubkey_t *pub = bundle->p;

      if(debug)
	pcp_dumppubkey(pub);

      if(sk == NULL) {
	fatals_ifany();
	char *yes = pcp_getstdin("WARNING: signature doesn't verify, import anyway [yes|NO]?");
	if(strncmp(yes, "yes", 1024) != 0) {
	  free(yes);
	  goto errip1;
	}
	free(yes);
      }

      if(pcp_sanitycheck_pub(pub) == 0) {
	if(pcpvault_addkey(vault, (void *)pub,  PCP_KEY_TYPE_PUBLIC) == 0) {
	  fprintf(stderr, "key 0x%s added to %s.\n", pub->id, vault->filename);
	}
	else
	  goto errip2;

	if(sk != NULL) {
	  if(pcpvault_addkey(vault, sk, sk->type) != 0)
	    goto errip2;
	}
      }
      else
	goto errip2;
    }
  }
  else {
    fatal("Input file is empty!\n");
    goto errip1;
  }

 errip2:
  ucfree(pub, sizeof(pcp_pubkey_t));

 errip1:
  if(sk != NULL) {
    ucfree(sk->blob, sk->size);
    ucfree(sk, sizeof(pcp_keysig_t));
  }
  ucfree(buf, 2048);
  return 1;
}

void pcpdelete_key(char *keyid) {
  pcp_pubkey_t *p = pcphash_pubkeyexists(keyid);
  
  if(p != NULL) {
    /*  delete public */
    HASH_DEL(pcppubkey_hash, p);
    free(p);
    vault->unsafed = 1;
    fprintf(stderr, "Public key deleted.\n");
  }
  else {
    pcp_key_t *s = pcphash_keyexists(keyid);
    if(s != NULL) {
      /*  delete secret */
      HASH_DEL(pcpkey_hash, s);
      free(s);
      vault->unsafed = 1;
      fprintf(stderr, "Secret key deleted.\n");
    }
    else {
      fatal("No key with id 0x%s found!\n", keyid);
    }
  }
}

void pcpedit_key(char *keyid) {
  pcp_key_t *key = pcphash_keyexists(keyid);
  
  if(key != NULL) {
    if(key->secret[0] == 0) {
      char *passphrase;
      pcp_readpass(&passphrase, "Enter passphrase to decrypt the key", NULL, 1);
      key = pcpkey_decrypt(key, passphrase);
    }

    if(key != NULL) {
      char *owner =  pcp_getstdin("Enter the name of the key owner");
      memcpy(key->owner, owner, strlen(owner) + 1);

      char *mail = pcp_getstdin("Enter the email address of the key owner");
      memcpy(key->mail, mail, strlen(mail) + 1);

      char *passphrase;
      pcp_readpass(&passphrase, "Enter passphrase for key encryption", NULL, 1);
      key = pcpkey_encrypt(key, passphrase);

      if(key != NULL) {
	if(debug)
	  pcp_dumpkey(key);

	vault->unsafed = 1; /*  will be safed automatically */
	fprintf(stderr, "Key key changed.\n");
      }
    }
  }
  else {
    fatal("No key with id 0x%s found!\n", keyid);
  }
}


char *pcp_find_id_byrec(char *recipient) {
  pcp_pubkey_t *p;
  char *id = NULL;
  _lc(recipient);
  pcphash_iteratepub(p) {
    if(strncmp(p->owner, recipient, 255) == 0) {
      id = ucmalloc(17);
      strncpy(id, p->id, 17);
      break;
    }
    if(strncmp(p->mail, recipient, 255) == 0) {
      id = ucmalloc(17);
      strncpy(id, p->id, 17);
      break;
    }
  }
  return id;
}



