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

  if(pcpvault_addkey(vault, key, sizeof(pcp_key_t), key->type) == 0) {
    if(vault->isnew)
      fprintf(stderr, "new vault created, ");
    fprintf(stderr, "key 0x%s added to %s.\n", key->id, vault->filename);
    return 0;
  }
  
  return 1;
}



void pcp_keygen(char *passwd, char *outfile) {
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
    if(outfile != NULL) {
      pcp_exportsecretkey(key, outfile);
      pcpkey_printshortinfo(key);
      fprintf(stderr, "key stored to file %s, vault unaltered\n", outfile);
      memset(key, 0, sizeof(pcp_key_t));
      free(key);
    }
    else {
      if(pcp_storekey(key) == 0) {
	pcpkey_printshortinfo(key);
      }
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

    for(k=pcpkey_hash; k != NULL; k=(pcp_key_t*)(k->hh.next)) {
      pcpkey_printlineinfo(k);
    }

    pcp_pubkey_t *p;
    for(p=pcppubkey_hash; p != NULL; p=(pcp_pubkey_t*)(p->hh.next)) {
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
  for(k=pcpkey_hash; k != NULL; k=(pcp_key_t*)(k->hh.next)) {
    if(k->type == PCP_KEY_TYPE_MAINSECRET) {
      key = ucmalloc(sizeof(pcp_key_t));
      memcpy(key, k, sizeof(pcp_key_t));
      return key;
    }
  }

  // no primary? whoops
  int nkeys = HASH_COUNT(pcpkey_hash);
  if(nkeys == 1) {
    for(k=pcpkey_hash; k != NULL; k=(pcp_key_t*)(k->hh.next)) {
      key = ucmalloc(sizeof(pcp_key_t));
      memcpy(key, k, sizeof(pcp_key_t));
      return key;
    }
  }

  return NULL;
}

void pcp_exportsecret(char *keyid, int useid, char *outfile) {
  pcp_key_t *key = NULL;

  if(useid == 1) {
    // look if we've got that one
    HASH_FIND_STR(pcpkey_hash, keyid, key);
    if(key == NULL) {
      fatal("Could not find a secret key with id 0x%s in vault %s!\n", keyid, vault->filename);
      free(key);
    }
  }
  else {
    // look for our primary key
    key = pcp_find_primary_secret();
    if(key == NULL) {
      fatal("There's no primary secret key in the vault %s!\n", vault->filename);
    }
  }

  if(key != NULL) {
    pcp_exportsecretkey(key, outfile);
  }
}

void pcp_exportsecretkey(pcp_key_t *key, char *outfile) {
  FILE *out;
  if(outfile == NULL) {
    out = stdout;
  }
  else {
    if((out = fopen(outfile, "wb+")) == NULL) {
      fatal("Could not create output file %s", outfile);
      out = NULL;
    }
  }
  
  if(out != NULL) {
    if(debug)
      pcp_dumpkey(key);
    else
      pcpkey_print(key, out);
  }
}

pcp_key_t *pcp_getrsk(pcp_key_t *s, char *recipient, char *passwd) {
  if(recipient != NULL) {
    if(s->secret[0] == 0) {
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
      s = pcpkey_decrypt(s, passphrase);
      if(s == NULL)
	goto errrsk1;
    }
    pcp_key_t *tmp;
    tmp = pcp_derive_pcpkey(s, recipient);
    return tmp;
  }

  return s;

 errrsk1:
  return NULL;
}

/*
  if id given, look if it is already a public and export this,
  else we look for a secret key with that id. without a given
  keyid we use the primary key. if we start with a secret key
  and a recipient have been given, we use a derived secret key
  and export the public component from that. without recipient
  just export the public component of the found secret key.
 */
void pcp_exportpublic(char *keyid, char *recipient, char *passwd, char *outfile) {
  pcp_pubkey_t *key = NULL;
  
  if(keyid != NULL) {
    // look if we've got that one
    HASH_FIND_STR(pcppubkey_hash, keyid, key);
    if(key == NULL) {
      // maybe it's a secret key?
      pcp_key_t *s = NULL;
      HASH_FIND_STR(pcpkey_hash, keyid, s);
      if(s == NULL) {
	fatal("Could not find a public key with id 0x%s in vault %s!\n", keyid, vault->filename);
	free(s);
      }
      else {
	s = pcp_getrsk(s, recipient, passwd);
	if(s != NULL)
	  key = pcpkey_pub_from_secret(s); 
      }
    }
  }
  else {
    // look for the primary secret
    pcp_key_t *s = NULL;
    s = pcp_find_primary_secret();
    if(s == NULL) {
      fatal("There's no primary secret key in the vault %s!\n", vault->filename);
      free(s);
    }
    else {
      pcp_key_t *t = NULL;
      t = pcp_getrsk(s, recipient, passwd);
      if(t != NULL)
	key = pcpkey_pub_from_secret(t); 
    }
  }

  if(key != NULL) {
    FILE *out;
    if(outfile == NULL) {
      out = stdout;
    }
    else {
      if((out = fopen(outfile, "wb+")) == NULL) {
	fatal("Could not create output file %s", outfile);
	out = NULL;
      }
    }

    if(out != NULL) {
      pcppubkey_print(key, out);
      fprintf(stderr, "public key exported.\n");
    }

    free(key);
  }
}



int pcp_importsecret (vault_t *vault, FILE *in) {
  size_t clen;
  char *z85 = pcp_readz85file(in);

  if(z85 == NULL)
    return 1;

  unsigned char *z85decoded = pcp_z85_decode((char *)z85, &clen);
  free(z85);

  if(z85decoded == NULL) {
    fatal("Error: could not decode input - it's probably not Z85.\n");
    return 1;
  }

  if(clen != sizeof(pcp_key_t)) {
    fatal("Error: decoded input didn't result to a proper sized key! (got %d bytes)\n", clen);
    free(z85decoded);
    return 1;
  }

  // all good now
  pcp_key_t *key = (pcp_key_t *)z85decoded;
  key2native(key);

  if(debug)
    pcp_dumpkey(key);

  if(pcp_sanitycheck_key(key) == 0) {
    if(key->secret[0] != 0) {
      // unencrypted, encrypt it
      fprintf(stderr, "Key to be imported is unencrypted.\n");
      char *passphrase;
      pcp_readpass(&passphrase, "Enter passphrase for key encryption", NULL, 1);
      key = pcpkey_encrypt(key, passphrase);
    }
    int nkeys = HASH_COUNT(pcpkey_hash);
    if(nkeys == 0)
      key->type = PCP_KEY_TYPE_MAINSECRET;

    if(pcpvault_addkey(vault, (void *)key, sizeof(pcp_key_t),
			PCP_KEY_TYPE_SECRET) == 0) {
      fprintf(stderr, "key 0x%s added to %s.\n", key->id, vault->filename);
      return 0;
    }
  }

  return 1;
}


int pcp_importpublic (vault_t *vault, FILE *in) {
  size_t clen;
  char *z85 = pcp_readz85file(in);

  if(z85 == NULL)
    return 1;

  unsigned char *z85decoded = pcp_z85_decode((char *)z85, &clen);
  free(z85);

  if(z85decoded == NULL) {
    fatal("Error: could not decode input - it's probably not Z85 (got %d bytes)\n", clen);
    return 1;
  }

  if(clen != sizeof(pcp_pubkey_t)) {
    fatal("Error: decoded input didn't result to a proper sized key!\n", clen);
    free(z85decoded);
    return 1;
  }

  // all good now
  pcp_pubkey_t *pub = (pcp_pubkey_t *)z85decoded;
  pubkey2native(pub);

  if(debug)
    pcp_dumppubkey(pub);
  if(pcp_sanitycheck_pub(pub) == 0) {
    if(pcpvault_addkey(vault, (void *)pub, sizeof(pcp_pubkey_t),  PCP_KEY_TYPE_PUBLIC) == 0) {
      fprintf(stderr, "key 0x%s added to %s.\n", pub->id, vault->filename);
      return 0;
    }
  }

  return 1;
}

int pcp_sanitycheck_pub(pcp_pubkey_t *key) {
  if(key->public[0] == 0) {
    fatal("Pubkey sanity check: public key contained in key seems to be empty!\n");
    return 1;
  }

  if(key->type != PCP_KEY_TYPE_PUBLIC) {
    fatal("Pubkey sanity check: key type is not PUBLIC (expected: %02x, got: %02x)!\n",
	  PCP_KEY_TYPE_PUBLIC, key->type);
    return 1;
  }

  if(key->version != PCP_KEY_VERSION) {
    fatal("Pubkey sanity check: unknown key version (expected: %08X, got: %08X)!\n",
	  PCP_KEY_VERSION, key->version);
    return 1;
  }
  
  if(key->serial <= 0) {
    fatal("Pubkey sanity check: invalid serial number: %08X!\n", key->serial);
    return 1;
  }

  if(key->id[16] != '\0') {
    char *got = ucmalloc(17);
    memcpy(got, key->id, 17);
    got[16] = '\0';
    fatal("Pubkey sanity check: invalid key id (expected 16 bytes, got: %s)!\n", got);
    free(got);
    return 1;
  }

  struct tm *c;
  time_t t = (time_t)key->ctime;
  c = localtime(&t);
  if(c->tm_year <= 0 || c->tm_year > 1100) {
    // well, I'm perhaps overacting here :)
    fatal("Pubkey sanity check: invalid creation timestamp (got year %04d)!\n", c->tm_year + 1900);
    return 1;
  }

  pcp_pubkey_t *maybe = pcppubkey_exists(key->id);
  if(maybe != NULL) {
    fatal("Pubkey sanity check: there already exists a key with the id 0x%s\n", key->id);
    return 1;
  }

  return 0;
}


int pcp_sanitycheck_key(pcp_key_t *key) {
  if(key->encrypted[0] == 0) {
    fatal("Secretkey sanity check: secret key contained in key seems to be empty!\n");
    return 1;
  }

  if(key->type != PCP_KEY_TYPE_SECRET && key->type != PCP_KEY_TYPE_MAINSECRET) {
    fatal("Secretkey sanity check: key type is not SECRET (expected: %02x, got: %02x)!\n",
	  PCP_KEY_TYPE_SECRET, key->type);
    return 1;
  }

  if(key->version != PCP_KEY_VERSION) {
    fatal("Secretkey sanity check: unknown key version (expected: %08X, got: %08X)!\n",
	  PCP_KEY_VERSION, key->version);
    return 1;
  }
  
  if(key->serial <= 0) {
    fatal("Secretkey sanity check: invalid serial number: %08X!\n", key->serial);
    return 1;
  }

  if(key->id[16] != '\0') {
    char *got = ucmalloc(17);
    memcpy(got, key->id, 17);
    got[16] = '\0';
    fatal("Secretkey sanity check: invalid key id (expected 16 bytes, got: %s)!\n", got);
    free(got);
    return 1;
  }

  struct tm *c;
  time_t t = (time_t)key->ctime;
  c = localtime(&t);
  if(c->tm_year <= 0 || c->tm_year > 1100) {
    // well, I'm perhaps overacting here :)
    fatal("Secretkey sanity check: invalid creation timestamp (got year %04d)!\n", c->tm_year + 1900);
    return 1;
  }

  pcp_key_t *maybe = pcpkey_exists(key->id);
  if(maybe != NULL) {
    fatal("Secretkey sanity check: there already exists a key with the id 0x%s\n", key->id);
    return 1;
  }

  return 0;
}

void pcpdelete_key(char *keyid) {
  pcp_pubkey_t *p = pcppubkey_exists(keyid);
  
  if(p != NULL) {
    // delete public
    HASH_DEL(pcppubkey_hash, p);
    free(p);
    vault->unsafed = 1;
    fprintf(stderr, "Public key deleted.\n");
  }
  else {
    pcp_key_t *s = pcpkey_exists(keyid);
    if(s != NULL) {
      // delete secret
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
  pcp_key_t *key = pcpkey_exists(keyid);
  
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

	vault->unsafed = 1; // will be safed automatically
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
  for(p=pcppubkey_hash; p != NULL; p=(pcp_pubkey_t*)(p->hh.next)) {
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

char *_lc(char *in) {
  size_t len = strlen(in);
  int i;
  for(i=0; i<len; ++i)
    in[i] = towlower(in[i]);
  return in;
}
