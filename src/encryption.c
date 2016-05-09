/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013-2016 T.v.Dein.

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

    You can contact me by mail: <tom AT vondein DOT org>.
*/


#include "encryption.h"

int pcpdecrypt(char *id, int useid, char *infile, char *outfile, char *passwd, int verify) {
  FILE *in = NULL;
  FILE *out = NULL;
  pcp_key_t *secret = NULL;
  byte *symkey = NULL;
  size_t dlen;
  uint8_t head;
  int anon = 0;

  if(infile == NULL)
    in = stdin;
  else {
    if((in = fopen(infile, "rb")) == NULL) {
      fatal(ptx, "Could not open input file %s\n", infile);
      goto errde3;
    }
  }

  if(outfile == NULL)
    out = stdout;
  else {
    if((out = fopen(outfile, "wb+")) == NULL) {
      fatal(ptx, "Could not open output file %s\n", outfile);
      goto errde3;
    }
  }

  Pcpstream *pin = ps_new_file(in);
  Pcpstream *pout = ps_new_file(out);

  ps_setdetermine(pin, PCP_BLOCK_SIZE/2);

  /*  determine crypt mode */
  ps_read(pin, &head, 1);

  if(!ps_end(pin) && !ps_err(pin)) {
    if(head == PCP_SYM_CIPHER) {
      /*  symetric mode */
      byte *salt = ucmalloc(90);
      char stsalt[] = PBP_COMPAT_SALT;
      memcpy(salt, stsalt, 90);

      char *passphrase;
      if(passwd == NULL) {
        pcp_readpass(ptx, &passphrase,
                     "Enter passphrase for symetric decryption", NULL, 1, NULL);
      }
      else {
        passphrase = smalloc(strlen(passwd)+1);
        memcpy(passphrase, passwd, strlen(passwd) + 1);
      }

      symkey = pcp_scrypt(ptx, passphrase, strlen(passphrase), salt, 90);
      sfree(passphrase);
      free(salt);
    }
    else if(head == PCP_ASYM_CIPHER || head == PCP_ASYM_CIPHER_SIG
            || head == PCP_ASYM_CIPHER_ANON || head == PCP_ASYM_CIPHER_ANON_SIG) {
      /*  asymetric mode */
      if(useid) {
        secret = pcphash_keyexists(ptx, id);
        if(secret == NULL) {
          fatal(ptx, "Could not find a secret key with id 0x%s in vault %s!\n",
                id, vault->filename);
          goto errde3;
        }
      }
      else {
        secret = pcp_find_primary_secret();
        if(secret == NULL) {
          fatal(ptx, "Could not find a secret key in vault %s!\n", id, vault->filename);
          goto errde3;
        }
      }

      char *passphrase;
      if(passwd == NULL) {
        pcp_readpass(ptx, &passphrase,
                     "Enter passphrase to decrypt your secret key", NULL, 1, NULL);
      }
      else {
        passphrase = smalloc(strlen(passwd)+1);
        memcpy(passphrase, passwd, strlen(passwd)+1);
      }

      secret = pcpkey_decrypt(ptx, secret, passphrase);
      sfree(passphrase);
      if(secret == NULL)
        goto errde3;
      
      if(head == PCP_ASYM_CIPHER_ANON)
        anon = 1;

      if(head == PCP_ASYM_CIPHER_SIG)
        verify = 1;

      if(head == PCP_ASYM_CIPHER_ANON_SIG) {
        anon = 1;
        verify = 1;
      }
    }
    else {
      fatal(ptx, "Could not determine input file type (got: %02x)\n", head);
      goto errde3;
    }
  }
  else {
    fatal(ptx, "Failed to read from file!\n");
    goto errde3;
  }

  if(symkey == NULL) {
    dlen = pcp_decrypt_stream(ptx, pin, pout, secret, NULL, verify, anon);
  }
  else {
    dlen = pcp_decrypt_stream(ptx, pin, pout, NULL, symkey, verify, 0);
    sfree(symkey);
    symkey = NULL;
  }

  ps_close(pin);
  ps_close(pout);

  if(dlen > 0) {
    if(verify)
      fprintf(stderr, "Decrypted and Verified %"FMT_SIZE_T" bytes successfully\n", (SIZE_T_CAST)dlen);
    else
      fprintf(stderr, "Decrypted %"FMT_SIZE_T" bytes successfully\n", (SIZE_T_CAST)dlen);
    return 0;
  }


 errde3:
  if(symkey != NULL)
     sfree(symkey);

  return 1;
}



int pcpencrypt(char *id, char *infile, char *outfile, char *passwd,
               plist_t *recipient, int signcrypt, int armor, int anon) {
  FILE *in = NULL;
  FILE *out = NULL;
  pcp_pubkey_t *pubhash = NULL; /*  FIXME: add free() */
  pcp_pubkey_t *tmp = NULL;
  pcp_pubkey_t *pub = NULL;
  pcp_key_t *secret = NULL;
  pcp_key_t *signsecret = NULL;
  byte *symkey = NULL;
  int symmode = 0;

  if(id == NULL && recipient == NULL) {
    /*  sym mode */
    symmode = 1;
    char *passphrase;
    if(passwd == NULL) {
      pcp_readpass(ptx, &passphrase,
                   "Enter passphrase for symetric encryption", "Repeat passphrase", 1, NULL);
    }
    else {
      passphrase = smalloc(strlen(passwd)+1);
      memcpy(passphrase, passwd, strlen(passwd)+1);
    }
    byte *salt = ucmalloc(90); /*  FIXME: use random salt, concat it with result afterwards */
    char stsalt[] = PBP_COMPAT_SALT;
    memcpy(salt, stsalt, 90);
    symkey = pcp_scrypt(ptx, passphrase, strlen(passphrase), salt, 90);
    free(salt);
    sfree(passphrase);
  }
  else if(id != NULL && recipient == NULL) {
    /*  lookup by id */
    tmp = pcphash_pubkeyexists(ptx, id);
    if(tmp == NULL) {
      /*  self-encryption: look if its a secret one */
      pcp_key_t *s = pcphash_keyexists(ptx, id);
      if(s != NULL) {
        tmp = pcpkey_pub_from_secret(s);
        pub = ucmalloc(sizeof(pcp_pubkey_t));
        memcpy(pub, tmp, sizeof(pcp_pubkey_t));
        HASH_ADD_STR( pubhash, id, pub);
      }
      else {
        fatal(ptx, "Could not find a public key with id 0x%s in vault %s!\n",
              id, vault->filename);
        goto erren3;
      }
    }
    else {
      /*  found one by id, copy into local hash */
      pub = ucmalloc(sizeof(pcp_pubkey_t));
      memcpy(pub, tmp, sizeof(pcp_pubkey_t));
      HASH_ADD_STR( pubhash, id, pub);
    }
  }
  else if(recipient != NULL) {
    /*  lookup by recipient list */
    /*  iterate through global hashlist */
    /*  copy matches into temporary pubhash */
    plist_t *rec;
    pcphash_iteratepub(ptx, tmp) {
      rec = recipient->first;
      while (rec != NULL) {
        _lc(rec->value);
        if(strnstr(tmp->mail, rec->value, 255) != NULL 
           || strnstr(tmp->owner, rec->value, 255) != NULL) {
          pub = ucmalloc(sizeof(pcp_pubkey_t));
          memcpy(pub, tmp, sizeof(pcp_pubkey_t));
          HASH_ADD_STR( pubhash, id, pub);
          /* fprintf(stderr, "  => found a matching key %s\n", tmp->id); */
        }
        rec = rec->next;
      }
    }

    /* look if we need to add ourselfes */
    rec = recipient->first;
    while (rec != NULL) {
      if(strnstr("__self__", rec->value, 13) != NULL) {
        pcp_key_t *s = pcp_find_primary_secret();
        pcp_pubkey_t *p = pcpkey_pub_from_secret(s);
        HASH_ADD_STR( pubhash, id, p);
        break;
      }
      rec = rec->next;
    }
    
    if(HASH_COUNT(pubhash) == 0) {
      fatal(ptx, "no matching key found for specified recipient(s)!\n");
      goto erren3;
    }
  }


  if(symmode != 1) {
  /*  we're using a random secret keypair on our side */
    if(signcrypt || !anon) {
      secret = pcp_find_primary_secret();
      if(secret == NULL) {
        fatal(ptx, "Could not find a secret key in vault %s!\n", id, vault->filename);
        goto erren2;
      }

      char *passphrase;
      if(passwd == NULL) {
        pcp_readpass(ptx, &passphrase,
                     "Enter passphrase to decrypt your secret key", NULL, 1, NULL);
      }
      else {
        passphrase = smalloc(strlen(passwd)+1);
        memcpy(passphrase, passwd, strlen(passwd)+1);
      }
      secret = pcpkey_decrypt(ptx, secret, passphrase);
      sfree(passphrase);
      if(secret == NULL)
        goto erren2;

      signsecret = secret;
    }
    if(anon)
      secret = pcpkey_new();      
  }

  if(infile == NULL)
    in = stdin;
  else {
    if((in = fopen(infile, "rb")) == NULL) {
      fatal(ptx, "Could not open input file %s\n", infile);
      goto erren2;
    }
  }

  if(outfile == NULL)
    out = stdout;
  else {
    if((out = fopen(outfile, "wb+")) == NULL) {
      fatal(ptx, "Could not open output file %s\n", outfile);
      goto erren2;
    }
  }

  size_t clen = 0;

  Pcpstream *pin = ps_new_file(in);
  Pcpstream *pout = ps_new_file(out);

  if(armor == 1) {
    ps_print(pout, PCP_ENFILE_HEADER);
    ps_armor(pout, PCP_BLOCK_SIZE/2);
  }

  if(symmode == 1) {
    clen = pcp_encrypt_stream_sym(ptx, pin, pout, symkey, 0, NULL);
    sfree(symkey);
  }
  else {
    clen = pcp_encrypt_stream(ptx, pin, pout, secret, signsecret, pubhash, signcrypt, anon);
  }

  if(armor == 1) {
    ps_finish(pout);
    ps_unarmor(pout);
    ps_print(pout, PCP_ENFILE_FOOTER);
  }

  ps_close(pout);

  ps_close(pin);

  if(clen > 0) {
    if(id == NULL && recipient == NULL) {
      fprintf(stderr, "Encrypted %"FMT_SIZE_T" bytes symetrically\n", (SIZE_T_CAST)clen);
    }
    else {
      fprintf(stderr, "Encrypted %"FMT_SIZE_T" bytes for:\n", (SIZE_T_CAST)clen);
      pcp_pubkey_t *cur, *t;
      HASH_ITER(hh, pubhash, cur, t) {
        fprintf(stderr, "  0x%s - %s <%s>\n", cur->id, cur->owner, cur->mail);
      }
    }
    if(signcrypt)
      fprintf(stderr, "Signed encrypted file successfully\n");

    pcphash_cleanpub(pubhash);
    return 0;
  }

 erren2:
  pcphash_cleanpub(pubhash);

  if(symkey != NULL)
    sfree(symkey);

 erren3:

  if(tmp != NULL)
    ucfree(tmp, sizeof(pcp_pubkey_t));

  return 1;
}

void pcpchecksum(char **files, int filenum, char *key) {
  int i;
  byte *checksum = ucmalloc(crypto_generichash_BYTES_MAX);
  size_t keylen = 0;

  if(key != NULL)
    keylen = strlen(key);
  
  for(i=0; i<filenum; i++) {
    FILE *in;
    if(files[i] == NULL) {
      in = stdin;
      files[i] = "stdin";
    }
    else {
      if((in = fopen(files[i], "rb")) == NULL) {
        fatal(ptx, "Could not open input file %s\n", files[i]);
        break;
      }
    }
    Pcpstream *pin = ps_new_file(in);
    if(pcp_checksum(ptx, pin, checksum, (byte *)key, keylen) > 0) {
      char *hex = _bin2hex(checksum, crypto_generichash_BYTES_MAX);
      fprintf(stdout, "BLAKE2b (%s) = %s\n", files[i], hex);
      free(hex);
    }
    else
      break;
  }

  free(checksum);
}
