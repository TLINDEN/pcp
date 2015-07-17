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


#include "keyprint.h"


int pcptext_infile(char *infile) {
  FILE *in;
  int insize;

  if((in = fopen(infile, "rb")) == NULL) {
    fatal(ptx, "Could not open input file %s\n", infile);
    goto errtinf1;
  }
  
  fseek(in, 0, SEEK_END);
  insize = ftell(in);
  fseek(in, 0, SEEK_SET);

  if(insize == 40) {
    fprintf(stdout, "%s seems to be an empty vault file\n", infile);
    goto tdone;
  }

  /*  maybe a vault? */
  vault_t *v = pcpvault_init(ptx, infile);
  if(v != NULL) {
    fprintf(stdout, "%s is a vault file\n", infile);
    pcptext_vault(v);
    goto tdone;
  }

  /*  try z85ing it */
  char *z85 = pcp_readz85file(ptx, in);
  if(z85 == NULL) {
      fprintf(stdout, "Can't handle %s - unknown file type.\n", infile); 
      goto errtinf1;
  }

  size_t clen;
  byte *bin = pcp_z85_decode(ptx, (char *)z85, &clen);
  free(z85);

  if(bin == NULL) {
    fprintf(stdout, "%s isn't properly Z85 encoded - unknown file type.\n", infile);
    goto errtinf1;
  }
  else
    /* FIXME: try to import pk or sk */
    free(bin);

  /*  still there? */
  fprintf(stdout, "%s looks Z85 encoded but otherwise unknown and is possibly encrypted.\n", infile);

 tdone:
  fatals_reset(ptx);
  return 0;

 errtinf1:
  fatals_reset(ptx);
  return 1;
}


void pcptext_key(char *keyid) {
  pcp_key_t *s = pcphash_keyexists(ptx, keyid);
  if(s != NULL) {
    if(debug)
      pcp_dumpkey(s);
    pcpkey_print(s, stdout);
  }
  else {
    pcp_pubkey_t *p = pcphash_pubkeyexists(ptx, keyid);
    if(p != NULL) {
      if(debug) {
	pcp_dumppubkey(p);
	pcp_keysig_t *s = pcphash_keysigexists(ptx, keyid);
	if(s != NULL) {
	  printf("\n");
	  pcp_dumpkeysig(s);
	}
	printf("\n");
      }
      pcppubkey_print(p, stdout);
    }
    else {
      fatal(ptx, "No key with id 0x%s found!\n", keyid);
    }
  }
}

void pcptext_vault(vault_t *vault) {
#ifdef HAVE_JSON
  
  if(ptx->json) {
    json_t *jout, *jkeys, *jtmp;
    char *checksum, *jdump;
    pcp_key_t *k;
    pcp_pubkey_t *p;
    
    checksum = _bin2hex(vault->checksum, 32);
    jout = json_pack("{sssisssisi}",
		     "keyvaultfile", vault->filename,
		     "version", vault->version,
		     "checksum", checksum,
		     "secretkeys", pcphash_count(ptx),
		     "publickey", pcphash_countpub(ptx));

    jkeys = json_array();
    
    pcphash_iterate(ptx, k) {
      jtmp = pcp_sk2json(k, NULL, 0);
      json_object_set(jtmp, "type", json_string("secret"));
      json_array_append(jkeys, jtmp);
    }

    pcphash_iteratepub(ptx, p) {
      jtmp = pcp_pk2json(p);
      json_array_append(jkeys, jtmp);
    }

    json_object_set(jout, "keys", jkeys);
    
    jdump  = json_dumps(jout, JSON_INDENT(4) | JSON_PRESERVE_ORDER);
    printf("%s\n", jdump);
    json_decref(jout);
    free(jdump);
  }
  else {
    
#endif

  printf("    Key vault: %s\n", vault->filename);
  printf("Vault version: %08X\n", vault->version);
  printf("     Checksum: ");

  int i;
  for ( i = 0;i <15 ;++i) printf("%02X:",(unsigned int) vault->checksum[i]);
  printf("%02X", vault->checksum[15]);
  printf("\n               ");
  for ( i = 16;i <31 ;++i) printf("%02X:",(unsigned int) vault->checksum[i]);
  printf("%02X", vault->checksum[31]);
  printf("\n");

  printf("  Secret keys: %d\n", pcphash_count(ptx));
  printf("  Public keys: %d\n", pcphash_countpub(ptx) );
  
#ifdef HAVE_JSON
  }
#endif
}

void pcpkey_printlineinfo(pcp_key_t *key) {
  struct tm *c;
  time_t t = (time_t)key->ctime;
  c = localtime(&t);
  printf("0x%s   %s   %04d-%02d-%02dT%02d:%02d:%02d  %s <%s>\n",
	 key->id,
	 (key->type ==  PCP_KEY_TYPE_MAINSECRET) ? "primary secret" : "secret        ",  
	 c->tm_year+1900, c->tm_mon+1, c->tm_mday,
	 c->tm_hour, c->tm_min, c->tm_sec,
	 key->owner, key->mail);

  if(ptx->verbose) {
    printf("    ");
    byte *hash = pcpkey_getchecksum(key);
    int i, y;
    for(i=0; i<32; i+=4) {
      for(y=0; y<4; y++) {
	printf("%02x", hash[i+y]);
      }
      printf(" ");
    }
    free(hash);
    printf("\n    encrypted: %s, serial: %08x, version: %d\n",
	   (key->secret[0] == '\0') ? "yes" : " no",
	   key->serial, (int)key->version);
    printf("\n");
  }
}

void pcppubkey_printlineinfo(pcp_pubkey_t *key) {
  struct tm *c;
  time_t t = (time_t)key->ctime;
  c = localtime(&t);
  printf("0x%s   %s   %04d-%02d-%02dT%02d:%02d:%02d  %s <%s>\n",
	 key->id,
	 (key->valid == 1) ? "valid public  " : "public        ",  
	 c->tm_year+1900, c->tm_mon+1, c->tm_mday,
	 c->tm_hour, c->tm_min, c->tm_sec,
	 key->owner, key->mail);

  if(ptx->verbose) {
    printf("    ");
    byte *hash = pcppubkey_getchecksum(key);
    int i, y;
    for(i=0; i<32; i+=4) {
      for(y=0; y<4; y++) {
	printf("%02x", hash[i+y]);
      }
      printf(" ");
    }
    free(hash);
    printf("\n    signed: %s, serial: %08x, version: %d, ",
	   (key->valid == 1) ? "yes" : " no",
	   key->serial, (int)key->version);
    pcp_keysig_t *sig = pcphash_keysigexists(ptx, key->id);
    if(sig != NULL) {
      printf("signature fingerprint:\n    ");
      byte *checksum = sig->checksum;
      for(i=0; i<32; i+=4) {
	for(y=0; y<4; y++) {
	  printf("%02x", checksum[i+y]);
	}
	printf(" ");
      }
      printf("\n");
    }
    else {
      printf("fail: no signature stored.\n");
    }

    printf("\n");
  }
}

void pcppubkey_print(pcp_pubkey_t *key, FILE* out) {
  char *r = pcppubkey_get_art(key);
   
#ifdef HAVE_JSON
  if(ptx->json) {
    json_t *jout;
    char *jdump;
    
    jout = pcp_pk2json(key);
    json_object_set(jout, "random-art-id", json_string(r));
		    
    jdump  = json_dumps(jout, JSON_INDENT(4) | JSON_PRESERVE_ORDER);
    fprintf(out, jdump);
    json_decref(jout);
    free(jdump);
  }
  else {
    
 #endif

    size_t zlen;
    struct tm *c;
    time_t t = (time_t)key->ctime;
    c = localtime(&t);

    fprintf(out, " Cipher: %s\n", EXP_PK_CIPHER_NAME);

    fprintf(out, " Owner: %s\n", key->owner);
    fprintf(out, " Mail: %s\n", key->mail);

    fprintf(out, " Key-ID: 0x%s\n", key->id);
    fprintf(out, " Public-Key: %s\n", pcp_z85_encode(key->pub, 32, &zlen, 1));

    /* 2004-06-14T23:34:30. */
    fprintf(out, " Creation Time: %04d-%02d-%02dT%02d:%02d:%02d\n",
	    c->tm_year+1900, c->tm_mon+1, c->tm_mday,
	    c->tm_hour, c->tm_min, c->tm_sec);

    byte *hash = pcppubkey_getchecksum(key);
    fprintf(out, " Checksum: ");

    size_t i;
    for ( i = 0;i <15 ;++i) fprintf(out, "%02X:",(unsigned int) hash[i]);
    fprintf(out, "%02X", hash[15]);
    fprintf(out, "\n           ");
    for ( i = 16;i <31 ;++i) fprintf(out, "%02X:",(unsigned int) hash[i]);
    fprintf(out, "%02X", hash[31]);
    fprintf(out, "\n");
    fprintf(out, " Serial Number: 0x%08X\n", key->serial);
    fprintf(out, " Key Version: 0x%08X\n", key->version);
  
    fprintf(out, " Random Art ID: ");
    size_t rlen = strlen(r);
    for (i=0; i<rlen; ++i) {
      if(r[i] == '\n') {
	fprintf(out, "\n                ");
      }
      else {
	fprintf(out, "%c", r[i]);
      }
    }
    fprintf(out, "\n");
  
    free(hash);

#ifdef HAVE_JSON
  }
#endif
  
  free(r);
}

void pcpkey_print(pcp_key_t *key, FILE* out) {
   char *r = pcpkey_get_art(key);
   
#ifdef HAVE_JSON

  if(ptx->json) {
    json_t *jout;
    char *jdump;
    
    jout = pcp_sk2json(key, NULL, 0);
    json_object_set(jout, "type", json_string("secret"));
    json_object_set(jout, "random-art-id", json_string(r));
		    
    jdump  = json_dumps(jout, JSON_INDENT(4) | JSON_PRESERVE_ORDER);
    fprintf(out, "%s\n", jdump);
    json_decref(jout);
    free(jdump);
  }
  else {
    
 #endif

    size_t i;
    struct tm *c;
    time_t t = (time_t)key->ctime;
    c = localtime(&t);

    fprintf(out, " Cipher: %s\n", EXP_PK_CIPHER_NAME);
    fprintf(out, " Owner: %s\n", key->owner);
    fprintf(out, " Mail: %s\n", key->mail);
    fprintf(out, " Key-ID: 0x%s\n", key->id);

    /* 2004-06-14T23:34:30. */
    fprintf(out, " Creation Time: %04d-%02d-%02dT%02d:%02d:%02d\n",
	    c->tm_year+1900, c->tm_mon+1, c->tm_mday,
	    c->tm_hour, c->tm_min, c->tm_sec);

    fprintf(out, " Serial Number: 0x%08X\n", key->serial);
    fprintf(out, " Key Version: 0x%08X\n", key->version);

    fprintf(out, " Random Art ID: ");
    size_t rlen = strlen(r);
    for (i=0; i<rlen; ++i) {
      if(r[i] == '\n') {
	fprintf(out, "\n                ");
      }
      else {
	fprintf(out, "%c", r[i]);
      }
    }
    fprintf(out, "\n");
    
#ifdef HAVE_JSON
  }
#endif

  free(r);
}

void pcpkey_printshortinfo(pcp_key_t *key) {
  size_t i;
  printf("        Key-ID: 0x%s\n", key->id);
  printf("         Owner: %s\n", key->owner);
  char *r = pcpkey_get_art(key);
  printf(" Random Art ID: ");
  size_t rlen = strlen(r);
  for (i=0; i<rlen; ++i) {
    if(r[i] == '\n') {
      printf("\n                ");
    }
    else {
      printf("%c", r[i]);
    }
  }
  printf("\n");
  free(r);
}

void pcppubkey_printshortinfo(pcp_pubkey_t *key) {
  size_t i;
  printf("        Key-ID: 0x%s\n", key->id);
  printf("         Owner: %s\n", key->owner);
  char *r = pcppubkey_get_art(key);
  printf(" Random Art ID: ");
  size_t rlen = strlen(r);
  for (i=0; i<rlen; ++i) {
    if(r[i] == '\n') {
      printf("\n                ");
    }
    else {
      printf("%c", r[i]);
    }
  }
  printf("\n");
  free(r);
}

void pcpprint_bin(FILE *out, byte *data, size_t len) {
  size_t i;
  for ( i = 0;i < len;++i)
    fprintf(out, "%02x", (unsigned int) data[i]);
}
