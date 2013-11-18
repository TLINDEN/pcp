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


#include "vault.h"
#include "keyhash.h"

vault_t *pcpvault_init(char *filename) {
  vault_t *vault = pcpvault_new(filename, 0);
  if(vault != NULL) {
    if(vault->isnew == 1) {
      if(pcpvault_create(vault) != 0) {
	pcpvault_close(vault);
	return NULL;
      }
    }
    else {
      if(pcpvault_fetchall(vault) != 0) {
	errno = 0; // weird, something sets it to ENOENT and it's not me
	pcpvault_close(vault);
	return NULL;
      }
    }
  }
  return vault;
}

vault_t *pcpvault_new(char *filename, int is_tmp) {
  vault_t *vault = ucmalloc(sizeof(vault_t));
  FILE *fd;
  struct stat stat_buf;
  vault->filename = ucmalloc(1024);

  if(is_tmp) {
    uint32_t a,b;
    while (1) {
      a = arc4random();
      b = arc4random();
      snprintf(vault->filename, 1024, "%s-%08x%08x", filename, a, b);
       if (stat (vault->filename, &stat_buf) != 0)
	 break;
    }
    unlink(vault->filename);
    vault->size = 0;
    vault->modified = 0;
    vault->mode = 0;
  }
  else {
    strncpy(vault->filename, filename, 1024);
    if (stat (vault->filename, &stat_buf) == 0) {
      vault->size = stat_buf.st_size;
      vault->modified = stat_buf.st_mtime;
      vault->mode = stat_buf.st_mode;
    }
    else {
      vault->size = 0;
      vault->modified = 0;
      vault->mode = 0;
    }
  }

  if(vault->size == 0) {
    vault->isnew = 1;
    mode_t old_mask = umask (S_IWGRP | S_IWOTH | S_IRGRP | S_IROTH);
    if((fd = fopen(vault->filename, "wb+")) == NULL) {
      fatal("Could not create vault file %s", vault->filename);
      umask (old_mask);
      goto errn;
    }
    umask (old_mask);
  }
  else {
    if((fd = fopen(vault->filename, "rb+")) == NULL) {
      fatal("Could not open vault file %s", vault->filename);
      goto errn;
    }
  }

  vault->fd = fd;
  vault->unsafed = 0;

  return vault;

 errn:
  free(vault);
  return NULL;
}

int pcpvault_create(vault_t *vault) {
  vault_header_t *header = ucmalloc(sizeof(vault_header_t));
  header->fileid = PCP_VAULT_ID;
  header->version = PCP_VAULT_VERSION;

  vault->version = header->version;
  memcpy(vault->checksum, header->checksum, 32);

  vh2be(header);

  fseek(vault->fd, 0, SEEK_SET);

  fwrite(header, sizeof(vault_header_t), 1, vault->fd);

  if(ferror(vault->fd) != 0) {
    fatal("Failed to write fileheader to vault %s!\n", vault->filename);
    return 1;
  }

  vault->unsafed = 0;

  return 0;
}

int pcpvault_additem(vault_t *vault, void *item, size_t itemsize, uint8_t type, uint8_t do_hash) {
  vault_item_header_t *header = ucmalloc(sizeof(vault_item_header_t));
  header->type = type;
  header->size = itemsize;

  crypto_hash_sha256((unsigned char*)header->checksum, item, itemsize);
  ih2be(header);

  void *saveitem = ucmalloc(itemsize);
  memcpy(saveitem, item, itemsize);



  fwrite(header, sizeof(vault_item_header_t), 1, vault->fd);
  fwrite(saveitem, itemsize, 1, vault->fd);

  memset(saveitem, 0, itemsize);
  free(saveitem);

  if(do_hash == 1) {
    // we don't re-hash if it's a full update
    pcphash_add(item, type);
    pcpvault_update_checksum(vault);
  }

  if(ferror(vault->fd) != 0) {
    fatal("Failed to add an item to vault %s!\n", vault->filename);
    return 1;
  }

  vault->unsafed = 0;

  return 0;

}

int pcpvault_addkey(vault_t *vault, void *item, uint8_t type) {
  vault_t *tmp = pcpvault_new(vault->filename, 1);
  size_t itemsize;

  if(type == PCP_KEY_TYPE_PUBLIC) {
    pubkey2be((pcp_pubkey_t *)item);
    itemsize = PCP_RAW_PUBKEYSIZE;
  }
  else {
    //pcp_dumpkey((pcp_key_t *)item);
    key2be((pcp_key_t *)item);
    itemsize = PCP_RAW_KEYSIZE;
  }

  void *blob = pcp_keyblob(item, type);

  if(tmp != NULL) {
    if(pcpvault_copy(vault, tmp) != 0)
      goto errak1;
    if(pcpvault_additem(tmp, blob, itemsize, type, 1) != 0)
      goto errak1;
    pcpvault_update_checksum(tmp);
    if(pcpvault_copy(tmp, vault) == 0) {
      pcpvault_unlink(tmp);
    }
    else {
      fprintf(stderr, "Keeping tmp vault %s\n", tmp->filename);
      goto errak1;
    }
    free(blob);
    free(tmp);
    return 0;
  }

 errak1:
  free(blob);

  if(tmp != NULL) {
    free(tmp);
  }
  return 1;
}

int pcpvault_writeall(vault_t *vault) {
  vault_t *tmp = pcpvault_new(vault->filename, 1);
  void *blob_s = ucmalloc(PCP_RAW_KEYSIZE);
  void *blob_p = ucmalloc(PCP_RAW_PUBKEYSIZE);

  if(tmp != NULL) {
    if(pcpvault_create(tmp) == 0) {
      pcp_key_t *k = NULL;
      pcphash_iterate(k) {
	pcp_seckeyblob(blob_s, k);
	if(pcpvault_additem(tmp, blob_s, PCP_RAW_KEYSIZE, PCP_KEY_TYPE_SECRET, 0) != 0)
	  goto errwa;
      }
      pcp_pubkey_t *p = NULL;
      pcphash_iteratepub(p) {
	pcp_pubkeyblob(blob_p, p);
	if(pcpvault_additem(tmp, blob_p, PCP_RAW_PUBKEYSIZE, PCP_KEY_TYPE_PUBLIC, 0) != 0)
	  goto errwa;
      }
      pcpvault_update_checksum(tmp);
      if(pcpvault_copy(tmp, vault) == 0) {
	pcpvault_unlink(tmp);
      }
      free(tmp);
      return 0;
    }
  }

  return 1;

 errwa:
  if(tmp != NULL) {
    pcpvault_unlink(tmp);
    free(tmp);
  }
  return 1;
}

void pcpvault_update_checksum(vault_t *vault) {
  unsigned char *checksum = pcpvault_create_checksum(vault);

  vault_header_t *header = ucmalloc(sizeof(vault_header_t));
  header->fileid = PCP_VAULT_ID;
  header->version = PCP_VAULT_VERSION;
  memcpy(header->checksum, checksum, 32);
  memcpy(vault->checksum, checksum, 32);
  
  //printf("write checksum: "); pcpprint_bin(stdout, checksum, 32); printf("\n");

  vh2be(header);

  fseek(vault->fd, 0, SEEK_SET);
  fwrite(header, sizeof(vault_header_t), 1, vault->fd);
  fseek(vault->fd, 0, SEEK_END);
}

unsigned char *pcpvault_create_checksum(vault_t *vault) {
  int numskeys = pcphash_count();
  int numpkeys = pcphash_countpub();

  size_t datasize = ((PCP_RAW_KEYSIZE) * numskeys) +
                    ((PCP_RAW_PUBKEYSIZE) * numpkeys);
  unsigned char *data = ucmalloc(datasize);
  unsigned char *checksum = ucmalloc(32);
  size_t datapos = 0;

  pcp_key_t *k = NULL;
  pcphash_iterate(k) {
    key2be(k);
    memcpy(&data[datapos], k, PCP_RAW_KEYSIZE);
    key2native(k);
    datapos += PCP_RAW_KEYSIZE;
  }

  pcp_pubkey_t *p = NULL;
  pcphash_iteratepub(p) {
    pubkey2be(p);
    memcpy(&data[datapos], p, PCP_RAW_PUBKEYSIZE);
    pubkey2native(p);
    datapos += PCP_RAW_PUBKEYSIZE;
  }

  //printf("DATA (%d) (s: %d, p: %d): ", (int)datasize, numskeys, numpkeys);
  //pcpprint_bin(stdout, data, datasize); printf("\n");

  crypto_hash_sha256(checksum, data, datasize);

  memset(data, 0, datasize);
  free(data);

  return checksum;
}


int pcpvault_copy(vault_t *tmp, vault_t *vault) {
  // fetch tmp content
  fseek(tmp->fd, 0, SEEK_END);
  int tmpsize = ftell(tmp->fd);
  fseek(tmp->fd, 0, SEEK_SET);
  unsigned char *in = ucmalloc(tmpsize);
  fread(in, tmpsize, 1, tmp->fd);

  // and put it into the new file
  vault->fd = freopen(vault->filename, "wb+", vault->fd);
  if(fwrite(in, tmpsize, 1, vault->fd) != 1) {
    fatal("Failed to copy %s to %s (write) [keeping %s]\n",
	  tmp->filename, vault->filename, tmp->filename);
    return 1;
  }

  if(fflush(vault->fd) != 0) {
    fatal("Failed to copy %s to %s (flush) [keeping %s]\n",
	  tmp->filename, vault->filename, tmp->filename);
    return 1;
  }

  return 0;
}

void pcpvault_unlink(vault_t *tmp) {
  int i, tmpsize;
  unsigned char *r;
  fseek(tmp->fd, 0, SEEK_END);
  tmpsize = ftell(tmp->fd);
  r = ucmalloc(tmpsize);
  for (i=0; i<16; ++i) {
    fseek(tmp->fd, 0, SEEK_SET);
    arc4random_buf(r, tmpsize);
    fwrite(r, tmpsize, 1, tmp->fd);
  }
  fclose(tmp->fd);
  unlink(tmp->filename);
  free(r);
}

int pcpvault_close(vault_t *vault) {
  if(vault != NULL) {
    if(vault->fd) {
      if(vault->unsafed == 1) {
	pcpvault_writeall(vault);
      }
      fclose(vault->fd);
    }
    free(vault);
    vault = NULL;
  }
  return 0;
}

vault_header_t * vh2be(vault_header_t *h) {
  h->version = htobe32(h->version);
  return h;
}

vault_header_t * vh2native(vault_header_t *h) {
  h->version = be32toh(h->version);
  return h;
}

vault_item_header_t * ih2be(vault_item_header_t *h) {
  h->version = htobe32(h->version);
  h->size    = htobe32(h->size);
  return h;
}

vault_item_header_t * ih2native(vault_item_header_t *h) {
  h->version = be32toh(h->version);
  h->size = be32toh(h->size);
  return h;
}


int pcpvault_fetchall(vault_t *vault) {
  fseek(vault->fd, 0, SEEK_SET);

  vault_header_t *header = ucmalloc(sizeof(vault_header_t));
  vault_item_header_t *item = ucmalloc(sizeof(vault_item_header_t));
  fread(header, sizeof(vault_header_t), 1, vault->fd);
  vh2native(header);

  if(header->fileid == PCP_VAULT_ID && header->version == PCP_VAULT_VERSION) {
    // loop over the file and slurp everything in
    int readpos = 0;
    pcp_key_t *key;
    pcp_pubkey_t *pubkey;
    int bytesleft = 0;
    int ksize =  PCP_RAW_PUBKEYSIZE; // smallest possbile item

    pcphash_init();

    vault->version = header->version;
    memcpy(vault->checksum, header->checksum, 32);

    for(;;) {
      readpos = ftell(vault->fd);
      if(vault->size - readpos >= sizeof(vault_item_header_t)) {
	// an item header follows
	fread(item, sizeof(vault_item_header_t), 1, vault->fd);
	ih2native(item);

	if(item->size > 0) {
	  // item is valid
	  readpos = ftell(vault->fd);
	  bytesleft = vault->size - readpos;
	  if(bytesleft >= ksize) {
	    // a key follows
	    if(item->type == PCP_KEY_TYPE_MAINSECRET ||
	       item->type == PCP_KEY_TYPE_SECRET) {
	      // read a secret key
	      key = ucmalloc(sizeof(pcp_key_t));
	      fread(key, PCP_RAW_KEYSIZE, 1, vault->fd);
	      key2native(key);
	      //pcp_dumpkey(key);
	      //pcpprint_bin(stdout, key, sizeof(pcp_key_t));printf("\n");
	      pcphash_add((void *)key, item->type);
	    }
	    else if(item->type == PCP_KEY_TYPE_PUBLIC) {
	      // read a public key
	      pubkey = ucmalloc(sizeof(pcp_pubkey_t));
	      fread(pubkey, PCP_RAW_PUBKEYSIZE, 1, vault->fd);
	      pubkey2native(pubkey);
	      pcphash_add((void *)pubkey, item->type);
	    }
	    else {
	      fatal("Failed to read vault - invalid key type: %02X! at %d\n", item->type, readpos);
	      goto err;
	    }
	  }
	  else {
	    fatal("Failed to read vault - that's no pcp key at %d!\n", readpos);
	    goto err;
	  }
	}
	else {
	  fatal("Failed to read vault - invalid key item header size at %d!\n",
		readpos);
	  goto err;
	}
      }
      else {
	// no more items
	break;
      }
    }
  }
  else {
    fatal("Unexpected vault file format!\n");
    goto err;
  }

  unsigned char *checksum = NULL;
  checksum = pcpvault_create_checksum(vault);
  //printf(" calc checksum: "); pcpprint_bin(stdout, checksum, 32); printf("\n");
  if(pcphash_count() + pcphash_countpub() > 0) {
    // only validate the checksum if there are keys
    if(memcmp(checksum, vault->checksum, 32) != 0) {
      fatal("Error: the checksum of the key vault doesn't match its contents!\n");
      goto err;
    }
  }

  free(checksum);
  free(item);
  free(header);
  return 0;

 err:
  free(item);
  free(header);
  //pcphash_clean();

  return -1;
}
