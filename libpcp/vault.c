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

  if(is_tmp) {
    filename = ucmalloc(1024);
    uint32_t a,b;
    while (1) {
      a = arc4random();
      b = arc4random();
      snprintf(filename, 1024, "%s/.pcpvault-%08x%08x", getenv("HOME"), a, b);
       if (stat (filename, &stat_buf) != 0)
	 break;
    }
    unlink(filename);
    vault->size = 0;
    vault->modified = 0;
    vault->mode = 0;
  }
  else {
    if (stat (filename, &stat_buf) == 0) {
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
    if((fd = fopen(filename, "wb+")) == NULL) {
      fatal("Could not create vault file %s", filename);
      umask (old_mask);
      goto errn;
    }
    umask (old_mask);
  }
  else {
    if((fd = fopen(filename, "rb+")) == NULL) {
      fatal("Could not open vault file %s", filename);
      goto errn;
    }
  }

  vault->fd = fd;
  vault->filename = filename;
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

  if(type == PCP_KEY_TYPE_PUBLIC)
    pubkey2be((pcp_pubkey_t *)saveitem);
  else
    key2be((pcp_key_t *)saveitem);

  fwrite(header, sizeof(vault_item_header_t), 1, vault->fd);
  fwrite(saveitem, itemsize, 1, vault->fd);

  memset(saveitem, 0, itemsize);
  free(saveitem);

  if(do_hash == 1) {
    // we don't re-hash if it's a full update
    if(type == PCP_KEY_TYPE_PUBLIC) {
      pcp_pubkey_t *p = (pcp_pubkey_t *)item;
      HASH_ADD_STR( pcppubkey_hash, id, p );
    }
    else {
      pcp_key_t *s =  (pcp_key_t *)item;
      HASH_ADD_STR( pcpkey_hash, id, s );
    }
    pcpvault_update_checksum(vault);
  }

  if(ferror(vault->fd) != 0) {
    fatal("Failed to add an item to vault %s!\n", vault->filename);
    return 1;
  }

  vault->unsafed = 0;

  return 0;
}

int pcpvault_writeall(vault_t *vault) {
  vault_t *tmp = pcpvault_new(NULL, 1); // FIXME
  if(tmp != NULL) {
    if(pcpvault_create(tmp) == 0) {
      pcp_key_t *k, *kt = NULL;
      HASH_ITER(hh, pcpkey_hash, k, kt) {
	if(pcpvault_additem(tmp, (void *)k, sizeof(pcp_key_t), PCP_KEY_TYPE_SECRET, 0) != 0)
	  goto errwa;
      }
      pcp_pubkey_t *p, *pt = NULL;
      HASH_ITER(hh, pcppubkey_hash, p, pt) {
	if(pcpvault_additem(tmp, (void *)p, sizeof(pcp_pubkey_t), PCP_KEY_TYPE_PUBLIC, 0) != 0)
	  goto errwa;
      }
      pcpvault_update_checksum(tmp);
      pcpvault_copy(tmp, vault);
    }
  }

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
  
  vh2be(header);

  fseek(vault->fd, 0, SEEK_SET);
  fwrite(header, sizeof(vault_header_t), 1, vault->fd);
  fseek(vault->fd, 0, SEEK_END);
}

unsigned char *pcpvault_create_checksum(vault_t *vault) {
  size_t skeysize = sizeof(pcp_key_t) - sizeof(UT_hash_handle);
  size_t pkeysize = sizeof(pcp_pubkey_t) - sizeof(UT_hash_handle);

  int numskeys = HASH_COUNT(pcpkey_hash);
  int numpkeys = HASH_COUNT(pcppubkey_hash);

  size_t datasize = (skeysize * numskeys) + (pkeysize * numpkeys);
  unsigned char *data = ucmalloc(datasize);
  unsigned char *checksum = ucmalloc(32);
  size_t datapos = 0;

  pcp_key_t *k, *kt = NULL;
  HASH_ITER(hh, pcpkey_hash, k, kt) {
    key2be(k);
    memcpy(&data[datapos], k, skeysize);
    key2native(k);
    datapos += skeysize;
  }

  pcp_pubkey_t *p, *pt = NULL;
  HASH_ITER(hh, pcppubkey_hash, p, pt) {
    pubkey2be(p);
    memcpy(&data[datapos], p, pkeysize);
    pubkey2native(p);
    datapos += pkeysize;
  }

  crypto_hash_sha256(checksum, data, datasize);

  memset(data, 0, datasize);
  free(data);

  return checksum;
}


void pcpvault_copy(vault_t *tmp, vault_t *vault) {
  // fetch tmp content
  fseek(tmp->fd, 0, SEEK_END);
  int tmpsize = ftell(tmp->fd);
  fseek(tmp->fd, 0, SEEK_SET);
  unsigned char *in = ucmalloc(tmpsize);
  fread(in, tmpsize, 1, tmp->fd);

  // and put it into the old file
  vault->fd = freopen(vault->filename, "wb+", vault->fd);
  fwrite(in, tmpsize, 1, vault->fd);
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
    pcpkey_hash = NULL;
    pcppubkey_hash = NULL;
    int readpos = 0;
    pcp_key_t *key;
    pcp_pubkey_t *pubkey;
    int bytesleft = 0;
    int ksize =  sizeof(pcp_pubkey_t); // smallest possbile item

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
	      fread(key, sizeof(pcp_key_t), 1, vault->fd);
	      key2native(key);
	      //pcp_dumpkey(key);
	      HASH_ADD_STR( pcpkey_hash, id, key ); 
	    }
	    else if(item->type == PCP_KEY_TYPE_PUBLIC) {
	      // read a public key
	      pubkey = ucmalloc(sizeof(pcp_pubkey_t));
	      fread(pubkey, sizeof(pcp_pubkey_t), 1, vault->fd);
	      pubkey2native(pubkey);
	      HASH_ADD_STR( pcppubkey_hash, id, pubkey ); 
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
  if(HASH_COUNT(pcpkey_hash) + HASH_COUNT(pcppubkey_hash) > 0) {
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
  pcp_cleanhashes();

  return -1;
}
