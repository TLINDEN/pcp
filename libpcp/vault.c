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

    You can contact me by mail: <tlinden AT cpan DOT org>.
*/


#include "vault.h"
#include "keyhash.h"
#include "defines.h"

vault_t *pcpvault_init(PCPCTX *ptx, char *filename) {
  vault_t *vault = pcpvault_new(ptx, filename, 0);
  if(vault != NULL) {
    if(vault->isnew == 1) {
      if(pcpvault_create(ptx, vault) != 0) {
        pcpvault_close(ptx, vault);
        return NULL;
      }
    }
    else {
      if(pcpvault_fetchall(ptx, vault) != 0) {
        errno = 0; /*  weird, something sets it to ENOENT and it's not me */
        pcpvault_close(ptx, vault);
        return NULL;
      }
    }
  }
  return vault;
}

vault_t *pcpvault_new(PCPCTX *ptx, char *filename, int is_tmp) {
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
      fatal(ptx, "Could not create vault file %s\n", vault->filename);
      umask (old_mask);
      goto errn;
    }
    umask (old_mask);
  }
  else {
    if((fd = fopen(vault->filename, "rb+")) == NULL) {
      fatal(ptx, "Could not open vault file %s\n", vault->filename);
      goto errn;
    }
  }

  vault->fd = fd;
  vault->unsafed = 0;

  return vault;

 errn:
  pcpvault_free(vault);
  return NULL;
}

int pcpvault_create(PCPCTX *ptx, vault_t *vault) {
  vault_header_t *header = ucmalloc(sizeof(vault_header_t));
  header->fileid = PCP_VAULT_ID;
  header->version = PCP_VAULT_VERSION;

  vault->version = header->version;
  memcpy(vault->checksum, header->checksum, LSHA);

  vh2be(header);

  fseek(vault->fd, 0, SEEK_SET);

  fwrite(header, sizeof(vault_header_t), 1, vault->fd);
  free(header);

  if(ferror(vault->fd) != 0) {
    fatal(ptx, "Failed to write fileheader to vault %s!\n", vault->filename);
    return 1;
  }

  vault->unsafed = 0;

  return 0;
}

int pcpvault_additem(PCPCTX *ptx, vault_t *vault, void *item, size_t itemsize, uint8_t type) {
  vault_item_header_t *header = ucmalloc(sizeof(vault_item_header_t));
  header->type = type;
  header->size = itemsize;

  crypto_hash_sha256((byte*)header->checksum, item, itemsize);
  ih2be(header);

  fwrite(header, sizeof(vault_item_header_t), 1, vault->fd);
  free(header);
  fwrite(item, itemsize, 1, vault->fd);

  if(ferror(vault->fd) != 0) {
    fatal(ptx, "Failed to add an item to vault %s!\n", vault->filename);
    return 1;
  }

  vault->unsafed = 0;

  return 0;

}

int pcpvault_addkey(PCPCTX *ptx, vault_t *vault, void *item, uint8_t type) {
  vault_t *tmp = pcpvault_new(ptx, vault->filename, 1);
  size_t itemsize;

  void *saveitem = NULL;
  Buffer *blob = NULL;

  if(type == PCP_KEY_TYPE_PUBLIC) {
    itemsize = PCP_RAW_PUBKEYSIZE;
    saveitem = ucmalloc(sizeof(pcp_pubkey_t));
    memcpy(saveitem, item, sizeof(pcp_pubkey_t));
    blob = pcp_keyblob(item, type);
  }
  else if(type == PCP_KEYSIG_NATIVE || type == PCP_KEYSIG_PBP) {
    /* FIXME: handle the same way as keys */
    saveitem = ucmalloc(sizeof(pcp_keysig_t));
    pcp_keysig_t *ksin = (pcp_keysig_t *)item;
    pcp_keysig_t *ksout = (pcp_keysig_t *)saveitem;
    
    memcpy(ksout, ksin, sizeof(pcp_keysig_t));
    ksout->blob = ucmalloc(ksin->size);
    memcpy(ksout->blob, ksin->blob, ksin->size);
    blob = pcp_keysig2blob(item);
    itemsize = buffer_size(blob);
  }
  else {
    itemsize = PCP_RAW_KEYSIZE;
    saveitem = ucmalloc(sizeof(pcp_key_t));
    memcpy(saveitem, item, sizeof(pcp_key_t));
    blob = pcp_keyblob(item, type);
  }

  if(tmp != NULL) {
    if(pcpvault_copy(ptx, vault, tmp) != 0)
      goto errak1;
    if(pcpvault_additem(ptx, tmp, buffer_get(blob), itemsize, type) != 0)
      goto errak1;

    pcphash_add(ptx, saveitem, type);
    pcpvault_update_checksum(ptx, tmp);
    
    if(pcpvault_copy(ptx, tmp, vault) == 0) {
      pcpvault_unlink(tmp);
    }
    else {
      fprintf(stderr, "Keeping tmp vault %s\n", tmp->filename);
      goto errak1;
    }
    buffer_free(blob);
    pcpvault_free(tmp);
    return 0;
  }

 errak1:
  buffer_free(blob);

  if(tmp != NULL) {
    free(tmp);
  }
  return 1;
}

int pcpvault_writeall(PCPCTX *ptx, vault_t *vault) {
  vault_t *tmp = pcpvault_new(ptx, vault->filename, 1);

  if(tmp != NULL) {
    if(pcpvault_create(ptx, tmp) == 0) {
      pcp_key_t *k = NULL;
      Buffer *blob = buffer_new(PCP_RAW_PUBKEYSIZE, "bs");
      pcphash_iterate(ptx, k) {
        pcp_seckeyblob(blob, k);
        if(pcpvault_additem(ptx, tmp, buffer_get(blob), PCP_RAW_KEYSIZE, PCP_KEY_TYPE_SECRET) != 0) {
          buffer_free(blob);
          goto errwa;
        }
        buffer_clear(blob);
      }
      pcp_pubkey_t *p = NULL;
      pcphash_iteratepub(ptx, p) {
        pcp_pubkeyblob(blob, p);
        if(pcpvault_additem(ptx, tmp, buffer_get(blob), PCP_RAW_PUBKEYSIZE, PCP_KEY_TYPE_PUBLIC) != 0) {
          buffer_free(blob);
          goto errwa;
        }
        buffer_clear(blob);
      }
      pcpvault_update_checksum(ptx, tmp);
      if(pcpvault_copy(ptx, tmp, vault) == 0) {
        pcpvault_unlink(tmp);
      }
      pcpvault_free(tmp);
      buffer_free(blob);
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

void pcpvault_update_checksum(PCPCTX *ptx, vault_t *vault) {
  byte *checksum = pcpvault_create_checksum(ptx);

  vault_header_t *header = ucmalloc(sizeof(vault_header_t));
  header->fileid = PCP_VAULT_ID;
  header->version = PCP_VAULT_VERSION;
  memcpy(header->checksum, checksum, LSHA);
  memcpy(vault->checksum, checksum, LSHA);
  ucfree(checksum, LSHA);
  
  vh2be(header);

  fseek(vault->fd, 0, SEEK_SET);
  fwrite(header, sizeof(vault_header_t), 1, vault->fd);
  free(header);

  fseek(vault->fd, 0, SEEK_END);
}

byte *pcpvault_create_checksum(PCPCTX *ptx) {
  pcp_key_t *k = NULL;
  Buffer *blob = buffer_new(PCP_RAW_KEYSIZE, "blob");;
  size_t datapos = 0;

  int numskeys = pcphash_count(ptx);
  int numpkeys = pcphash_countpub(ptx);

  size_t datasize = ((PCP_RAW_KEYSIZE) * numskeys) +
                    ((PCP_RAW_PUBKEYSIZE) * numpkeys);
  byte *data = ucmalloc(datasize);
  byte *checksum = ucmalloc(LSHA);

  pcphash_iterate(ptx, k) {
    pcp_seckeyblob(blob, (pcp_key_t *)k);
    memcpy(&data[datapos], buffer_get(blob), buffer_size(blob));
    buffer_clear(blob);
    datapos += buffer_size(blob);
  }

  pcp_pubkey_t *p = NULL;
  pcphash_iteratepub(ptx, p) {
    /* pcp_dumppubkey(p); */
    pcp_pubkeyblob(blob, (pcp_pubkey_t *)p);
    memcpy(&data[datapos], buffer_get(blob), buffer_size(blob));
    buffer_clear(blob);
    datapos += PCP_RAW_KEYSIZE;
  }

  buffer_free(blob);

  crypto_hash_sha256(checksum, data, datasize);

  memset(data, 0, datasize);
  free(data);

  return checksum;
}


int pcpvault_copy(PCPCTX *ptx, vault_t *tmp, vault_t *vault) {
  /*  fetch tmp content */
  fseek(tmp->fd, 0, SEEK_END);
  int tmpsize = ftell(tmp->fd);
  fseek(tmp->fd, 0, SEEK_SET);
  byte *in = ucmalloc(tmpsize);
  tmpsize = fread(in, 1, tmpsize, tmp->fd);

  /*  and put it into the new file */
  vault->fd = freopen(vault->filename, "wb+", vault->fd);
  if(fwrite(in, tmpsize, 1, vault->fd) != 1) {
    fatal(ptx, "Failed to copy %s to %s (write) [keeping %s]\n",
          tmp->filename, vault->filename, tmp->filename);
    ucfree(in, tmpsize);
    return 1;
  }
  ucfree(in, tmpsize);

  if(fflush(vault->fd) != 0) {
    fatal(ptx, "Failed to copy %s to %s (flush) [keeping %s]\n",
          tmp->filename, vault->filename, tmp->filename);
    return 1;
  }

  return 0;
}

void pcpvault_unlink(vault_t *tmp) {
  int i, tmpsize;
  byte *r;
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

int pcpvault_close(PCPCTX *ptx, vault_t *vault) {
  if(vault != NULL) {
    if(vault->fd) {
      if(vault->unsafed == 1) {
        pcpvault_writeall(ptx, vault);
      }
      fclose(vault->fd);
    }
    pcpvault_free(vault);
    vault = NULL;
  }
  return 0;
}

void pcpvault_free(vault_t *vault) {
  if(vault != NULL) {
    free(vault->filename);
    free(vault);
  }
}

vault_header_t * vh2be(vault_header_t *h) {
  _32towire(h->version, (byte *)&h->version);
  return h;
}

vault_header_t * vh2native(vault_header_t *h) {
  h->version = _wireto32((byte *)&h->version);
  return h;
}

vault_item_header_t * ih2be(vault_item_header_t *h) {
  _32towire(h->version, (byte *)&h->version);
  _32towire(h->size, (byte *)&h->size);
  return h;
}

vault_item_header_t * ih2native(vault_item_header_t *h) {
  h->version = _wireto32((byte *)&h->version);
  h->size = _wireto32((byte *)&h->size);
  return h;
}


int pcpvault_fetchall(PCPCTX *ptx, vault_t *vault) {
  size_t got = 0;
  fseek(vault->fd, 0, SEEK_SET);

  vault_header_t *header = ucmalloc(sizeof(vault_header_t));
  vault_item_header_t *item = ucmalloc(sizeof(vault_item_header_t));
  got = fread(header, 1, sizeof(vault_header_t), vault->fd);
  if(got < sizeof(vault_header_t)) {
    fatal(ptx, "empty or invalid vault header size (got %ld, expected %ld)\n",
          got,  sizeof(vault_header_t)); 
    goto err;
  }
  vh2native(header);

  if(header->fileid == PCP_VAULT_ID && header->version == PCP_VAULT_VERSION) {
    /*  loop over the file and slurp everything in */
    size_t readpos = 0;
    pcp_key_t *key;
    pcp_pubkey_t *pubkey;
    int bytesleft = 0;
    int ksize =  PCP_RAW_KEYSIGSIZE; /*  smallest possbile item */
    Buffer *raw = buffer_new(256, "rawin");
    
    vault->version = header->version;
    memcpy(vault->checksum, header->checksum, LSHA);

    for(;;) {
      readpos = ftell(vault->fd);
      if(vault->size - readpos >= sizeof(vault_item_header_t)) {
        /*  an item header follows */
        got = fread(item, sizeof(vault_item_header_t), 1, vault->fd);
        ih2native(item);

        if(item->size > 0) {
          /*  item is valid */
          readpos = ftell(vault->fd);
          bytesleft = vault->size - readpos;
          if(bytesleft >= ksize) {
            /*  a key follows */
            if(item->type == PCP_KEY_TYPE_MAINSECRET ||
               item->type == PCP_KEY_TYPE_SECRET) {
              /*  read a secret key */
              buffer_fd_read(raw, vault->fd, item->size);
              key = pcp_blob2key(raw);
              pcphash_add(ptx, (void *)key, item->type);
              buffer_clear(raw);
            }
            else if(item->type == PCP_KEY_TYPE_PUBLIC) {
              /*  read a public key */
              buffer_fd_read(raw, vault->fd, item->size);
              pubkey = pcp_blob2pubkey(raw);
              pcphash_add(ptx, (void *)pubkey, item->type);
              buffer_clear(raw);
            }
            else if(item->type == PCP_KEYSIG_NATIVE || item->type == PCP_KEYSIG_PBP) {
              buffer_fd_read(raw, vault->fd, item->size);
              pcp_keysig_t *s = pcp_keysig_new(raw);
              pcphash_add(ptx, (void *)s, item->type);
              buffer_clear(raw);
            }
            else {
              fatal(ptx, "Failed to read vault - invalid key type: %02X! at %d\n",
                    item->type, readpos);
              goto err;
            }
          }
          else {
            fatal(ptx, "Failed to read vault - that's no pcp key at %d (size %ld)!\n",
                  readpos, bytesleft);
            goto err;
          }
        }
        else {
          fatal(ptx, "Failed to read vault - invalid key item header size at %d!\n",
                readpos);
          goto err;
        }
      }
      else {
        /*  no more items */
        break;
      }
    }
  }
  else {
    fatal(ptx, "Unexpected vault file format!\n");
    goto err;
  }

  byte *checksum = NULL;
  checksum = pcpvault_create_checksum(ptx);
  
  if(pcphash_count(ptx) + pcphash_countpub(ptx) > 0) {
    /*  only validate the checksum if there are keys */
    if(cst_time_memcmp(checksum, vault->checksum, LSHA) != 0) {
      fatal(ptx, "Error: the checksum of the key vault doesn't match its contents!\n");
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
  /* pcphash_clean(); */

  return -1;
}
