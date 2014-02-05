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


#include "keyhash.h"

pcp_key_t *pcpkey_hash;
pcp_pubkey_t *pcppubkey_hash;
pcp_key_t *__k;
pcp_pubkey_t *__p;

void pcphash_init() {
  pcpkey_hash = NULL;
  pcppubkey_hash = NULL;
}

void pcphash_del(void *key, int type) {
  if(type == PCP_KEY_TYPE_SECRET) {
    HASH_DEL(pcpkey_hash, (pcp_key_t *)key);
    memset(key, 0, sizeof(pcp_key_t));
  }
  else {
    HASH_DEL(pcppubkey_hash, (pcp_pubkey_t *)key);
    memset(key, 0, sizeof(pcp_pubkey_t));
  }
  free(key);
}

void pcphash_clean() {
  if(pcpkey_hash != NULL) {
    pcp_key_t *current_key, *tmp;
    HASH_ITER(hh, pcpkey_hash, current_key, tmp) {
      pcphash_del(current_key, PCP_KEY_TYPE_SECRET);
    }
  }

  if(pcppubkey_hash != NULL) {
    pcp_pubkey_t *current_pub, *ptmp;
    HASH_ITER(hh, pcppubkey_hash, current_pub, ptmp) {
      pcphash_del(current_pub, PCP_KEY_TYPE_PUBLIC);
    }
  }
  pcphash_init();
}


pcp_key_t *pcphash_keyexists(char *id) {
  pcp_key_t *key = NULL;
  HASH_FIND_STR(pcpkey_hash, id, key);
  return key; /*  maybe NULL! */
}

pcp_pubkey_t *pcphash_pubkeyexists(char *id) {
  pcp_pubkey_t *key = NULL;
  HASH_FIND_STR(pcppubkey_hash, id, key);
  return key; /*  maybe NULL! */
}

void pcphash_add(void *key, int type) {
  if(type == PCP_KEY_TYPE_PUBLIC) {
    pcp_pubkey_t *k = (pcp_pubkey_t *)key;
    HASH_ADD_STR( pcppubkey_hash, id, k );
  }
  else {
    pcp_key_t *k = (pcp_key_t *)key;    
    HASH_ADD_STR( pcpkey_hash, id, k);
  }
}

int pcphash_count() {
  return HASH_COUNT(pcpkey_hash);
}

int pcphash_countpub() {
  return HASH_COUNT(pcppubkey_hash);
}

