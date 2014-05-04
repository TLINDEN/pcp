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


void pcphash_del(PCPCTX *ptx, void *key, int type) {
  if(type == PCP_KEY_TYPE_SECRET) {
    HASH_DEL(ptx->pcpkey_hash, (pcp_key_t *)key);
    memset(key, 0, sizeof(pcp_key_t));
  }
  else if(type == PCP_KEYSIG_NATIVE || type == PCP_KEYSIG_PBP) {
    pcp_keysig_t *keysig = (pcp_keysig_t *)key;
    memset(keysig->blob, 0, keysig->size);
    free(keysig->blob);
    HASH_DEL(ptx->pcpkeysig_hash, (pcp_keysig_t *)key);
  }
  else {
    HASH_DEL(ptx->pcppubkey_hash, (pcp_pubkey_t *)key);
    memset(key, 0, sizeof(pcp_pubkey_t));
  }
  free(key);
}

void pcphash_clean(PCPCTX *ptx) {
  if(ptx->pcpkey_hash != NULL) {
    pcp_key_t *current_key, *tmp;
    HASH_ITER(hh, ptx->pcpkey_hash, current_key, tmp) {
      pcphash_del(ptx, current_key, PCP_KEY_TYPE_SECRET);
    }
  }

  if(ptx->pcppubkey_hash != NULL) {
    pcp_pubkey_t *current_pub, *ptmp;
    HASH_ITER(hh, ptx->pcppubkey_hash, current_pub, ptmp) {
      pcphash_del(ptx, current_pub, PCP_KEY_TYPE_PUBLIC);
    }
  }

  if(ptx->pcpkeysig_hash != NULL) {
    pcp_keysig_t *current_keysig, *tmp;
    HASH_ITER(hh, ptx->pcpkeysig_hash, current_keysig, tmp) {
      pcphash_del(ptx, current_keysig, current_keysig->type);
    }
  }
}


pcp_keysig_t *pcphash_keysigexists(PCPCTX *ptx, char *id) {
  pcp_keysig_t *keysig = NULL;
  HASH_FIND_STR(ptx->pcpkeysig_hash, id, keysig);
  return keysig; /*  maybe NULL! */
}

pcp_key_t *pcphash_keyexists(PCPCTX *ptx, char *id) {
  pcp_key_t *key = NULL;
  HASH_FIND_STR(ptx->pcpkey_hash, id, key);
  return key; /*  maybe NULL! */
}

pcp_pubkey_t *pcphash_pubkeyexists(PCPCTX *ptx, char *id) {
  pcp_pubkey_t *key = NULL;
  HASH_FIND_STR(ptx->pcppubkey_hash, id, key);
  return key; /*  maybe NULL! */
}

void pcphash_add(PCPCTX *ptx, void *key, int type) {
  if(type == PCP_KEY_TYPE_PUBLIC) {
    pcp_pubkey_t *k = (pcp_pubkey_t *)key;
    HASH_ADD_STR( ptx->pcppubkey_hash, id, k );
  }
  else if(type == PCP_KEYSIG_NATIVE || type == PCP_KEYSIG_PBP) {
    pcp_keysig_t *keysig = (pcp_keysig_t *)key;
    HASH_ADD_STR( ptx->pcpkeysig_hash, id, keysig);
  }
  else {
    pcp_key_t *k = (pcp_key_t *)key;    
    HASH_ADD_STR( ptx->pcpkey_hash, id, k);
  }
}

int pcphash_count(PCPCTX *ptx) {
  return HASH_COUNT(ptx->pcpkey_hash);
}

int pcphash_countpub(PCPCTX *ptx) {
  return HASH_COUNT(ptx->pcppubkey_hash);
}

