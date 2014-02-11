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

#ifndef _HAVE_KEYHASH_H
#define _HAVE_KEYHASH_H

#include "uthash.h"
#include "key.h"

/* storage of keys in a global hash */
extern pcp_key_t *pcpkey_hash;
extern pcp_pubkey_t *pcppubkey_hash;
extern pcp_key_t *__k;
extern pcp_pubkey_t *__p;

/*  wrapper for HASH_ITER */
#define pcphash_iterate(key) \
  __k = NULL; \
  HASH_ITER(hh, pcpkey_hash, key, __k)

#define pcphash_iteratepub(key) \
  __p = NULL; \
  HASH_ITER(hh, pcppubkey_hash, key, __p)


void pcphash_init();
void pcphash_del(void *key, int type);
void pcphash_clean();

pcp_key_t *pcphash_keyexists(char *id);
pcp_pubkey_t *pcphash_pubkeyexists(char *id);

void pcphash_add(void *key, int type);
int pcphash_count();
int pcphash_countpub();

/* the same, for keysigs */
extern pcp_keysig_t *pcpkeysig_hash;
extern pcp_keysig_t *__s;

#define pcphash_iteratekeysig(key) \
  __s = NULL; \
  HASH_ITER(hh, pcpkeysig_hash, key, __s)

pcp_keysig_t *pcphash_keysigexists(char *id);

#endif /*  _HAVE_KEYHASH_H */
