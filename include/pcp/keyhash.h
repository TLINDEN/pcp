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

/** \defgroup KEYHASH KEYHASH
    @{

    Uthashes of secret and public key structures.

    Libpcp uses the <a href="http://troydhanson.github.io/uthash/">uthash</a>
    system to maintain lists of keys. There's one hash per key type. The
    hash has the same type as the key structure itself, but is global.
*/

#include "uthash.h"
#include "key.h"

/* storage of keys in a global hash */

/** Global hash for secret keys. */
extern pcp_key_t *pcpkey_hash;

/** Global hash for public keys. */
extern pcp_pubkey_t *pcppubkey_hash;

extern pcp_key_t *__k;
extern pcp_pubkey_t *__p;

/*  wrapper for HASH_ITER */
/** Iterate over the list of secret keys.

    Sample use:

    @code
    pcp_key_t k = NULL;
    pcphash_iterate(k) {
      pcp_dumpkey(k);
    }
    @endcode

    Also, don't free() the keyhash or the temporary key pointer
    yourself. Use pcphash_clean() instead when done.
*/
#define pcphash_iterate(key) \
  __k = NULL; \
  HASH_ITER(hh, pcpkey_hash, key, __k)


/** Iterate over the list of public keys.

    Sample use:

    @code
    pcp_pubkey_t k = NULL;
    pcphash_iteratepub(k) {
      pcp_dumppubkey(k);
    }
    @endcode

    Also, don't free() the keyhash or the temporary key pointer
    yourself. Use pcphash_clean() instead when done.
*/
#define pcphash_iteratepub(key) \
  __p = NULL; \
  HASH_ITER(hh, pcppubkey_hash, key, __p)

/** Initialize the global hashes. */
void pcphash_init();

/** Delete an entry from a hash.

    \param[in] key A pointer to the key structure to delete.

    \param[in] type An integer specifying the key type to delete. \see _PCP_KEY_TYPES.

 */
void pcphash_del(void *key, int type);

/** Frees the memory allocated by the hashes.

    Clears and frees memory of all keys in the hash lists
    and the hashes themselfes.

 */
void pcphash_clean();

/** Check if a secret key with a given key-id exists in the hash.

    \param[in] id A string with the key-id (max 17 chars incl 0).

    \return Returns a pointer to the matching key or NULL if the id doesn't match.
*/
pcp_key_t *pcphash_keyexists(char *id);

/** Check if a publickey with a given key-id exists in the hash.

    \param[in] id A string with the key-id (max 17 chars incl 0).

    \return Returns a pointer to the matching key or NULL if the id doesn't match.
*/
pcp_pubkey_t *pcphash_pubkeyexists(char *id);

/** Add a key structure to the hash list.
    
    \param[in] key A pointer to the key structure to delete.

    \param[in] type An integer specifying the key type to delete. \see _PCP_KEY_TYPES.
 */
void pcphash_add(void *key, int type);

/** Returns the number of secret keys in the hash.

    \return Number of keys.
*/
int pcphash_count();

/** Returns the number of public keys in the hash.

    \return Number of keys.
*/
int pcphash_countpub();

/** Global hash for key signatures. */
extern pcp_keysig_t *pcpkeysig_hash;
extern pcp_keysig_t *__s;

#define pcphash_iteratekeysig(key) \
  __s = NULL; \
  HASH_ITER(hh, pcpkeysig_hash, key, __s)

pcp_keysig_t *pcphash_keysigexists(char *id);

#endif /*  _HAVE_KEYHASH_H */

/**@}*/
