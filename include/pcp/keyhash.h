/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013-2015 T.Linden.

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

#include "structs.h"



/** \defgroup KEYHASH KEYHASH
    @{

    Uthashes of secret and public key structures.

    Libpcp uses the <a href="http://troydhanson.github.io/uthash/">uthash</a>
    system to maintain lists of keys. There's one hash per key type. The
    hash has the same type as the key structure itself, and is stored in
    the PCP Context object.
*/



/*  wrapper for HASH_ITER */
/** Iterate over the list of secret keys.

    Sample use:

    @code
    pcp_key_t k = NULL;
    pcphash_iterate(ptx, k) {
      pcp_dumpkey(k);
    }
    @endcode

    Also, don't free() the keyhash or the temporary key pointer
    yourself. Use pcphash_clean() instead when done.
*/
#define pcphash_iterate(ptx, key)		\
  pcp_key_t *__k = NULL; \
  HASH_ITER(hh, ptx->pcpkey_hash, key, __k)


/** Iterate over the list of public keys.

    Sample use:

    @code
    pcp_pubkey_t k = NULL;
    pcphash_iteratepub(ptx, k) {
      pcp_dumppubkey(k);
    }
    @endcode

    Also, don't free() the keyhash or the temporary key pointer
    yourself. Use pcphash_clean() instead when done.
*/
#define pcphash_iteratepub(ptx, key)		\
  pcp_pubkey_t *__p = NULL; \
  HASH_ITER(hh, ptx->pcppubkey_hash, key, __p)

/** Delete an entry from a hash.

    \param[in] ptx Pcp Context object.

    \param[in] key A pointer to the key structure to delete.

    \param[in] type An integer specifying the key type to delete. \see _PCP_KEY_TYPES.

 */
void pcphash_del(PCPCTX *ptx, void *key, int type);

/** Free memory used by key global ptx-attached hashes. */
void pcphash_clean(PCPCTX *ptx);

/** Free memory by local pubkey hash */
void pcphash_cleanpub(pcp_pubkey_t *pub);

/** Check if a secret key with a given key-id exists in the hash.

    \param[in] ptx Pcp Context object.

    \param[in] id A string with the key-id (max 17 chars incl 0).

    \return Returns a pointer to the matching key or NULL if the id doesn't match.
*/
pcp_key_t *pcphash_keyexists(PCPCTX *ptx, char *id);

/** Check if a publickey with a given key-id exists in the hash.

    \param[in] ptx Pcp Context object.

    \param[in] id A string with the key-id (max 17 chars incl 0).

    \return Returns a pointer to the matching key or NULL if the id doesn't match.
*/
pcp_pubkey_t *pcphash_pubkeyexists(PCPCTX *ptx, char *id);

/** Add a key structure to the hash list.

    \param[in] ptx Pcp Context object.
    
    \param[in] key A pointer to the key structure to delete.

    \param[in] type An integer specifying the key type to delete. \see _PCP_KEY_TYPES.
 */
void pcphash_add(PCPCTX *ptx, void *key, int type);

/** Returns the number of secret keys in the hash.

    \param[in] ptx Pcp Context object.

    \return Number of keys.
*/
int pcphash_count(PCPCTX *ptx);

/** Returns the number of public keys in the hash.

    \param[in] ptx Pcp Context object.

    \return Number of keys.
*/
int pcphash_countpub(PCPCTX *ptx);



#define pcphash_iteratekeysig(ptx, key)		\
  pcp_keysig_t *__s = NULL; \
  HASH_ITER(hh, ptx->pcpkeysig_hash, key, __s)

pcp_keysig_t *pcphash_keysigexists(PCPCTX *ptx, char *id);

#endif /*  _HAVE_KEYHASH_H */

/**@}*/
