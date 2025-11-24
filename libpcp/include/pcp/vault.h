/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013-2015 T.v.Dein.

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


#ifndef _HAVE_PCP_VAULT
#define _HAVE_PCP_VAULT

/** \defgroup VAULT VAULT
    @{

    The vault file is used to store keys and key-signatures on disk.
    It works like a keyring.

    \section vformat Vault File Format

    The vault file contains all public and secret keys. It's a portable
    binary file.

    The file starts with a header:

    @code
    +-------------------------------------------+
    | Field        Size   Description           |
    +-------------------------------------------+
    | File ID    |    1 | Vault Identifier 0xC4 |
    +-------------------------------------------+
    | Version    |    4 | Big endian, version   |
    +-------------------------------------------+
    | Checksum   |   32 | SHA256 Checksum       |
    +-------------------------------------------+
    @endcode

    The checksum is a checksum of all keys.
    
    The header is followed by the keys. Each key is preceded by an
    item header which looks like this:
    
    @code
    +--------------------------------------------+
    | Field        Size   Description            |
    +--------------------------------------------+
    | Type       |    1 | Key type (S,P,M)       |
    +--------------------------------------------+
    | Size       |    4 | Big endian, keysize    |
    +--------------------------------------------+
    | Version    |    4 | Big endian, keyversion |
    +--------------------------------------------+
    | Checksum   |   32 | SHA256 Key Checksum    |
    +--------------------------------------------+
    @endcode

    Type can be one of:
    
    - PCP_KEY_TYPE_MAINSECRET 0x01
    - PCP_KEY_TYPE_SECRET     0x02
    - PCP_KEY_TYPE_PUBLIC     0x03

    The item header is followed by the actual key contents.
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <sodium.h>
#include <unistd.h>

#include "defines.h"
#include "platform.h"
#include "mem.h"
#include "key.h"
#include "uthash.h"
#include "buffer.h"
#include "keysig.h"
#include "structs.h"
#include "context.h"


/** Open a vault file.
    If the file doesn't exist, it will be created.

    \param[in] ptx pcp context.
    \param[in] filename The filename of the vault file.

    \return Returns a vault object.
 */
vault_t *pcpvault_init(PCPCTX *ptx, char *filename);


/*  Creates a new vault file. Called internally only.
    If is_tmp If set to 1, create a temporary vault file.
 */
vault_t *pcpvault_new(PCPCTX *ptx, char *filename, int is_tmp);


/*  Writes the initial vault header to the vault.
    Called internally only. */
int pcpvault_create(PCPCTX *ptx, vault_t *vault);


/** Add an item to the vault.

    Adds \a item with the size \a itemsize and type \a type
    to the vault. Generates the item header and the checksum
    of the item.

    This function writes directly into the vault file. Use
    with care. To be safe, use pcpvault_addkey() instead.

    \param[in] ptx pcp context.
    \param[out] vault The vault object.
    \param[in] item The item to write.
    \param[in] itemsize Size of the item.
    \param[in] type Type of the item.  \see _PCP_KEY_TYPES.
    
    \return Returns the number of bytes written or 0 in case of
            an error. Check fatals_if_any().
 */
int pcpvault_additem(PCPCTX *ptx, vault_t *vault, void *item, size_t itemsize, uint8_t type);


/** Add a key to the vault.

    This function determines the size of the item to write
    based on the given type. It converts the internal structure
    to a binary blob and converty multibyte values to big
    endian.

    It copies the given vault file to a temporary vault file,
    adds the item and if this went ok, copies the temporary file
    back to the original location. It then re-calculates the
    vault checksum and puts it into the vault header.

    \param[in] ptx pcp context.
    \param[out] vault The vault object.
    \param[in] item The item to write (a key or keysig)
    \param[in] type Type of the item.  \see _PCP_KEY_TYPES.

    \return Returns 0 on success or 1 in case of errors. Check fatals_if_any().
 */
int pcpvault_addkey(PCPCTX *ptx, vault_t *vault, void *item, uint8_t type);


/** Close a vault file.

    If the vault is in unsafed state, write everything to disk
    and close the vault. Before overwriting the current vault file
    a backup will be made. If anything fails during writing the
    backup file will be retained and the error message will
    contain the filename of the backup file, so that the user
    doesn't loose data.

    \param[in] ptx pcp context.
    \param[out] vault The vault object.

    \return Returns 0. Check fatals_if_any() anyway.

 */
int pcpvault_close(PCPCTX *ptx, vault_t *vault);

/** Free vault resources

    \param[in] vault The vault object.
*/
void pcpvault_free(vault_t *vault);

/** Reads in the vault contents.

    This function reads the open vault contents and puts
    them into the apropriate hashes. \see KEYHASH.

    Currently only known types can be read. If your're saving
    unknown types to the vault, an error will occur.  \see _PCP_KEY_TYPES.

    Each item will be converted put into the aproprieate
    structure, multibyte values will be converted to
    host endianess. It also calculates the checksum of the vault
    contents and compares it with the one stored in the vault
    header. If it doesn't match an error will be thrown.

    \param[in] ptx pcp context.
    \param[out] vault The vault object.

    \return Returns 0 on success or -1 in case of errors. Check fatals_if_any().
 */
int pcpvault_fetchall(PCPCTX *ptx, vault_t *vault);


/* Write everything back to disk. */
int pcpvault_writeall(PCPCTX *ptx, vault_t *vault);

/* copy a vault to another file */
int pcpvault_copy(PCPCTX *ptx, vault_t *tmp, vault_t *vault);

/* delete a vault file */
void pcpvault_unlink(vault_t *tmp);

/* calculate the checksum of the current vault (that is, from the
   list of keys in the current context */
byte *pcpvault_create_checksum(PCPCTX *ptx);

/* write the new checksum to the header of the current vault */
void pcpvault_update_checksum(PCPCTX *ptx, vault_t *vault);

/* bigendian converters */
vault_header_t * vh2be(vault_header_t *h);
vault_header_t * vh2native(vault_header_t *h);
vault_item_header_t * ih2be(vault_item_header_t *h);
vault_item_header_t * ih2native(vault_item_header_t *h);

#endif /*  _HAVE_PCP_VAULT */

/**@}*/
