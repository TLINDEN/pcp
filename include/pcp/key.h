/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013-2014 T.v.Dein.

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


#ifndef _HAVE_PCP_KEYPAIR_H
#define _HAVE_PCP_KEYPAIR_H

#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "defines.h"
#include "platform.h"
#include "mem.h"
#include "mac.h"
#include "randomart.h"
#include "version.h"
#include "z85.h"
#include "uthash.h"
#include "jenhash.h"
#include "scrypt.h"
#include "keysig.h"


/**
 * \defgroup PCPKEY PCP public and secret key functions
 * @{
 */


/** \struct _pcp_key_t

    PCP private key structure. Most fields are self explanatory.

  Some notes:

  'encrypted' contains the encrypted secret keys (contatenated mastersecret,
  secret and edsecret). If it's set,
  the field 'secret' which contains the clear secret key will
  be zeroed with random values, the first byte will be 0. Same
  for the field 'edsecret'.

  'nonce' contains the nonce required to decrypt the encrypted
  secret, if set.

  'serial' is a random number.

  'id' is a string containing the hex values of the CRC32 checksum
  of the public and secret key.

  Upon creation everything will be filled with random bytes.
  String fields will contain a string followed by 0 followed
  by the rest of the pre-filled random bytes. To denote a string
  field as empty, the first byte will be set to 0.

  There are dynamically calculated attributes as well:

  'checksum' is a 256 bit SHA hash of the public key returned
  by pcpkey_getchecksum() or pcppubkey_getchecksum().

  'random id' is a random art ascii image returned by
  pcppubkey_get_art() or pcpkey_get_art(), calculated from
  the public key.

  If exported to a single file or printed, the structure will
  be encoded using Z85 encoding.

 */
struct _pcp_key_t {
  byte masterpub[32];    /**< ED25519 master public key signing key */
  byte mastersecret[64]; /**< ED25519 master secret key signing key */
  byte pub[32];          /**< Curve25519 encryption public key */
  byte secret[32];       /**< Curve25519 encryption secret key */
  byte edpub[32];        /**< ED25519 public signing key */
  byte edsecret[64];     /**< ED25519 secret signing key */
  byte nonce[24];        /**< random nonce used to encrypt secret keys */
  byte encrypted[176];   /**< concatenated and encrypted secret keys */
  char owner[255];       /**< the key owner, string */
  char mail[255];        /**< mail address of the owner, string */
  char id[17];           /**< key-id, used internally only, jenhash of public keys */
  uint8_t type;          /**< key type: MASTER_SECRET or SECRET */
  uint64_t ctime;        /**< creation time, epoch */
  uint32_t version;      /**< key version */
  uint32_t serial;       /**< serial number of the key, randomly generated */
  UT_hash_handle hh;
};

/** Typedef for secret keys */
typedef struct _pcp_key_t pcp_key_t;

/** \struct _pcp_pubkey_t

    PCP public key structure.

    This structure contains a subset of the pcp_key_t structure
    without the secret and nonce fields.
*/
struct _pcp_pubkey_t {
  byte masterpub[32];    /**< ED25519 master public key signing key */
  byte sigpub[32];       /**< ED25519 public signing key */
  byte pub[32];          /**< Curve25519 encryption public key */
  byte edpub[32];        /**< ED25519 public signing key (FIXME: huh? 2 of them???) */
  char owner[255];       /**< the key owner, string */
  char mail[255];        /**< mail address of the owner, string */
  char id[17];           /**< key-id, used internally only, jenhash of public keys */
  uint8_t type;          /**< key type: MASTER_SECRET or SECRET */
  uint64_t ctime;        /**< creation time, epoch */
  uint32_t version;      /**< key version */
  uint32_t serial;       /**< serial number of the key, randomly generated */
  uint8_t valid;         /**< 1 if import signature verified, 0 if not */
  byte signature[crypto_generichash_BYTES_MAX + crypto_sign_BYTES]; /**< raw binary blob of pubkey export signature */
  UT_hash_handle hh;
};

/** Typedef for public keys */
typedef struct _pcp_pubkey_t pcp_pubkey_t;


/*  the PBP public key format */
/*  keys.mp+keys.cp+keys.sp+keys.name */
struct _pbp_pubkey_t {
  byte sigpub[crypto_sign_PUBLICKEYBYTES];
  byte edpub[crypto_sign_PUBLICKEYBYTES];
  byte pub[crypto_box_PUBLICKEYBYTES];
  char iso_ctime[32];
  char iso_expire[32];
  char name[1024];
};

typedef struct _pbp_pubkey_t pbp_pubkey_t;

/*
  encrypted recipient list, required for crypt+sign
  contains the encrypted recipients and the secret
  key required for signing the message+recipients.
*/
struct _pcp_rec_t {
  size_t ciphersize;
  byte *cipher;
  pcp_key_t *secret;
  pcp_pubkey_t *pub;
};

typedef struct _pcp_rec_t pcp_rec_t;

#define PCP_RAW_KEYSIZE    sizeof(pcp_key_t)    - sizeof(UT_hash_handle)
#define PCP_RAW_PUBKEYSIZE sizeof(pcp_pubkey_t) - sizeof(UT_hash_handle)


/** Generate a new key structure.

    Owner and mail field must be filled by the caller.
    Memory for the returned pointer will be allocated
    by the function.

    \return Returns pointer to new pcp_key_t structure.
 */
pcp_key_t *pcpkey_new ();

void pcp_keypairs(byte *msk, byte *mpk, byte *csk, byte *cpk, byte *esk, byte *epk);

/** Generate an ASCII art image of the public key.

    This functions originally appeared in OpenSSH rev 1.70,
    comitted by Alexander von Gernler, published under the
    BSD license.

    Human beings are bad at memorizing numbers, especially
    large numbers, but we are very good at recognizing images.
    This function calculates an ascii art image of a public
    key, which the user shall always see, when used. If the
    image changes, the user would immediately recognize the
    change, even unconsciously.

    Sample random art image from the following public key:

    @code
    c308455ed4cf0c140bf48bfb0d87c4999c66e823bbe74ff16e2a9adc8e770747

    +----------------+
    |     .o.ooo.    |
    |     o .  o     |
    |    . .    =    |
    |     . o    +   |
    |      . +       |
    |         .      |
    |                |
    |                |
    +----------------+
    @endcode

    \param[in] k The public key structure.

    \return Returns an allocated char pointer containing the ASCII art image.
            The caller is responsible to free() it.
 */
char *pcppubkey_get_art(pcp_pubkey_t *k);

/** Generate an ASCII art image of the public key part of a secret key.

    see pcppubkey_get_art() for details.

    \param[in] k The secret key structure.

    \return Returns an allocated char pointer containing the ASCII art image.
            The caller is responsible to free() it.
 */
char *pcpkey_get_art(pcp_key_t *k);

/** Encrypt a secret key structure.

    The given passphrase will be used to calculate an encryption
    key using the scrypt() function.

    The secret keys will be concatenated and encrypted, the result
    will be put into the 'encrypted' field. The first byte of each
    secret key field will be set to 0 to indicate the key is encrypted.

    The data structure will be modified directly, no new memory
    will be allocated.

    The caller is responsible to clear the passphrase right after
    use and free() it as soon as possible.

    \param[in,out] key The secret key structure.

    \param[in] passphrase The passphrase used to encrypt the key.

    \return Returns a pointer to the encrypted key structure or NULL
            in case of an error. Use fatals_ifany() to catch them.
 */
pcp_key_t *pcpkey_encrypt(pcp_key_t *key, char *passphrase);

/** Decrypt a secret key structure.

    The given passphrase will be used to calculate an encryption
    key using the scrypt() function.

    The encryption key will be used to decrypt the 'encrypted'
    field of the structure. If it works, the result will be dissected
    and put into the correspondig secret key fields.

    The data structure will be modified directly, no new memory
    will be allocated.

    The caller is responsible to clear the passphrase right after
    use and free() it as soon as possible.

    \param[in,out] key The secret key structure.

    \param[in] passphrase The passphrase used to decrypt the key.

    \return Returns a pointer to the decrypted key structure or NULL
            in case of an error. Use fatals_ifany() to catch them.

 */
pcp_key_t *pcpkey_decrypt(pcp_key_t *key, char *passphrase);

/** Generate a public key structure from a given secret key structure.

    This function extracts all required fields and fills a newly
    allocated pcp_pubkey_t structure.

    The caller is responsible to clear and free() it after use.

    \param[in] key The secret key structure.

    \return Returns a new pcp_pubkey_t structure.
 */
pcp_pubkey_t *pcpkey_pub_from_secret(pcp_key_t *key);


/** Calculate a key-id from public key fields.

    This function calculates 2 JEN Hashes: one from the 'pub'
    field and one from the 'edpub' field. It the puts them
    together into a newly allocated char pointer of 17 bytes
    length as hex, terminated with a 0.

    The key-id is supposed to be collision save, but there's
    no guarantee. However, it's used locally only, it wont be
    transmitted over the network and it's not part of any exported
    packet.

    \param[in] k The secret key structure.

    \return Returns a char pointer containing the key-id string.
 */
char *pcp_getkeyid(pcp_key_t *k);


/** Calculate a key-id from public key fields.

    This does the same as pcp_getkeyid() but uses a pcp_pubkey_t
    as input.


    \param[in] k The public key structure.

    \return Returns a char pointer containing the key-id string.
*/
char *pcp_getpubkeyid(pcp_pubkey_t *k);

/** Calculate a checksum of a public key.

    This function calculates a 32 byte checksum of the
    encryption public key part of the given pcp_pubkey_t
    structure using crypto_hash_sha256.

    The returned pointer will be allocated and it is the
    responsibility of the caller to free() ist after use.

    \param[in] k The public key structure.

    \return Returns a pointer to an 32 byte unsigned char.
 */
unsigned char *pcppubkey_getchecksum(pcp_pubkey_t *k);

/** Calculate a checksum of a public key part of the given secret key.

    See pcppubkey_getchecksum().

    \param[in] k The secret key structure.

    \return Returns a pointer to an 32 byte unsigned char.
 */
unsigned char *pcpkey_getchecksum(pcp_key_t *k);


/** Checks if a secret key structure is registered in the secret key hash.

    Returns a pointer to a pcp_key_t structure if there
    exists a secret key structure with the given id in the
    secret key hash.

    FIXME: needs to be moved to keyhash.h.

    \param[in] id A null-terminated char pointer of 17 bytes containing a key-id.

    \return Returns a pointer to a pcp_key_t struture or NULL if no key exists.
 */
pcp_key_t *pcpkey_exists(char *id);

/** Checks if a public key structure is registered in the public key hash.

    Returns a pointer to a pcp_pubkey_t structure if there
    exists a public key structure with the given id in the
    public key hash.

    FIXME: needs to be moved to keyhash.h.

    \param[in] id A null-terminated char pointer of 17 bytes containing a key-id.

    \return Returns a pointer to a pcp_pubkey_t struture or NULL if no key exists.
 */
pcp_pubkey_t *pcppubkey_exists(char *id);

pcp_key_t * key2be(pcp_key_t *k);
pcp_key_t *key2native(pcp_key_t *k);
pcp_pubkey_t * pubkey2be(pcp_pubkey_t *k);
pcp_pubkey_t *pubkey2native(pcp_pubkey_t *k);

/** Generate a nonce.

    This function generates a 24 byte nonce used for cryptographic
    functions. It allocates the memory and the caller is responsible
    to clear and free() it after use.

    \return Returns a pointer to a 24 byte unsigned char array.
*/
unsigned char * pcp_gennonce();

/*  use scrypt() to create a key from a passphrase and a nonce
    FIXME: use pure scrypt() instead.
*/
unsigned char *pcp_derivekey(char *passphrase, unsigned char *nonce);

/* FIXME: abandon and use Buffer instead */
void pcp_seckeyblob(void *blob, pcp_key_t *k);
void pcp_pubkeyblob(void *blob, pcp_pubkey_t *k);
void *pcp_keyblob(void *k, int type); /*  allocates blob */

/** Make a sanity check of the given public key structure.

    \param[in] key The public key structure.

    \return Returns 1 if the sanity check succeeds, 0 otherwise.
            Use fatals_ifany() to check why.
*/
int pcp_sanitycheck_pub(pcp_pubkey_t *key);

/** Make a sanity check of the given secret key structure.

    \param[in] key The secret key structure.

    \return Returns 1 if the sanity check succeeds, 0 otherwise.
            Use fatals_ifany() to check why.
*/
int pcp_sanitycheck_key(pcp_key_t *key);


#endif /*  _HAVE_PCP_KEYPAIR_H */

/**@}*/
