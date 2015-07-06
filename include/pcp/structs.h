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

#ifndef _HAVE_PCP_STRUCTS_H
#define _HAVE_PCP_STRUCTS_H

#include "defines.h"
#include "uthash.h"
#include <sodium.h>

/** 
    \addtogroup KEYS
    @{
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

/** \struct _pcp_rec_t

    Encrypted recipient list.

    Encrypted recipient list, required for crypt+sign
    contains the encrypted recipients and the secret
    key required for signing the message+recipients.

    Used internally only.
*/
struct _pcp_rec_t {
  size_t ciphersize; /**< the size of the encrypted recipient list */
  byte *cipher;      /**< contains the whole encrypted recipient list */
  pcp_key_t *secret; /**< the secret key of the recipient for signing */
  pcp_pubkey_t *pub; /**< if verification were ok, contains the public key of the signer */
};

/** Typedef for public keys */
typedef struct _pcp_rec_t pcp_rec_t;


/* holds a public key signature */
struct _pcp_keysig_t {
  uint8_t type;
  uint32_t size;
  char id[17];
  byte checksum[32];
  byte *blob;
  UT_hash_handle hh;
};

typedef struct _pcp_keysig_t pcp_keysig_t;

/** @}
 */










/** 
    \addtogroup CONTEXT
    @{
*/  


/** \struct _pcp_ctx_t

    PCP context object.

    Holds error state and key hashes.
*/

struct _pcp_ctx_t {
  char *pcp_err;    /**< last error message. retrieve with fatals_ifany() */
  byte pcp_errset;  /**< indicates if an error occurred. */
  int  pcp_exit;    /**< exit code for pcp commandline utility */
  int  verbose;     /**< enable verbose output */
#ifdef HAVE_JSON
  int  json;        /**< enable json i/o */
#endif
  pcp_key_t *pcpkey_hash;       /**< hash containing for keys */
  pcp_pubkey_t *pcppubkey_hash; /**< hash for keys. */
  pcp_keysig_t *pcpkeysig_hash; /**< hash for key sigs */
};

typedef struct _pcp_ctx_t PCPCTX;

/** @}
 */








/** 
    \addtogroup VAULT
    @{
*/  

/** \struct _vault_t
    This structure represents a vault. */
struct _vault_t {
  char *filename;    /**< The filename of the vault (full path) */
  FILE *fd;          /**< Filehandle if opened */
  uint8_t unsafed;   /**< Flag to tell if the file needs to be written */
  uint8_t isnew;     /**< Flag to tell if the vault has been newly created */
  uint32_t size;     /**< Filesize */
  time_t modified;   /**< mtime */
  mode_t mode;       /**< File mode */
  uint32_t version;  /**< Vault version */
  byte checksum[32]; /**< SHA256 checksum over the whole vault */
};

/** Name of the struct */
typedef struct _vault_t vault_t;

/** \struct _vault_header_t
    Defines the vault header. */
struct _vault_header_t {
  uint8_t fileid;    /**< File id, proprietary. Marks the vault as a vault */
  uint32_t version;  /**< File version */
  byte checksum[32]; /**< SHA256 checksum over the whole vault */
};

/** Name of the struct */
typedef struct _vault_header_t vault_header_t;

/** \struct _vault_item_header_t
    An item header. */
struct _vault_item_header_t {
  uint8_t type;       /**< Item type (secret key, public, key, keysig, \see _PCP_KEY_TYPES */
  uint32_t size;      /**< Size of the item */
  uint32_t version;   /**< Version of the item */
  byte checksum[32];  /**< SHA256 checksum of the item */
};

/** Name of the struct */
typedef struct _vault_item_header_t vault_item_header_t;

/** @}
 */




/** 
    \addtogroup BUFFER
    @{
*/  

/** \struct _pcp_buffer
    A flexible buffer object wich automatically resizes, if neccessary.
*/
struct _pcp_buffer {
  char *name;        /**< just for convenience in error messages and the like, so we know which buffer cause trouble */
  uint8_t allocated; /**< marks the buffer as allocated */
  size_t blocksize;  /**< the blocksize to use when resizing, also used for initial malloc() */
  size_t size;       /**< stores the current allocated size of the object */
  size_t offset;     /**< current read position */
  size_t end;        /**< current write position, data end. maybe less than size. */
  uint8_t isstring;  /**< treat as char array/string */
  void *buf;         /**< the actual storage buffer */
};

/** The name used everywhere */
typedef struct _pcp_buffer Buffer;


/** @}
 */









/** 
    \addtogroup PCPSTREAMS
    @{
*/  

/** \struct _pcp_stream_t
    An I/O wrapper object backed by a file or a buffer.
*/
struct _pcp_stream_t {
  FILE *fd;          /**< The backend FILE stream */
  Buffer *b;         /**< The backend Buffer object */
  Buffer *cache;     /**< The caching Buffer object (for look ahead read) */
  Buffer *next;      /**< The caching Next-Buffer object (for look ahead read) */
  Buffer *save;      /**< Temporary buffer to backup overflow data */
  uint8_t is_buffer; /**< Set to 1 if the backend is a Buffer */
  uint8_t eof;       /**< Set to 1 if EOF reached */
  uint8_t err;       /**< Set to 1 if an error occured */
  uint8_t armor;     /**< Set to 1 if Z85 en/de-coding is requested */
  uint8_t determine; /**< Set to 1 to automatically determine armor mode */
  uint8_t firstread; /**< Internal flag, will be set after first read() */
  size_t  linewr;    /**< Used for Z85 writing, number of chars written on last line */
  size_t  blocksize; /**< Blocksize used for z85, if requested */
  uint8_t is_output; /**< marks the stream as output stream */
  uint8_t have_begin; /**< flag to indicate we already got the begin header, if any */
  size_t pos;        /**< remember i/o position */
};

typedef enum _PSVARS {
  PSMAXLINE = 20000
} PSVARS;


/** The name used everywhere */
typedef struct _pcp_stream_t Pcpstream;
/** @}
 */






/* various helper structs for mgmt.c, used internally only */
struct _pcp_rfc_pubkey_header_t {
  uint8_t version;
  uint64_t ctime;
  uint8_t cipher;
};

struct _pcp_rfc_pubkey_0x21_t {
  byte sig_ed25519_pub[crypto_sign_PUBLICKEYBYTES];
  byte ed25519_pub[crypto_sign_PUBLICKEYBYTES];
  byte curve25519_pub[crypto_box_PUBLICKEYBYTES];
};

struct _pcp_rfc_pubkey_sigheader_0x21_t {
  uint8_t version;
  uint8_t type;
  uint8_t pkcipher;
  uint8_t hashcipher;
  uint16_t numsubs;
};

struct _pcp_rfc_pubkey_sigsub_0x21_t {
  uint32_t size;
  uint8_t type;
};

typedef struct _pcp_rfc_pubkey_header_t rfc_pub_h;
typedef struct _pcp_rfc_pubkey_0x21_t  rfc_pub_k;
typedef struct _pcp_rfc_pubkey_sigheader_0x21_t rfc_pub_sig_h;
typedef struct _pcp_rfc_pubkey_sigsub_0x21_t rfc_pub_sig_s;

struct _pcp_ks_bundle_t {
  pcp_pubkey_t *p;
  pcp_keysig_t *s;
};
typedef struct _pcp_ks_bundle_t pcp_ks_bundle_t;

#endif //_HAVE_PCP_STRUCTS_H
