/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2014 T.v.Dein.

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
#include "buffer.h"

/*
  PCP private key structure. Most fields are self explanatory.
  Some notes:

  'encrypted' contains the encrypted ed25519 secret key. If it's set,
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
  byte pub[32];
  byte secret[32];
  byte edpub[32];
  byte edsecret[64];
  byte nonce[24];
  byte encrypted[112]; /*  both ed+curve encrypted */
  char owner[255];
  char mail[255];
  char id[17];
  uint8_t type;
  uint64_t ctime;   /*  8 */
  uint32_t version; /*  4 */
  uint32_t serial;  /*  4 */
  UT_hash_handle hh;
};

struct _pcp_pubkey_t {
  byte pub[32];
  byte edpub[32];
  char owner[255];
  char mail[255];
  char id[17];
  uint8_t type;
  uint64_t ctime;
  uint32_t version;
  uint32_t serial;
  UT_hash_handle hh;
};

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


typedef struct _pcp_key_t pcp_key_t;
typedef struct _pcp_pubkey_t pcp_pubkey_t;
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






/* RFC4880 alike public key export with some simplifications:

   In sig subpackets we're using fixed sized fields instead
   of the mess they use in rfc4880. Sorry. We use only these types:

            2 = Signature Creation Time     (4 byte)
            3 = Signature Expiration Time   (4 byte)
            9 = Key Expiration Time         (4 bytes)
           20 = Notation Data               (4 byte flags, N bytes name+value)
           27 = Key Flags                   (1 byte, use 0x02, 0x08 and 0x80
  
  The actual signature field doesn't contain the 1st 16 bits
  of the hash, since crypto_sign() created signatures consist
  of the hash+signature anyway.

  So, a full pubkey export looks like this

  version
  ctime
  cipher
  3 x raw keys           \
  sigheader               > calc hash from this
   sigsubs (header+data) /
  hash
  signature

  We use big-endian always.

  http://tools.ietf.org/html/rfc4880#section-5.2.3
 
 */
struct _pcp_rfc_pubkey_header_t {
  uint8_t version;
  uint32_t ctime;
  uint8_t cipher;
};

struct _pcp_rfc_pubkey_0x21_t {
  byte sig_ed25519_pub[crypto_sign_PUBLICKEYBYTES];
  byte ed25519_pub[crypto_sign_PUBLICKEYBYTES];
  byte curve25519_pub[crypto_box_PUBLICKEYBYTES];
};

struct _pcp_rfc_pubkey_sigheader_0x21_t {
  uint8_t version;
  uint8_t type; /* 0x1F only, self signed */
  uint8_t pkcipher;
  uint8_t hashcipher;
  uint16_t numsubs;
};

struct _pcp_rfc_pubkey_sigsub_0x21_t {
  uint32_t size;
  uint8_t type;
};

struct _pcp_rfc_pubkey_sig_0x21_t {
  byte signature[crypto_generichash_BYTES_MAX + crypto_sign_BYTES];
};

typedef struct _pcp_rfc_pubkey_header_t rfc_pub_h;
typedef struct _pcp_rfc_pubkey_0x21_t  rfc_pub_k;
typedef struct _pcp_rfc_pubkey_sigheader_0x21_t rfc_pub_sig_h;
typedef struct _pcp_rfc_pubkey_sigsub_0x21_t rfc_pub_sig_s;
typedef struct _pcp_rfc_pubkey_sig_0x21_t rfc_pub_sig;





void pcp_cleanhashes();
pcp_key_t *pcpkey_new ();

void pcp_keypairs(byte *csk, byte *cpk, byte *esk, byte *epk);
void pcp_ed_keypairs(byte *csk, byte *esk);

char *pcppubkey_get_art(pcp_pubkey_t *k);
char *pcpkey_get_art(pcp_key_t *k);

pcp_key_t *pcpkey_encrypt(pcp_key_t *key, char *passphrase);
pcp_key_t *pcpkey_decrypt(pcp_key_t *key, char *passphrase);
pcp_pubkey_t *pcpkey_pub_from_secret(pcp_key_t *key);
char *pcp_getkeyid(pcp_key_t *k);
char *pcp_getpubkeyid(pcp_pubkey_t *k);
unsigned char *pcppubkey_getchecksum(pcp_pubkey_t *k);
unsigned char *pcpkey_getchecksum(pcp_key_t *k);
void pcp_inithashes();

pcp_key_t *pcpkey_exists(char *id);
pcp_pubkey_t *pcppubkey_exists(char *id);

pcp_key_t * key2be(pcp_key_t *k);
pcp_key_t *key2native(pcp_key_t *k);
pcp_pubkey_t * pubkey2be(pcp_pubkey_t *k);
pcp_pubkey_t *pubkey2native(pcp_pubkey_t *k);

unsigned char * pcp_gennonce();

void pcpedit_key(char *keyid);

/*  use scrypt() to create a key from a passphrase and a nonce */
unsigned char *pcp_derivekey(char *passphrase, unsigned char *nonce);

pcp_key_t *pcp_derive_pcpkey (pcp_key_t *ours, char *theirs);

void pcp_seckeyblob(void *blob, pcp_key_t *k);
void pcp_pubkeyblob(void *blob, pcp_pubkey_t *k);
void *pcp_keyblob(void *k, int type); /*  allocates blob */

int pcp_sanitycheck_pub(pcp_pubkey_t *key);
int pcp_sanitycheck_key(pcp_key_t *key);


#endif /*  _HAVE_PCP_KEYPAIR_H */
