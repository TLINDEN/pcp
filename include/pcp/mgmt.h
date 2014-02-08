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


#ifndef _HAVE_PCP_MGMT_H
#define _HAVE_PCP_MGMT_H

#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "defines.h"
#include "platform.h"
#include "mem.h"
#include "ed.h"
#include "key.h"
#include "buffer.h"




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
  uint8_t type;
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

#define EXP_PK_CIPHER        0x21
#define EXP_PK_CIPHER_NAME  "CURVE25519-ED25519-POLY1305-SALSA20"

#define EXP_HASH_CIPHER      0x22
#define EXP_HASH_NAME       "BLAKE2"

#define EXP_SIG_CIPHER       0x23
#define EXP_SIG_CIPHER_NAME "ED25519"

#define EXP_SIG_VERSION      0x01
#define EXP_SIG_TYPE         0x1F /* self signed */

/* sig sub notiation we support */
#define EXP_SIG_SUB_CTIME     2
#define EXP_SIG_SUB_SIGEXPIRE 3
#define EXP_SIG_SUB_KEYEXPIRE 9
#define EXP_SIG_SUB_NOTATION  20
#define EXP_SIG_SUB_KEYFLAGS  27

/* in armored mode, we're using the usual head+foot */
#define EXP_PK_HEADER "-----BEGIN ED25519-CURVE29915 PUBLIC KEY-----"
#define EXP_PK_FOOTER "------END ED25519-CURVE29915 PUBLICKEY------"


/* export public key */
Buffer *pcp_get_rfc_pub (pcp_pubkey_t *key, pcp_key_t *sk);

#endif // _HAVE_PCP_MGMT_H
