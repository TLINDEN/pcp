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


#ifndef _DEFINES_H
#define _DEFINES_H


/** \mainpage

    \section intro_sec Introduction

    This is the API documentation of libpcp, the library behind
    <a href="/PrettyCurvedPrivacy">Pretty Curved Privacy (pcp)</a>.
    The library can be used independently
    of pcp to manage keys and to encrypt or sign files or buffers.

    For most actual crypto related things, libpcp uses
    <a href="https://github.com/jedisct1/libsodium">libsodium, the portable NaCL library</a>.

    \section sample_sec Sample usage

    Example use of the libpcp library:

    \include tests/sample.c

    To compile the example, use the following commands:

    @code
    g++ -c sample.o `pkg-config --cflags libpcp1`
    g++ sample.o `pkg-config --libs libpcp1` -o sample
    @endcode
 */


#include "config.h"

typedef unsigned char   byte;           /*   Single unsigned byte = 8 bits */
typedef unsigned short  dbyte;          /*   Double byte = 16 bits */
typedef unsigned int    qbyte;          /*   Quad byte = 32 bits */

/*  key stuff, deprecated. */
#define PCP_ENFILE_HEADER "----- BEGIN PCP ENCRYPTED FILE -----\r\n"
#define PCP_ENFILE_FOOTER "\r\n----- END PCP ENCRYPTED FILE -----\r\n"

#define PCP_ZFILE_HEADER "----- BEGIN Z85 ENCODED FILE -----"
#define PCP_ZFILE_FOOTER "----- END Z85 ENCODED FILE -----"

#define PCP_SIG_HEADER "----- BEGIN ED25519 SIGNED MESSAGE -----"
#define PCP_SIG_START  "----- BEGIN ED25519 SIGNATURE -----"
#define PCP_SIG_END    "----- END ED25519 SIGNATURE -----"
#define PCP_SIGPREFIX  "\nnacl-"

#define PCP_ME "Pretty Curved Privacy"

#define PCP_KEY_VERSION 6
#define PCP_KEY_PRIMITIVE "CURVE25519-ED25519-SALSA20-POLY1305"

typedef enum _ZBEGINS {
  PCP_ENCRYPTED_FILE,
  Z85_ENCODED_FILE,
  ED25519_SIGNED_MESSAGE,
  ED25519_SIGNATURE,
  ED25519_CURVE29915_PUBLIC_KEY,
  ED25519_CURVE29915_PRIVATE_KEY,
} ZBEGINS;

/** 
    \addtogroup KEYS
    @{
*/    

/** \enum _PCP_KEY_TYPES

    Internal key types.
 */
typedef enum _PCP_KEY_TYPES {
  PCP_KEY_TYPE_MAINSECRET = 1, /**< 1 - Primary secret */
  PCP_KEY_TYPE_SECRET     = 2, /**< 2 - Other secret */
  PCP_KEY_TYPE_PUBLIC     = 3, /**< 3 - Public */
  PCP_KEYSIG_NATIVE       = 4, /**< 4 - PCP native key signature */
  PCP_KEYSIG_PBP          = 5  /**< 5 - PBP key signature */
} PCP_KEY_TYPES;

/** @}
 */

/*  save typing, dammit */
#define PCP_ENCRYPT_MAC crypto_secretbox_ZEROBYTES + crypto_secretbox_NONCEBYTES

/*  vault id */
#define PCP_VAULT_ID 14
#define PCP_VAULT_VERSION 2

/*  sigs */
#define PCP_SIG_VERSION 2

/*  crypto file format stuff */
/*  enabled via config.h (configure --enable-cbc) */
#ifndef PCP_CBC
  #define PCP_ASYM_CIPHER         5
  #define PCP_ASYM_CIPHER_ANON    6
  #define PCP_SYM_CIPHER          23
  #define PCP_ASYM_CIPHER_SIG     24
  #define PCP_BLOCK_SIZE          32 * 1024
#else
/*  CBC mode, use smaller blocks */
  #define PCP_ASYM_CIPHER         7
  #define PCP_ASYM_CIPHER_ANON    9
  #define PCP_ASYM_CIPHER_SIG     8
  #define PCP_SYM_CIPHER          25
  #define PCP_BLOCK_SIZE          1 * 1024
#endif

#define PCP_CRYPTO_ADD          (crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES)
#define PCP_BLOCK_SIZE_IN       (PCP_BLOCK_SIZE) + PCP_CRYPTO_ADD + crypto_secretbox_NONCEBYTES
#define PCP_ASYM_RECIPIENT_SIZE crypto_secretbox_KEYBYTES + PCP_CRYPTO_ADD + crypto_secretbox_NONCEBYTES

/* #define PCP_ASYM_ADD_SENDER_PUB */

/*  used for self encryption only */
#define PBP_COMPAT_SALT "qa~t](84z<1t<1oz:ik.@IRNyhG=8q(on9}4#!/_h#a7wqK{Nt$T?W>,mt8NqYq&6U<GB1$,<$j>,rSYI2GRDd:Bcm"

#define PCP_RFC_CIPHER 0x21 /* curve25519+ed25519+poly1305+salsa20+blake2 */



/* defines for key management (mgmt.c) */
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
#define EXP_PK_HEADER "----- BEGIN ED25519-CURVE29915 PUBLIC KEY -----"
#define EXP_PK_FOOTER "----- END ED25519-CURVE29915 PUBLIC KEY -----"
#define EXP_SK_HEADER "----- BEGIN ED25519-CURVE29915 PRIVATE KEY -----"
#define EXP_SK_FOOTER "----- END ED25519-CURVE29915 PRIVATE KEY -----"


/* pubkey export formats */
#define EXP_FORMAT_NATIVE   1
#define EXP_FORMAT_PBP      2
#define EXP_FORMAT_YAML     3
#define EXP_FORMAT_C        4
#define EXP_FORMAT_PY       5
#define EXP_FORMAT_PERL     6





#endif /*  _DEFINES_H */

/**@}*/
