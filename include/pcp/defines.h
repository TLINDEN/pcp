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


#ifndef _DEFINES_H
#define _DEFINES_H


/** \mainpage

    \section intro_sec Introduction

    This is the API documentation of libpcp, the library behind
    Pretty Curved Privacy (pcp). The library can be used independently
    of pcp to manage keys and to encrypt or sign files or buffers.

    For most actual crypto related things, libpcp uses libsodium,
    the portable NaCL library.

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

/*  key stuff */
#define PCP_KEY_HEADER "----- BEGIN PCP SECRET KEY -----"
#define PCP_KEY_FOOTER "------ END PCP SECRET KEY ------"

#define PCP_PUBKEY_HEADER "----- BEGIN PCP PUBLIC KEY -----"
#define PCP_PUBKEY_FOOTER "------ END PCP PUBLICKEY ------"

#define PCP_ENFILE_HEADER "----- BEGIN PCP ENCRYPTED FILE -----"
#define PCP_ENFILE_FOOTER "------ END PCP ENCRYPTED FILE ------"

#define PCP_ZFILE_HEADER "----- BEGIN Z85 ENCODED FILE -----"
#define PCP_ZFILE_FOOTER "------ END Z85 ENCODED FILE ------"

#define PCP_SIG_HEADER "----- BEGIN ED25519 SIGNED MESSAGE -----"
#define PCP_SIG_START  "----- BEGIN ED25519 SIGNATURE -----"
#define PCP_SIG_END    "------ END ED25519 SIGNATURE ------"
#define PCP_SIGPREFIX  "\nnacl-"

#define PCP_ME "Pretty Curved Privacy"

#define PCP_KEY_VERSION 6
#define PCP_KEY_PRIMITIVE "CURVE25519-ED25519-SALSA20-POLY1305"

#define PCP_KEY_TYPE_MAINSECRET 1
#define PCP_KEY_TYPE_SECRET     2
#define PCP_KEY_TYPE_PUBLIC     3
#define PCP_KEYSIG_NATIVE       4
#define PCP_KEYSIG_PBP          5

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
  #define PCP_SYM_CIPHER          23
  #define PCP_BLOCK_SIZE          32 * 1024
#else
/*  CBC mode, use smaller blocks */
  #define PCP_ASYM_CIPHER         7
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

/**
 * \defgroup FATALS FATALS
 * @{

 A couple of functions to catch errors and display them.

 */

/*  error handling */

/** \var PCP_ERR

    Global variable holding the last error message.
    Can be retrieved with fatals_ifany().
*/
extern char *PCP_ERR;

/** \var PCP_ERRSET

    Global variable indicating if an error occurred.
*/
extern byte PCP_ERRSET;

/** \var PCP_EXIT

    Exitcode for the pcp commandline utility.
*/
extern int PCP_EXIT;

/** Set an error message.

    This function gets a printf() like error message,
    which it stores in the global PCP_ERR variable
    and sets PCP_ERRSET to 1.

    \param[in] fmt printf() like format description.

    \param[in] ... format parameters, if any.
*/
void fatal(const char * fmt, ...);

/** Prints error messages to STDERR, if there are some.

    FIXME: add something like this which returns the
    message.
*/
void fatals_ifany();

/** Reset the error variables.

    This can be used to ignore previous errors.
    Use with care.
*/
void fatals_reset();

/** Cleans up memory allocation of global error variables.
 */
void fatals_done();

#endif /*  _DEFINES_H */

/**@}*/
