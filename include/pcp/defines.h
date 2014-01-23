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

typedef unsigned char   byte;           //  Single unsigned byte = 8 bits
typedef unsigned short  dbyte;          //  Double byte = 16 bits
typedef unsigned int    qbyte;          //  Quad byte = 32 bits

// key stuff
#define PCP_KEY_HEADER "----- BEGIN PCP SECRET KEY -----"
#define PCP_KEY_FOOTER "------ END PCP SECRET KEY ------"

#define PCP_PUBKEY_HEADER "----- BEGIN PCP PUBLIC KEY -----"
#define PCP_PUBKEY_FOOTER "------ END PCP PUBLICKEY ------"

#define PCP_ENFILE_HEADER "----- BEGIN PCP ENCRYPTED FILE -----"
#define PCP_ENFILE_FOOTER "------ END PCP ENCRYPTED FILE ------"

#define PCP_ZFILE_HEADER "----- BEGIN Z85 ENCODED FILE -----"
#define PCP_ZFILE_FOOTER "------ END Z85 ENCODED FILE ------"

#define PCP_SIG_HEADER "----- BEGIN PCP SIGNED MESSAGE -----"
#define PCP_SIG_START  "----- BEGIN PCP SIGNATURE -----"
#define PCP_SIG_END    "------ END PCP SIGNATURE ------"

#define PCP_ME "Pretty Curved Privacy"

#define PCP_KEY_VERSION 5
#define PCP_KEY_PRIMITIVE "CURVE25519-ED25519-SALSA20-POLY1305"

#define PCP_KEY_TYPE_MAINSECRET 1
#define PCP_KEY_TYPE_SECRET     2
#define PCP_KEY_TYPE_PUBLIC     3

// how many times do we hash a passphrase
#define HCYCLES 128000

// save typing, dammit
#define PCP_ENCRYPT_PAD crypto_secretbox_ZEROBYTES + crypto_secretbox_NONCEBYTES

// vault id
#define PCP_VAULT_ID 14
#define PCP_VAULT_VERSION 2

// sigs
#define PCP_SIG_VERSION 2

// crypto file format stuff
#define PCP_ASYM_CIPHER         5
#define PCP_SYM_CIPHER          23
#define PCP_BLOCK_SIZE          32 * 1024
#define PCP_BLOCK_SIZE_IN       (PCP_BLOCK_SIZE) + 16 + crypto_secretbox_NONCEBYTES
#define PCP_CRYPTO_ADD          (crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES)
#define PCP_ASYM_RECIPIENT_SIZE crypto_secretbox_KEYBYTES + PCP_CRYPTO_ADD +  crypto_secretbox_NONCEBYTES
//#define PCP_ASYM_ADD_SENDER_PUB

// used for self encryption only
#define PBP_COMPAT_SALT "qa~t](84z<1t<1oz:ik.@IRNyhG=8q(on9}4#!/_h#a7wqK{Nt$T?W>,mt8NqYq&6U<GB1$,<$j>,rSYI2GRDd:Bcm"

// error handling
extern char *PCP_ERR;
extern byte PCP_ERRSET;
extern int PCP_EXIT;

//set error
void fatal(const char * fmt, ...);

// fetch error
void fatals_ifany();

// reset
void fatals_reset();

#endif // _DEFINES_H
