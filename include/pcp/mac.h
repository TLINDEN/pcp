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


#ifndef _HAVE_PCP_MAC
#define _HAVE_PCP_MAC

/**
 * \addtogroup CRYPTO
 * @{
 */
#include <strings.h>
#include <stdlib.h>
#include <errno.h>
#include <sodium.h>
#include "pad.h"
#include "mem.h"


/*  how many times do we hash the passphrase */
#define HCYCLES 128000

/** Symmetrically encrypt a message.

    This function encrypts a message symmetrically
    using crypto_secretbox() using the given Curve25519 raw
    secret key and the nonce.

    It allocates apropriate memory for the result,
    which will be stored in \a cipher.

    \param[out] cipher Encrypted result.
    \param[in] cleartext Clear message.
    \param[in] clearsize Size of message.
    \param[in] nonce A random nonce (24 Bytes).
    \param[in] key A Curve25519 key (32 Bytes).

    \return Returns the size of \a cipher.
 */
size_t pcp_sodium_mac(unsigned char **cipher,
                      unsigned char *cleartext,
                      size_t clearsize,
                      unsigned char *nonce,
                      unsigned char *key);

/** Decrypt a symmetrically encrypted message.

    This function decrypts a symmetrically encrypted message
    using crypto_secretbox_open() using the given Curve25519 raw
    secret key and the nonce.

    It allocates apropriate memory for the result,
    which will be stored in \a cleartext.

    \param[out] cleartext The decrypted result.
    \param[in] message The encrypted message.
    \param[in] messagesize Size of message.
    \param[in] nonce A random nonce (24 Bytes).
    \param[in] key A Curve25519 key (32 Bytes).

    \return Returns 0 in case of success of -1 in case of an error. Check fatals_if_any().

 */
int pcp_sodium_verify_mac(unsigned char **cleartext,
                          unsigned char* message,
                          size_t messagesize,
                          unsigned char *nonce,
                          unsigned char *key);




#endif /*  _HAVE_PCP_MAC */

/**@}*/
