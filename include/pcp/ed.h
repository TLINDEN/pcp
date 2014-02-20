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

#ifndef _HAVE_PCP_ED_H
#define _HAVE_PCP_ED_H

/** \defgroup ED SIGNING
    @{

    ED25519 signature functions.

*/

#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "defines.h"
#include "platform.h"
#include "mem.h"
#include "key.h"
#include "keyhash.h"
#include "util.h"
#include "pcpstream.h"

/** Sign a raw message.

    Sign a message of messagesize using s->edsecret.
    This is just a convenience wrapper around crypto_sign().

    \param[in] message The message to sign.

    \param[in] messagesize Size of the message.

    \param[in] s Pointer to secret key structure.

    \return Returns message+signature with size of messagesize + crypto_sign_BYTES,
            or NULL in case of an error.
*/
unsigned char *pcp_ed_sign(unsigned char *message, size_t messagesize, pcp_key_t *s);

/** Sign a raw message using s->mastersecret.

    The same as pcp_ed_sign() but uses the mastersecret for signing.
    Usually used for key signing only.

    \param[in] message The message to sign.

    \param[in] messagesize Size of the message.

    \param[in] s Pointer to secret key structure.

    \return Returns message+signature with size of messagesize + crypto_sign_BYTES,
            or NULL in case of an error.

*/unsigned char *pcp_ed_sign_key(unsigned char *message, size_t messagesize, pcp_key_t *s);

/** Verify a signature.

    Verify a signature of size siglen using p->edpub.

    The signature must contain the message+nacl signature (with size crypto_sign_BYTES).

    \param[in] signature Message+signature.

    \param[in] siglen Size of message+signature.

    \param[in] p Pointer to public key structure.

    \return If the signature verifies return the raw message with the signature removed (size: siglen - crypto_sign_BYTES),
    returns NULL in case of errors. Check fatals_if_any().
*/
unsigned char *pcp_ed_verify(unsigned char *signature, size_t siglen, pcp_pubkey_t *p);

/**  Verify a signature using the mastersecret.

    Verify a signature of size siglen using p->masterpub.

    The signature must contain the message+nacl signature (with size crypto_sign_BYTES).

    \param[in] signature Message+signature.

    \param[in] siglen Size of message+signature.

    \param[in] p Pointer to public key structure.

    \return If the signature verifies return the raw message with the signature removed (size: siglen - crypto_sign_BYTES),
    returns NULL in case of errors. Check fatals_if_any().
*/
unsigned char *pcp_ed_verify_key(unsigned char *signature, size_t siglen, pcp_pubkey_t *p);

/** Sign a stream in 32k block mode.

    This function reads blockwise from the stream \a in and generates a hash
    of the contents of the stream. It outputs the stream to \a out, also blockwise
    and appends the signature afterwards, which consists of the hash+nacl-signature.

    \param[in] in Stream to read from.

    \param[out] out Stream to write to.

    \param[in] s Pointer to secret key.

    \param[in] z85 Flag which indicates if to create an armored signature or not. 1=armored, 0=raw.

    \return Returns the number of bytes written to the output stream.

*/
size_t pcp_ed_sign_buffered(Pcpstream *in, Pcpstream *out, pcp_key_t *s, int z85);


/** Verify a signature from a stream in 32k block mode.

    This function reads blockwise from the stream \a in and generates a hash
    of the contents of the stream. While reading from the stream it extracts
    the appended signature (hash+sig). It then verifies the signature using
    p->edpub and compares the signature hash with the hash it calculated
    from the signed content.

    The parameter \a p can be NULL. In this case the function loops through
    the global public key hash pcppubkey_hash to find a public key which is able to verify
    the signature.

    \param[in] in Stream to read from.

    \param[in] p Pointer to public key structure.

    \return Returns a pointer to a public key which were used to verify the signature or NULL if
            an error occurred. Check fatals_if_any().
*/
pcp_pubkey_t *pcp_ed_verify_buffered(Pcpstream *in, pcp_pubkey_t *p);

/** Generate a detached signature from a stream in 32k block mode.

    This function reads blockwise from the stream \a in and generates a hash
    of the contents of the stream. It then signs that hash and writes the
    hash and the signature to the output stream \a out.

    \param[in] in Stream to read from.

    \param[out] out Stream to write to.

    \param[in] s Pointer to secret key.

    \return Returns the size of the detached signature written or 0 in case of errors. Check fatals_if_any().
   
 */
size_t pcp_ed_detachsign_buffered(Pcpstream *in, Pcpstream *out, pcp_key_t *s);

/** Verify a detached signature from a stream in 32k block mode.

    This function reads blockwise from the stream \a in and generates a hash
    of the contents of the stream. It then reads the signature from the stream
    \a sigfd and verifies the signature from it using p->edpub and compares
    the signature hash with the hash it calculated
    from the signed content.

    \param[in] in Stream to read from.

    \param[in] sigfd Stream containing the detached signature.

    \param[in] p Pointer to public key structure.

    \return Returns a pointer to a public key which were used to verify the signature or NULL if
            an error occurred. Check fatals_if_any().

 */
pcp_pubkey_t *pcp_ed_detachverify_buffered(Pcpstream *in, Pcpstream *sigfd, pcp_pubkey_t *p);

#endif /*  _HAVE_PCP_ED_H */

/**@}*/
