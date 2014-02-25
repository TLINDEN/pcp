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


#ifndef _HAVE_PCP_CRYPTO_H
#define _HAVE_PCP_CRYPTO_H

#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <sodium.h>
#include <stdlib.h>

#include "defines.h"
#include "mem.h"
#include "key.h"
#include "keyhash.h"
#include "ed.h"
#include "pcpstream.h"

/**
   \defgroup CRYPTO CRYPTO
   @{

   Functions for symmetrical or asymmetrical encryption using NaCL.

   \section intro Introduction

   Encryption is done 32k blockwise using an ephemeral key.

   If using asymmetrical encryption the ephemeral key is encrypted
   asymmetrically using Curve25519 for all recipients and added to
   the output.

   If sign+crypt is requested, a hash of the clear content plus
   the recipient list will be made and signed. That signature
   will be encrypted using the ephemeral key as well and appended
   to the output.

   For each encryption cycle (per block) a unique nonce will be
   used.

   \section format Encrypted Output Format

   Encrypted output will always written as binary files. No armoring
   supported yet. The encryption process works as this:

   - generate a random symetric 32 byte key B<S>
   - encrypt it asymetrically for each recipient using a unique nonce (B<R>)
   - encrypt the input file 32k blockwise using the symetric key

   Symmetric encryption works the very same with the recipient stuff
   left out.

   Formal format description, asymmetric encrypted files:

            +---------------------------------------------------------+
            | Field         Size      Description                     |
            +-------------+--------+----------------------------------+
            | Type        |      1 | Filetype, 5=ASYM, 23=SYM         |
            +-------------|--------|----------------------------------+
            | Len R       |      4 | Number of recipients         (*) |
            +-------------|--------|----------------------------------+
            | Recipients  |   R*72 | C(recipient)|C(recipient)... (*) |
            +-------------|--------|----------------------------------+
            | Encrypted   |      ~ | The actual encrypted data        |
            +-------------|--------|----------------------------------+

    The following will be Left out when doing symetric encryption.
    
    Recipient field format:

            +---------------------------------------------------------+
            | Field         Size      Description                     |
            +-------------+--------+----------------------------------+
            | Nonce       |     24 | Random Nonce, one per R          |
            +-------------|--------|----------------------------------+
            | Cipher      |     48 | S encrypted with PK or R         |
            +-------------|--------|----------------------------------+

   R is calculated using public key encryption using the senders
   secret key, the recipients public key and a random nonce.

   Pseudocode:

   @code
   R = foreach P: N | crypto_box(S, N, P, SK)
   L = len(R)
   T = 5
   write (T | L | R)
   foreach I: write (N | crypto_secret_box(I, N, S))
   @endcode

   where P is the public key of a recipient, SK is the senders
   secret key, R is the recipient list, L is the number of recipients,
   T is the filetype header, I is a block of input with a size
   of 32k, N is a nonce (new per block) and S the symmetric key.
*/

size_t pcp_sodium_box(byte **cipher,
                      byte *cleartext,
                      size_t clearsize,
                      byte *nonce,
                      byte *secret,
                      byte *pub);

int pcp_sodium_verify_box(byte **cleartext, byte* message,
                          size_t messagesize, byte *nonce,
                          byte *secret, byte *pub);

/** Asymmetrically encrypt a message.

    This function is used internally and normally a user doesn't
    need to use it. However, from time to time there maybe the
    requirement to work with raw NaCL crypto_box() output. This
    function adds the neccessary padding and it uses PCP key structures.

    \param[in] secret The secret key structure from the sender.

    \param[in] pub The public key structure from the recipient.

    \param[in] message The clear unencrypted message.

    \param[in] messagesize The size in bytes of the message.

    \param[out] csize A pointer which will be set to the size of the encrypted result if successful.

    \return Returns an allocated byte array of the size csize which contains the encrypted result.
            In case of an error, it returns NULL sets csize to 0. Use fatals_ifany() to check for errors.
*/
byte *pcp_box_encrypt(pcp_key_t *secret, pcp_pubkey_t *pub,
                               byte *message, size_t messagesize,
			       size_t *csize);

/** Asymmetrically decrypt a message.

    This function is used internally and normally a user doesn't
    need to use it. However, from time to time there maybe the
    requirement to work with raw NaCL crypto_box() output. This
    function adds the neccessary padding and it uses PCP key structures.

    \param[in] secret The secret key structure from the sender.

    \param[in] pub The public key structure from the recipient.

    \param[in] cipher The encrypted message.

    \param[in] ciphersize The size in bytes of the encrypted message.

    \param[out] dsize A pointer which will be set to the size of the decrypted result if successful.

    \return Returns an allocated byte array of the size csize which contains the encrypted result.
            In case of an error, it returns NULL sets csize to 0. Use fatals_ifany() to check for errors.
*/
byte *pcp_box_decrypt(pcp_key_t *secret, pcp_pubkey_t *pub,
                               byte *cipher, size_t ciphersize,
			       size_t *dsize);


/** Asymmetrically encrypt a file or a buffer stream.

    This function encrypts a stream 32k-blockwise for
    a number of recipients.

    Calls pcp_encrypt_stream_sym() after assembling the encrypted recipient list.

    \param[in] in Stream to read the data to encrypt from.

    \param[out] out Stream to write encrypted result to.

    \param[in] s Secret key structure of the sender.

    \param[in] p Public key hash containing a list of the recipients.

    \param signcrypt Flag to indicate sign+crypt. If 1 it adds a signature, otherwise not.

    \return Returns the size of the output written to the output stream or 0 in case of errors.
*/
size_t pcp_encrypt_stream(Pcpstream *in, Pcpstream* out, pcp_key_t *s, pcp_pubkey_t *p, int signcrypt);

/** Symmetrically encrypt a file or a buffer stream.

    This function encrypts a stream 32k-blockwise using
    a given ephemeral key. Usually compute this key using the pcp_scrypt()
    function.

    Uses crypto_secret_box() for each 32k-block with a random nonce for each.

    \param[in] in Stream to read the data to encrypt from.

    \param[out] out Stream to write encrypted result to.

    \param[in] symkey Ephemeral key to use for encryption.

    \param[in] havehead Flag to indicate if the file header has already been written.
    Set to 0 if you call this function directly in order to do symmetrical encryption.

    \param recsign Recipient list, set this to NULL if you call this function directly.

    \return Returns the size of the output written to the output stream or 0 in case of errors.
*/
size_t pcp_encrypt_stream_sym(Pcpstream *in, Pcpstream* out, byte *symkey, int havehead, pcp_rec_t *recsign);


/** Asymmetrically decrypt a file or a buffer stream.

    This function decrypts a stream 32k+16-blockwise for
    a number of recipients.

    Calls pcp_decrypt_stream_sym() after assembling the encrypted recipient list.

    FIXME: should return the pcp_rec_t structure upon successfull verification somehow.

    \param[in] in Stream to read the data to decrypt from.

    \param[out] out Stream to write decrypted result to.

    \param[in] s Secret key structure of the recipient.

    \param[in] symkey Ephemeral key for symmetric decryption. Set to NULL if you call this function directly.

    \param verify Flag to indicate sign+crypt. If 1 it tries to verify a signature, otherwise not.

    \return Returns the size of the output written to the output stream or 0 in case of errors.
*/
size_t pcp_decrypt_stream(Pcpstream *in, Pcpstream* out, pcp_key_t *s, byte *symkey, int verify);


/** Symmetrically decrypt a file or a buffer stream.

    This function decrypts a stream 32k+16-blockwise using
    a given ephemeral key. Usually compute this key using the pcp_scrypt()
    function. If not called directly, the key have been extracted from
    the recipient list.

    Uses crypto_secret_box_open() for each 32k+16-block with a random nonce for each.

    \param[in] in Stream to read the data to decrypt from.

    \param[out] out Stream to write decrypted result to.

    \param[in] symkey Ephemeral key to use for decryption.

    \param recverify Flag to indicate sign+crypt. If 1 it tries to verify a signature, otherwise not.

    \return Returns the size of the output written to the output stream or 0 in case of errors.
*/
size_t pcp_decrypt_stream_sym(Pcpstream *in, Pcpstream* out, byte *symkey, pcp_rec_t *recverify);

pcp_rec_t *pcp_rec_new(byte *cipher, size_t clen, pcp_key_t *secret, pcp_pubkey_t *pub);
void pcp_rec_free(pcp_rec_t *r);

#endif /*  _HAVE_PCP_CRYPTO_H */

/**@}*/
