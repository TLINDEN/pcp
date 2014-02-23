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


/*  from https://github.com/tlinden/curve-keygen/ */
#ifndef _HAVE_PCP_Z85_H

/**
 * \defgroup Z85 Z85
 * @{

 Z85 Encoding functions.

The Z85 encoding format is described here: <a href="http://rfc.zeromq.org/spec:32">ZeroMQ Spec.32</a>.
It's part of <a href="http://zeromq.org">ZeroMQ</a>. Z85 is based on ASCII85 with
a couple of modifications (portability, readability etc).

To fulfil the requirements of the ZeroMQ Z85 functions, PCP
does some additional preparations of raw input before actually doing the 
encoding, since the input for zmq_z85_encode() must be divisible by 4. Therefore
we pad the input with zeroes and remove them after decoding.

 */
#include <ctype.h>
#include "defines.h"
#include "zmq_z85.h"
#include "mem.h"
#include "buffer.h"

/** Zero-pad some input data.

    This function allocates new memory for the returned data. It puts
    the original pointer into it and adds a number of zeros so that the
    result has a size divisable by 4.

    \param[in] src Unpadded data.
    \param[in] srclen Size of unpadded data.
    \param[in] dstlen Returned size of padded data (pointer to int).

    \return Returns a pointer to the padded data.
 */
unsigned char *pcp_padfour(unsigned char *src, size_t srclen, size_t *dstlen);


/** Unpad padded input data.

    It just calculates the size of the unpadded result (size - all trailing zeroes).
    Doesn't allocate any memory or modify anything.

    \param[in] src Padded data.
    \param[in] srclen Size of padded data.

    \return Returns the unpadded size of the data.
 */
size_t pcp_unpadfour(unsigned char *src, size_t srclen);

/** Decode data from Z85 encoding.

    The input \a z85block may contain newlines which will be removed.

    \param[in] z85block The Z85 encoded string.
    \param[in] dstlen Returned size of decoded data (pointer to int).

    \return Returns a newly allocated pointer to the decoded data. If decoding failed,
            returns NULL. Check fatals_if_any().

*/
unsigned char *pcp_z85_decode(char *z85block, size_t *dstlen);


/** Encode data to Z85 encoding.

    Beside Z85 encoding it also adds a newline everiy 72 characters.

    \param[in] raw Pointer to raw data.
    \param[in] srclen Size of the data.
    \param[in] dstlen Returned size of encoded data (pointer to int).

    \return Returns a string (char array) containing the Z85 encoded data.
*/
char *pcp_z85_encode(unsigned char *raw, size_t srclen, size_t *dstlen);

/** Read a Z85 encoded file.

    Reads a file and returns the raw Z85 encoded string.
    It ignores newlines, comments and Headerstrings.

    \param[in] infile FILE stream to read from.

    \return Raw Z85 encoded string with comments, headers and newlines removed.
 */
char *pcp_readz85file(FILE *infile);

/** Read a Z85 encoded string.

    Parses the given input string and returns the raw Z85 encoded string.
    It ignores newlines, comments and Headerstrings.

    \param[in] input Z85 encoded string.
    \param[in] bufsize Size of the string.

    \return Raw Z85 encoded string with comments, headers and newlines removed.

 */
char *pcp_readz85string(unsigned char *input, size_t bufsize);

/** Determine if a buffer is binary or ascii.

    \param[in] buf The buffer to check.
    \param[in] len Len of the buffer.
    \return Returns 0 if the input is ascii or a number > 0 if
            it contains binary data.
*/
size_t _buffer_is_binary(unsigned char *buf, size_t len);

#endif /*  _HAVE_PCP_Z85_H */

/**@}*/
