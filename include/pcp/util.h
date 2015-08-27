/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013 T. von Dein.

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


/*  various helpers, too small to put into own c */

#ifndef _HAVE_PCP_UTIL_H
#define _HAVE_PCP_UTIL_H

/** \defgroup UTILs UTILS
    @{

    Various useful helper functions.
*/

#include <ctype.h>
#include <wctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "platform.h"
#include "defines.h"


/** Convert a char array to lowercase.

    The supplied char array will be directly modified. Use
    a copy if you want to retain the original.

    \param[in,out] in The char array to convert.

    \return Returns the pointer to the char array.

 */
char *_lc(char *in);

/** Find the offset of some offset marker in some arbitrary data.

    Sample input:
    @code
    ABABABABnacl-98a7sd98a7das98d7
    @endcode

    If you look for the offset of "nacl" within that data, the
    function will return 9, which is the position within the data
    where the marker starts.

    \param[in] bin Aribrary data where to look for the marker.

    \param[in] binlen The size of the data.

    \param[in] sigstart The offset marker.

    \param[in] hlen Size of the offset marker.

    \return Returns the offset or -1 of the offset were not found.

 */
long int _findoffset(byte *bin, size_t binlen, char *sigstart, size_t hlen);

/** XOR an input buffer with another buffer.

    Both buffers have to have the same size. The input
    buffer will bei modified directly.

    \param[in] iv The buffer to XOR with.

    \param[in,out] buf The buffer which will be XORed with 'iv'.

    \param[in] xlen The size of the buffers (they must have the same size).
 */
void _xorbuf(byte *iv, byte *buf, size_t xlen);

/** Dump binary data as hex to stderr.

    \param[in] n Description, string.

    \param[in] d Data to print.

    \param[in] s Size of d.
 */
void _dump(char *n, byte *d, size_t s);


/** return hex string of binary data
    \param[in] bin byte array
    \param[in] len size of byte array
    \return Returns malloc'd hex string. Caller must free.
*/
char *_bin2hex(byte *bin, size_t len);

/** convert hex string to binary date
    \param[in] hex_str hex string
    \param[out] byte_array output buffer (malloc'd to byte_array_max)
    \param[in] byte_array_max max size allowed for output buffer
    \return Returns size of output buffer
*/
size_t _hex2bin(const char *hex_str, unsigned char *byte_array, size_t byte_array_max);

/** compare two memory regions in a constant time
    \param[in] m1 array1
    \param[in] m2 array2
    \param[in] n size in bytes to compare
    \return 0 if m1 and m2 are equal up to n
 */
int cst_time_memcmp(const void *m1, const void *m2, size_t n);

#endif /*  _HAVE_PCP_UTIL_H */

/**@}*/
