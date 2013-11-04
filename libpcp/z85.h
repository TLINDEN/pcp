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


// from https://github.com/tlinden/curve-keygen/
#ifndef _HAVE_PCP_Z85_H

#include "defines.h"
#include "zmq_z85.h"
#include "mem.h"

// convert a binary stream to one which gets accepted by zmq_z85_encode
// we pad it with zeroes and put the number of zerores in front of it 
unsigned char *pcp_unpadfour(unsigned char *src, size_t srclen, size_t *dstlen);

// the reverse of the above
unsigned char *pcp_unpadfour(unsigned char *src, size_t srclen, size_t *dstlen);

// wrapper around zmq Z85 encoding function
unsigned char *pcp_z85_decode(char *z85block, size_t *dstlen);

// the reverse of the above
char *pcp_z85_encode(unsigned char *raw, size_t srclen, size_t *dstlen);

char *pcp_readz85file(FILE *infile);

#endif // _HAVE_PCP_Z85_H
