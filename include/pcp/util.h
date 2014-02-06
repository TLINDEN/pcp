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

#include <ctype.h>
#include <wctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *_lc(char *in);
size_t _findoffset(unsigned char *bin, size_t binlen, char *sigstart, size_t hlen);
void _xorbuf(unsigned char *iv, unsigned char *buf, size_t xlen);
void _dump(char *n, unsigned char *d, size_t s);

#endif /*  _HAVE_PCP_UTIL_H */
