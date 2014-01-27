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


// various helpers

#ifndef _HAVE_PCP_UTIL_H
#define _HAVE_PCP_UTIL_H

#include <ctype.h>
#include <wctype.h>

// lowercase a string
static inline char *_lc(char *in) {
  size_t len = strlen(in);
  size_t i;
  for(i=0; i<len; ++i)
    in[i] = towlower(in[i]);
  return in;
}

// find the offset of the beginning of a certain string within binary data
static inline size_t _findoffset(unsigned char *bin, size_t binlen, char *sigstart, size_t hlen) {
  size_t i;
  size_t offset = 0;
  int m = 0;

  for(i=0; i<binlen-hlen; ++i) {
    if(memcmp(&bin[i], sigstart, hlen) == 0) {
      offset = i;
      m = 1;
      break;
    }
  }

  if(m == 0)
    offset = -1;


  return offset;
}

#endif // _HAVE_PCP_UTIL_H
