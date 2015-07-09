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

#include "util.h"

/* lowercase a string */
char *_lc(char *in) {
  size_t len = strlen(in);
  size_t i;
  for(i=0; i<len; ++i)
    in[i] = towlower(in[i]);
  return in;
}

/* find the offset of the beginning of a certain string within binary data */
long int _findoffset(byte *bin, size_t binlen, char *sigstart, size_t hlen) {
  size_t i;
  long int offset = 0;
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

/* xor 2 likesized buffers */
void _xorbuf(byte *iv, byte *buf, size_t xlen) {
  size_t i;
  for (i = 0; i < xlen; ++i)
   buf[i] = iv[i] ^ buf[i];
}

/* print some binary data to stderr */
void _dump(char *n, byte *d, size_t s) {
  int l = strlen(n) + 9;
  fprintf(stderr, "%s (%04"FMT_SIZE_T"): ", n, (SIZE_T_CAST)s);
  size_t i;
  int c;
  for (i=0; i<s; ++i) {
    fprintf(stderr, "%02x", d[i]);
    if(i % 36 == 35 && i > 0) {
      fprintf(stderr, "\n");
      for(c=0; c<l; ++c)
	fprintf(stderr, " ");
    }
  }
  fprintf(stderr, "\n");
}

char *_bin2hex(byte *bin, size_t len) {
  char *out = malloc((len*2) + 1);
  size_t i;
  for(i=0; i<len; ++i)
    sprintf(&out[i*2], "%02x", bin[i]);
  out[len*2] = '\0';
  return out;
}

/* via stackoverflow. yes, lazy */
size_t _hex2bin(const char *hex_str, unsigned char *byte_array, size_t byte_array_max) {
    size_t hex_str_len = strlen(hex_str);
    size_t i = 0, j = 0;

    // The output array size is half the hex_str length (rounded up)
    size_t byte_array_size = (hex_str_len+1)/2;

    if (byte_array_size > byte_array_max)
    {
        // Too big for the output array
        return 0;
    }

    if (hex_str_len % 2 == 1)
    {
        // hex_str is an odd length, so assume an implicit "0" prefix
        if (sscanf(&(hex_str[0]), "%1hhx", &(byte_array[0])) != 1)
        {
            return 0;
        }

        i = j = 1;
    }

    for (; i < hex_str_len; i+=2, j++)
    {
        if (sscanf(&(hex_str[i]), "%2hhx", &(byte_array[j])) != 1)
        {
            return 0;
        }
    }

    return byte_array_size;
}
