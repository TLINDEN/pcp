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


#include "pad.h"

void pcp_pad_prepend(byte **padded, byte *unpadded,
		 size_t padlen, size_t unpadlen) {
  *padded = ucmalloc(unpadlen + padlen);
  byte *tmp = ucmalloc(unpadlen + padlen);

  /*  pcp_append orig */
  int i;
  for(i=0; i<unpadlen; ++i) {
    tmp[i + padlen] = unpadded[i];
  }

  memcpy(*padded, tmp, unpadlen + padlen);
  free(tmp);
}

void pcp_pad_remove(byte **unpadded, byte *padded,
		size_t padlen, size_t unpadlen) {
  *unpadded = ucmalloc(unpadlen * sizeof(byte));
  byte *tmp = ucmalloc(unpadlen);

  int i;
  for(i=0; i<unpadlen; ++i) {
    tmp[i] = padded[padlen + i];
  }
  
  memcpy(*unpadded, tmp, unpadlen);
  free(tmp);
}

#ifdef _MK_ZPAD_MAIN
int main(int argc, char **argv) {
  if(argc >= 2) {
    size_t unpadlen;
    int padlen = strtol(argv[2], NULL, 0);
    unpadlen = strlen(argv[1]);
    byte *dst;
    
    pcp_pad_prepend(&dst, argv[1], padlen, unpadlen);
    /* printf("   prev: %s\n  after: %s\n", argv[1], dst); */
    
    byte *reverse;
    pcp_pad_remove(&reverse, dst, padlen, unpadlen);
    /* printf("reverse: %s\n", reverse); */
    
    return 0;
  }
  /* fprintf(stderr, "Usage: pad <string> <padlen>\n"); */
  return -1;
}
#endif

