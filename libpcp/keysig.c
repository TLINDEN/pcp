/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013-2016 T.v.Dein.

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


#include "keysig.h"

void pcp_keysig2blob(Buffer *b, pcp_keysig_t *s) {
  buffer_add8(b, s->type);
  buffer_add32be(b, s->size);
  buffer_add(b, s->id, 17);
  buffer_add(b, s->checksum, LSHA);
  buffer_add(b, s->blob, s->size);
}

Buffer *pcp_keysigblob(pcp_keysig_t *s) {
  Buffer *b = buffer_new(256, "keysig2blob");
  pcp_keysig2blob(b, s);
  return b;
}

pcp_keysig_t *pcp_blob2keysig(Buffer *blob) {
  pcp_keysig_t *sk = ucmalloc(sizeof(pcp_keysig_t));

  uint8_t type = buffer_get8(blob);
  uint32_t size = buffer_get32na(blob);
  
  buffer_get_chunk(blob, sk->id, 17);

  byte *checksum = ucmalloc(LSHA);
  buffer_get_chunk(blob, checksum, LSHA);
  
  sk->blob = ucmalloc(size);
  buffer_get_chunk(blob, sk->blob, size);

  sk->size = size;
  sk->type = type;
  memcpy(sk->checksum, checksum, LSHA);

  ucfree(checksum, LSHA);

  return sk;
}

void pcp_dumpkeysig(pcp_keysig_t *s) {
  int i;

  printf("Dumping pcp_sigkey_t raw values:\n");

  printf("     type: 0x%02X\n", s->type);
  printf("     size: %ld\n", (long int)s->size);

  printf(" checksum: ");
  for ( i = 0;i < LSHA;++i) printf("%02x",(unsigned int) s->checksum[i]);
  printf("\n");

  _dump("     blob:", s->blob, s->size);
}
