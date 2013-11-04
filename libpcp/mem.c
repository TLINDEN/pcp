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


#include "mem.h"
#include <stdio.h>


void *ucmalloc(size_t s) {
  size_t size = s * sizeof(unsigned char);
  void *value = malloc (size);

  if (value == NULL) {
    err(errno, "Cannot allocate memory");
    exit(-1);
  }

  memset (value, 0, size);

  //printf("allocated %d bytes at %p\n", (int)size, value);

  return value;
}

void *urmalloc(size_t s) {
  void *value = ucmalloc (s);

  arc4random_buf(value, s);

  return value;
}


void *ucfree(void *ptr) {
  free(ptr);
  ptr = NULL;
}
