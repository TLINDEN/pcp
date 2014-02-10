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
  if (s == 0)
    return NULL;

  size_t size = s * sizeof(unsigned char);
  void *value = malloc (size);

  if (value == NULL) {
    err(errno, "Cannot allocate %d bytes of memory", (int)s);
    exit(-1);
  }

  memset (value, 0, size);

  /* printf("allocated %d bytes at %p\n", (int)size, value); */

  return value;
}

void *urmalloc(size_t s) {
  void *value = ucmalloc (s);

  arc4random_buf(value, s);

  return value;
}


void *ucrealloc(void *d, size_t oldlen, size_t newlen) {
  newlen = newlen * sizeof(unsigned char);
  void *value = realloc (d, newlen);

  if (value == NULL) {
    err(errno, "Cannot reallocate %ld bytes of memory", newlen);
    exit(-1);
  }

  memset (&value[oldlen], 0, newlen-oldlen);

  return value;
}

void ucfree(void *d, size_t len) {
  if(d != NULL) {
    memset(d, 0, len);
    free(d);
  }
}
