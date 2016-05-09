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

    You can contact me by mail: <tlinden AT cpan DOT org>.
*/


#include "mem.h"
#include <stdio.h>


void *ucmalloc(size_t s) {
  if (s == 0)
    return NULL;

  size_t size = s * sizeof(byte);
  void *value = malloc (size);

  if (value == NULL) {
    err(errno, "Cannot allocate %d bytes of memory", (int)s);
    exit(-1);
  }

  sodium_memzero(value, size);

  /* printf("allocated %ld bytes at %p\n", size, value); */

  return value;
}

void *smalloc(size_t s) {
  if (s == 0)
    return NULL;

  size_t size = s * sizeof(byte);
  void *value = sodium_malloc (size);

  if (value == NULL) {
    err(errno, "Cannot allocate %d bytes of memory", (int)s);
    exit(-1);
  }

  return value;
}

void *urmalloc(size_t s) {
  void *value = ucmalloc (s);

  arc4random_buf(value, s);

  return value;
}

void *srmalloc(size_t s) {
  void *value = sodium_malloc (s);

  arc4random_buf(value, s);

  return value;
}


void *ucrealloc(void *d, size_t oldlen, size_t newlen) {
  newlen = newlen * sizeof(byte);

  /* we're using a 1 byte sized pointer, so that we can
     memset(zero) it after resizing */
  byte *value = realloc (d, newlen);

  if (value == NULL) {
    err(errno, "Cannot reallocate %"FMT_SIZE_T" bytes of memory", (SIZE_T_CAST)newlen);
    exit(-1);
  }

  memset (&value[oldlen], 0, newlen-oldlen);

  return (void *)value;
}

void ucfree(void *d, size_t len) {
  if(d != NULL) {
    memset(d, 0, len);
    free(d);
  }
}

void sfree(void *d) {
  sodium_free(d);
}
