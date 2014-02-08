/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013-2014 T.v.Dein.

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

/*

  Flexible buffer management, idea from openssh/buffer.c.
  This allows us to dissect buffers into parts at will
  whithout the hassle of boundary checking in each and every
  line. Therefore it is more secure, since this system wraps
  all this stuff from us, so in case we're attemt to overflow
  a buffer or the like, the buffer functions will catch this,
  warn us and die.

*/

#ifndef HAVE_PCP_BUFFER_H
#define HAVE_PCP_BUFFER_H

#include "mem.h"
#include "util.h"
#include "defines.h"

struct _pcp_buffer {
  char *name;     /* just for convenience in error messages and the
                     like, so we know which buffer cause trouble */
  uint8_t allocated;
  size_t blocksize;
  size_t size;
  size_t offset;  /* read position */
  size_t end;     /* write position, data end */
  void *buf;
};

typedef struct _pcp_buffer Buffer;

/* create a new buffer */
Buffer *buffer_new(size_t blocksize, char *name);

/* zero the buffer and free it, if allocated */
void buffer_free(Buffer *b);

/* zero the buffer, always called from buffer_free() */
void buffer_clear(Buffer *b);

/* add data to the buffer, memorize end position */
void buffer_add(Buffer *b, const void *data, size_t len);

/* resize the buffer if necessary */
void buffer_resize(Buffer *b, size_t len);

/* get some chunk of data from the buffer, starting from offset til len,
   it doesn't allocate the returned data (void *buf, the 2nd argument).
*/
size_t buffer_get_chunk(Buffer *b, void *buf, size_t len);

/* return the whole buffer contents */
unsigned char *buffer_get(Buffer *b);

/* same as buffer_get() but fetch some data chunk from somewhere
   in the middle of the buffer */
size_t buffer_extract(Buffer *b, void *buf, size_t offset, size_t len);

/* dump the buffer contents to stderr */
void buffer_dump(const Buffer *b);

/* print buffer counters to stderr */
void buffer_info(const Buffer *b);

/* tell how much data there is in the buffer */
size_t buffer_size(const Buffer *b);

/* access the last byte(s) as numbers directly, save typing,
   in contrast to buffer_get() it doesn't increment offset */
uint8_t  buffer_last8(Buffer *b);
uint16_t buffer_last16(Buffer *b);
uint32_t buffer_last32(Buffer *b);
uint64_t buffer_last64(Buffer *b);

/* read from a file directly into a buffer object */
size_t buffer_fd_read(Buffer *b, FILE *in, size_t len);

/* write numbers as binary into the buffer */
void buffer_add8(Buffer *b, uint8_t v);
void buffer_add16(Buffer *b, uint16_t v);
void buffer_add32(Buffer *b, uint32_t v);
void buffer_add64(Buffer *b, uint64_t v);

/* the same, but convert to big-endian before doing so */
void buffer_add16be(Buffer *b, uint16_t v);
void buffer_add32be(Buffer *b, uint32_t v);
void buffer_add64be(Buffer *b, uint64_t v);


#endif // HAVE_PCP_BUFFER_H
