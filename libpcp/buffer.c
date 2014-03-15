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

#define _GNU_SOURCE /* vasprintf() linux */

#include "buffer.h"

void buffer_init(Buffer *b, size_t blocksize, char *name) {
  b->name = ucmalloc(strlen(name)+1);
  b->size = blocksize;
  b->allocated = 1;
  b->isstring = 0;
  b->offset = 0;
  b->end = 0;
  b->blocksize = blocksize;
  memcpy(b->name, name, strlen(name)+1);
}

Buffer *buffer_new(size_t blocksize, char *name) {
  Buffer *b = ucmalloc(sizeof(Buffer));
  b->buf = ucmalloc(blocksize);
  buffer_init(b, blocksize, name);
  return b;
}

Buffer *buffer_new_str(char *name) {
  Buffer *b = buffer_new(256, name);
  b->isstring = 1;
  return b;
}

Buffer *buffer_new_buf(char *name, void *data, size_t datasize) {
  Buffer *b = buffer_new(256, name);
  b->allocated = 0;
  b->buf = data;
  b->size = datasize;
  b->end = datasize;
  return b;
}

void buffer_free(Buffer *b) {
  if(b != NULL) {
    if(b->allocated == 1) {
      /* free the underlying data pointer only if we allocated it */
      if(b->end > 0) {
	buffer_clear(b);
      }
      free(b->buf);
      b->allocated = 0;
    }
    free(b);
  }
}

void buffer_clear(Buffer *b) {
  b->offset = 0;
  b->end = 0;
  memset(b->buf, 0, b->size);
}

void buffer_rewind(Buffer *b) {
  b->offset = 0;
}

void buffer_add(Buffer *b, const void *data, size_t len) {
  buffer_resize(b, len);
  memcpy(b->buf + b->end, data, len);
  b->end += len;
}

void buffer_add_str(Buffer *b, const char * fmt, ...) {
  va_list ap;
  char *dst;
  va_start(ap, fmt);
  if(vasprintf(&dst, fmt, ap) >= 0) {
    if(b->end > 0)
      b->end--;
    buffer_add(b, dst, strlen(dst)+1);
  }
  va_end(ap);
  free(dst);
}

void buffer_add_hex(Buffer *b, void *data, size_t len) {
  size_t i;
  byte *d = data;
  for(i=0; i<len; ++i) {
    buffer_add_str(b, "%02x", d[i]);
  }
}

void buffer_add_buf(Buffer *dst, Buffer *src) {
  buffer_add(dst, buffer_get(src), buffer_size(src));
}

void buffer_resize(Buffer *b, size_t len) {
  if((b->end > 0 && b->end + len > b->size) || (b->end == 0 && len > b->size) ) {
    /* increase by buf blocksize */
    size_t newsize = (((len / b->blocksize) +1) * b->blocksize) + b->size;
    b->buf = ucrealloc(b->buf, b->size, newsize);
    b->size = newsize;
  }
}

byte *buffer_get(Buffer *b) {
  if(b->end > 0)
    return b->buf;
  else
    return NULL;
}

size_t buffer_get_chunk(Buffer *b, void *buf, size_t len) {
  if(len > b->end - b->offset) {
    fatal("[buffer %s] attempt to read %ld bytes data from buffer with %ld bytes left at offset %ld\n",
	  b->name, len, b->end - b->offset, b->offset);
    return 0;
  }
  else if(len == 0) {
    /* FIXME: check how this happens */
    return 0;
  }

  memcpy(buf, b->buf + b->offset, len);

  b->offset += len;
  return len;
}

size_t buffer_get_chunk_tobuf(Buffer *b, Buffer *dst, size_t len) {
  if(len > b->end - b->offset) {
    fatal("[buffer %s] attempt to read %ld bytes data from buffer with %ld bytes left at offset %ld\n",
	  b->name, len, b->end - b->offset, b->offset);
    return 0;
  }
  else if(len == 0) {
    /* FIXME: check how this happens */
    return 0;
  }

  buffer_resize(dst, len);
  memcpy(dst->buf+buffer_size(dst), b->buf + b->offset, len);
  b->offset += len;
  dst->end += len;
  return len;
}

byte *buffer_get_remainder(Buffer *b) {
  void *buf = ucmalloc(b->end - b->offset);
  if(buffer_get_chunk(b, buf, b->end - b->offset) == 0) {
    free(buf);
    return NULL;
  }
  else {
    return buf;
  }
}

uint8_t buffer_get8(Buffer *b) {
  uint8_t i;
  if(buffer_get_chunk(b, &i, 1) > 0) {
    return i;
  }
  else
    return 0;
}

uint16_t buffer_get16(Buffer *b) {
  uint16_t i;
  if(buffer_get_chunk(b, &i, 2) > 0) {
    return i;
  }
  else
    return 0;
}

uint32_t buffer_get32(Buffer *b) {
  uint32_t i;
  if(buffer_get_chunk(b, &i, 4) > 0) {
    return i;
  }
  else
    return 0;
}

uint64_t buffer_get64(Buffer *b) {
  uint64_t i;
  if(buffer_get_chunk(b, &i, 8) > 0) {
    return i;
  }
  else
    return 0;
}

uint16_t buffer_get16na(Buffer *b) {
  uint16_t i;
  if(buffer_get_chunk(b, &i, 2) > 0) {
    i = be16toh(i);
    return i;
  }
  else
    return 0;
}

uint32_t buffer_get32na(Buffer *b) {
  uint32_t i;
  if(buffer_get_chunk(b, &i, 4) > 0) {
    i = be32toh(i);
    return i;
  }
  else
    return 0;
}

uint64_t buffer_get64na(Buffer *b) {
  uint64_t i;
  if(buffer_get_chunk(b, &i, 8) > 0) {
    i = be64toh(i);
    return i;
  }
  else
    return 0;
}

char *buffer_get_str(Buffer *b) {
  buffer_resize(b, 1); /* make room for trailing zero */
  return (char *)b->buf;
}

size_t buffer_extract(Buffer *b, void *buf, size_t offset, size_t len) {
  if(len > b->end) {
    fatal("[buffer %s] attempt to read %ld bytes past end of buffer at %ld\n", b->name, b->end - (b->offset + len), b->end);
    return 0;
  }

  if(offset > b->end) {
    fatal("[buffer %s] attempt to read at offset %ld past len to read %ld\n", b->name, offset, b->end);
    return 0;
  }

  memcpy(buf, b->buf + offset, len);
  return len - offset;
}

void buffer_dump(const Buffer *b) {
  _dump(b->name, b->buf, b->size);
}

void buffer_info(const Buffer *b) {
  fprintf(stderr, "   buffer: %s\n", b->name);
  fprintf(stderr, "blocksize: %"FMT_SIZE_T"\n", (SIZE_T_CAST)b->blocksize);
  fprintf(stderr, "     size: %"FMT_SIZE_T"\n", (SIZE_T_CAST)b->size);
  fprintf(stderr, "   offset: %"FMT_SIZE_T"\n", (SIZE_T_CAST)b->offset);
  fprintf(stderr, "      end: %"FMT_SIZE_T"\n", (SIZE_T_CAST)b->end);
  fprintf(stderr, "allocated: %d\n\n", b->allocated);
}

size_t buffer_size(const Buffer *b) {
  return b->end;
}

size_t buffer_left(const Buffer *b) {
  return b->end - b->offset;
}

int buffer_done(Buffer *b) {
  if(b->offset == b->end)
    return 1;
  else
    return 0;
}

uint8_t buffer_last8(Buffer *b) {
  uint8_t i;
  if(buffer_extract(b, &i, b->end - 1, 1) > 0)
    return i;
  else
    return 0;
}

uint16_t buffer_last16(Buffer *b) {
  uint16_t i;
  if(buffer_extract(b, &i, b->end - 2, 2) > 0)
    return i;
  else
    return 0;
}

uint32_t buffer_last32(Buffer *b) {
  uint32_t i;
  if(buffer_extract(b, &i, b->end - 4, 4) > 0)
    return i;
  else
    return 0;
}

uint64_t buffer_last64(Buffer *b) {
  uint64_t i;
  if(buffer_extract(b, &i, b->end - 8, 8) > 0)
    return i;
  else
    return 0;
}

size_t buffer_fd_read(Buffer *b, FILE *in, size_t len) {
  if(feof(in) || ferror(in)) {
    return 0;
  }

  void *data = ucmalloc(len);

  size_t s = fread(data, 1, len, in);

  if(s < len) {
    fatal("[buffer %s] attempt to read %"FMT_SIZE_T" bytes from FILE, but got %"FMT_SIZE_T" bytes only\n", b->name, (SIZE_T_CAST)len, (SIZE_T_CAST)s);
    return 0;
  }

  buffer_add(b, data, len);
  return len;
}

void buffer_add8(Buffer *b, uint8_t v) {
  buffer_add(b, &v, 1);
}

void buffer_add16(Buffer *b, uint16_t v) {
  buffer_add(b, &v, 2);
}

void buffer_add32(Buffer *b, uint32_t v) {
  buffer_add(b, &v, 4);
}

void buffer_add64(Buffer *b, uint64_t v) {
  buffer_add(b, &v, 8);
}

void buffer_add16be(Buffer *b, uint16_t v) {
  uint16_t e = v;
  e = htobe16(e);
  buffer_add(b, &e, 2);
}

void buffer_add32be(Buffer *b, uint32_t v) {
  uint32_t e = v;
  e = htobe32(e);
  buffer_add(b, &e, 4);
}

void buffer_add64be(Buffer *b, uint64_t v) {
  uint64_t e = v;
  e = htobe64(e);
  buffer_add(b, &e, 8);
}
