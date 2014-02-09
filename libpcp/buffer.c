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

#include "buffer.h"

Buffer *buffer_new(size_t blocksize, char *name) {
  Buffer *b = ucmalloc(sizeof(Buffer));
  b->buf = ucmalloc(blocksize);
  b->name = ucmalloc(strlen(name)+1);
  b->size = blocksize;
  b->allocated = 1;
  b->offset = 0;
  b->end = 0;
  b->blocksize = blocksize;
  memcpy(b->name, name, strlen(name)+1);
  return b;
}

void buffer_free(Buffer *b) {
  if(b != NULL) {
    if(b->allocated > 0) {
      buffer_clear(b);
      free(b->buf);
      free(b);
    }
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

void buffer_add_buf(Buffer *dst, Buffer *src) {
  buffer_add(dst, buffer_get(src), buffer_size(src));
}

void buffer_resize(Buffer *b, size_t len) {
  if((b->end > 0 && b->end + len > b->size) || (b->end == 0 && len > b->size) ) {
    /* increase by buf blocksize */
    size_t newsize = (((len / b->blocksize) +1) * b->blocksize) + b->size;
    fprintf(stderr, "[buffer %s] resizing from %ld to %ld\n", b->name, b->size, newsize);
    b->buf = ucrealloc(b->buf, b->size, newsize);
    b->size = newsize;
  }
}

unsigned char *buffer_get(Buffer *b) {
  if(b->end > 0)
    return b->buf;
  else
    return NULL;
}

size_t buffer_get_chunk(Buffer *b, void *buf, size_t len) {
  if(len > b->end - b->offset || len == 0) {
    fatal("[buffer %s] attempt to read %ld data from buffer with size %ld %p at offset %ld",
	  len, b->size, b->offset);
    return 0;
  }
  memcpy(buf, b->buf + b->offset, len);
  b->offset += len;
  return len;
}

char *buffer_get_str(Buffer *b) {
  buffer_resize(b, 1); /* make room for trailing zero */
  return (char *)b->buf;
  /*
  char *out = ucmalloc(b->end+1);
  memcpy(out, buffer_get(b), buffer_size(b));
  out[buffer_size(b)] = '\0';
  return out;
  */
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
  fprintf(stderr, "blocksize: %ld\n", b->blocksize);
  fprintf(stderr, "     size: %ld\n", b->size);
  fprintf(stderr, "   offset: %ld\n", b->offset);
  fprintf(stderr, "      end: %ld\n", b->end);
  fprintf(stderr, "allocated: %d\n", b->allocated);
}

size_t buffer_size(const Buffer *b) {
  return b->end;
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
    fatal("[buffer %s] attempt to read %ld bytes from FILE, but got %ld bytes only\n", b->name, len, s);
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
