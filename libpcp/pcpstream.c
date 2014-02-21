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

#include "pcpstream.h"

Pcpstream *ps_init(void) {
  Pcpstream *stream = ucmalloc(sizeof(Pcpstream));
  stream->b = NULL;
  stream->fd = NULL;
  stream->is_buffer = 0;
  stream->eof = 0;
  stream->err = 0;
  return stream;
}

Pcpstream *ps_new_file(FILE *backendfd) {
  Pcpstream *stream = ps_init();
  stream->fd = backendfd;
  return stream;
}

Pcpstream *ps_new_inbuffer(Buffer *b) {
  Pcpstream *stream = ps_init();
  stream->b = b;
  stream->is_buffer = 1;
  return stream;
}

Pcpstream *ps_new_outbuffer() {
  Pcpstream *stream = ps_init();
  stream->b = buffer_new(32, "Pcpstream");
  stream->is_buffer = 1;
  return stream;
}

size_t ps_read(Pcpstream *stream, void *buf, size_t readbytes) {
  size_t gotbytes = 0;

  if(stream->is_buffer) {
    /* check if there's enough space in our buffer */
    if(buffer_left(stream->b) < readbytes)
      readbytes = buffer_left(stream->b);

    gotbytes = buffer_get_chunk(stream->b, buf, readbytes);
    if(gotbytes == 0) {
      /* this should not happen with buffers */
      stream->eof = 1;
      stream->err = 1;
    }
  }
  else {
    gotbytes = fread(buf, 1, readbytes, stream->fd);
    if(gotbytes == 0) {
      if(feof(stream->fd) != 0)
	stream->eof = 1;
      if(ferror(stream->fd) != 0)
	stream->err = 1;
    }
  }

  return gotbytes;
}

size_t ps_write(Pcpstream *stream, void *buf, size_t writebytes) {
  size_t donebytes = 0;

  if(stream->is_buffer) {
    buffer_add(stream->b, buf, writebytes);
    donebytes = writebytes;
  }
  else {
    donebytes = fwrite(buf, 1, writebytes, stream->fd);
    if(ferror(stream->fd) != 0 || donebytes < writebytes)
      stream->err = 1;
  }

  return writebytes;
}

size_t ps_print(Pcpstream *stream, const char * fmt, ...) {
  va_list ap;
  char *dst;
  va_start(ap, fmt);
  vasprintf(&dst, fmt, ap);
  va_end(ap);
  size_t len = strlen(dst);

  if(stream->is_buffer) {
    buffer_add(stream->b, dst, len);
    return len;
  }
  else {
    return ps_write(stream, dst, len);
  }
}

void ps_close(Pcpstream *stream) {
  if(stream->is_buffer) {
    buffer_clear(stream->b);
    free(stream);
  }
  else {
    /* only close files, not terminal devices */
    if(fileno(stream->fd) > 2)
      fclose(stream->fd);
    free(stream);
  }
}

int ps_end(Pcpstream *stream) {
  return stream->eof;
}

int ps_err(Pcpstream *stream) {
  return stream->err;
}

size_t ps_tell(Pcpstream *stream) {
  if(stream->is_buffer) {
    if(stream->b->end > stream->b->offset)
      return stream->b->end; /* write buffer */
    else
      return stream->b->offset; /* read buffer */
  }
  else {
    return ftell(stream->fd);
  }
}

Buffer *ps_buffer(Pcpstream *stream) {
  return stream->b;
}
