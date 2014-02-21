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
  stream->z = buffer_new(32, "Z85stream");
  stream->b = NULL;
  stream->fd = NULL;
  stream->is_buffer = 0;
  stream->eof = 0;
  stream->err = 0;
  stream->armor = 0;
  stream->determine = 0;
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

void ps_armor(Pcpstream *stream) {
  stream->armor = 1;
}

void ps_determine(Pcpstream *stream) {
  stream->determine = 1;
}

int ps_end(Pcpstream *stream) {
  return stream->eof;
}

int ps_err(Pcpstream *stream) {
  return stream->err;
}

size_t ps_read(Pcpstream *stream, void *buf, size_t readbytes) {
  size_t gotbytes = 0;

  if(stream->is_buffer) {
    /* a buffer stream */
    if(buffer_left(stream->b) < readbytes)
      readbytes = buffer_left(stream->b);

    if(stream->armor == 1) {
      size_t i = 0;
      uint8_t c;
      while (i < readbytes) {
	c = buffer_get8(stream->b);
	if(c != '\r' && c != '\n') {
	  buffer_add8(stream->z, c);
	  i++;
	}
      }
      memcpy(buf, buffer_get(stream->z), buffer_size(stream->z));
      gotbytes = buffer_size(stream->z);
      buffer_clear(stream->z);
    }
    else
      gotbytes = buffer_get_chunk(stream->b, buf, readbytes);

    if(gotbytes == 0) {
      /* this should not happen with buffers */
      stream->eof = 1;
      stream->err = 1;
    }
  }
  else {
    /* a FILE stream */
    if(stream->armor == 1) {
      size_t i = 0;
      uint8_t c;
      while (i < readbytes) {
	gotbytes = fread(&c, 1, 1, stream->fd);
	if(gotbytes == 0)
	  break;
	if(c != '\r' && c != '\n') {
	  buffer_add8(stream->z, c);
	  i++;
	}
      }
      memcpy(buf, buffer_get(stream->z), buffer_size(stream->z));
      gotbytes = buffer_size(stream->z);
      _dump("buf", buf, gotbytes);
      buffer_clear(stream->z);
    }
    else
      gotbytes = fread(buf, 1, readbytes, stream->fd);

    if(gotbytes == 0) {
      if(feof(stream->fd) != 0)
	stream->eof = 1;
      if(ferror(stream->fd) != 0)
	stream->err = 1;
    }
  }

  if(gotbytes > 0 && stream->determine  && stream->firstread == 0) {
    /* check if we need to decode input */
    fprintf(stderr, "determine\n");
    if(_buffer_is_binary(buf, gotbytes) == 0) {
      fprintf(stderr, "is armored\n");
      stream->armor = 1;
    }
  }

  stream->firstread = 1;

  if(gotbytes > 0 && stream->armor == 1) {
    /* z85 decode buf */
    size_t binlen;
    unsigned char *bin = pcp_z85_decode(buf, &binlen);
    if(bin == NULL) {
      return 0;
    }

    memcpy(buf, bin, binlen);

    _dump("decoded", buf, binlen);

    free(bin);
    return binlen;
  }

  return gotbytes;
}

size_t ps_write(Pcpstream *stream, void *buf, size_t writebytes) {
  size_t donebytes = 0;

  if(stream->armor == 1) {
    /* z85 encode buf */
    size_t padlen, zlen, i, pos;
    unsigned char *padded = pcp_padfour(buf, writebytes, &padlen);
    
    zlen = (padlen * 5 / 4);
    char *z85 = ucmalloc(zlen);

    zmq_z85_encode(z85, padded, padlen);

    _dump("   orig", buf, writebytes);
    _dump("    z85", z85, zlen);

    pos = stream->linewr;
    for(i=0; i<zlen; ++i) {
       if(pos >= 71) {
	 buffer_add8(stream->z, '\r');
	 buffer_add8(stream->z, '\n');
	 pos = 1;
       }
       else
	 pos++;
       buffer_add8(stream->z, z85[i]);
    }
    stream->linewr = pos;
    _dump("n added", buffer_get(stream->z), buffer_size(stream->z));
  }
  else {
    buffer_add(stream->z, buf, writebytes);
  }

  if(stream->is_buffer) {
    buffer_add(stream->b, buffer_get(stream->z), buffer_size(stream->z));
    donebytes =  buffer_size(stream->z);
  }
  else {
    donebytes = fwrite(buffer_get(stream->z), 1, buffer_size(stream->z), stream->fd);
    if(ferror(stream->fd) != 0 || donebytes < buffer_size(stream->z))
      stream->err = 1;
  }

  writebytes = buffer_size(stream->z);
  buffer_clear(stream->z);
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

