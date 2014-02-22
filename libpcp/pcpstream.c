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
  stream->cache = buffer_new(32, "Pcpstreamcache");
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
  stream->b = buffer_new(32, "Pcpstreamoutbuf");
  stream->is_buffer = 1;
  return stream;
}

void ps_setdetermine(Pcpstream *stream, size_t blocksize) {
  stream->determine = 1;
  stream->blocksize = blocksize;
}

void ps_armor(Pcpstream *stream, size_t blocksize) {
  stream->armor = 1;
  stream->blocksize = blocksize;
}

size_t ps_read_raw(Pcpstream *stream, void *buf, size_t readbytes) {
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

  stream->firstread = 1;
  return gotbytes;
}

/* return readbytes from cache. if it is more than left in the cache
   fetch (and decode) the next chunk, append it to cache and return from
   that */
size_t ps_read_cached(Pcpstream *stream, void *buf, size_t readbytes) {
  if(buffer_left(stream->cache) <= readbytes) {
    /* enough left in current cache */
    return buffer_get_chunk(stream->cache, buf, readbytes);
  }
  else {
    /* not enough, fetch the next chunk */
    ps_read_next(stream);

    /* determine overlapping bytes */
    size_t overlap = readbytes - buffer_left(stream->cache);

    /* fetch the rest from the cache */
    size_t fromcache = buffer_get_chunk(stream->cache, buf, buffer_left(stream->cache));

    /* fetch the overlap from next, append to buf */
    if(overlap > buffer_left(stream->next))
      overlap = buffer_left(stream->next);
    buffer_get_chunk(stream->next, buf+overlap, overlap);

    /* move the rest of stream->next into cache */
    buffer_clear(stream->cache);
    void *rest = buffer_get_remainder(stream->next);
    buffer_add(stream->cache, rest, buffer_left(stream->next));
    free(rest);

    /* reset next */
    buffer_clear(stream->next);

    return fromcache + overlap;
  }
}

/* read and decode the next chunk and put it into stream->next */
size_t ps_read_next(Pcpstream *stream) {
  if(stream->armor == 1) {
    /* fetch next chunk and decode it */
    return ps_read_decode(stream, stream->next, NULL, 0);
  }
  else {
    /* unencoded source, fetch as is */
    void *buf = ucmalloc(stream->blocksize);
    size_t got = ps_read_raw(stream, buf, stream->blocksize);
    buffer_add(stream->next, buf, got);
    return got;
  }
}

size_t ps_read(Pcpstream *stream, void *buf, size_t readbytes) {
  if(buffer_size(stream->cache) > 0) {
    /* use cache */
    return ps_read_cached(stream, buf, readbytes);
  }
  else {
    /* no cache yet */
    if(stream->determine == 1 && stream->firstread == 0) {
      /* fetch the first chunk into the cache and decode, if required,
         recursively call ps_read() again to return the apropriate data */
      ps_determine(stream);
      return ps_read(stream, buf, readbytes);
    }
    else if(stream->armor == 1) {
      /* z85 encoding has already been determined, therefore the cache
	 is now filled, use it then */
      return ps_read_cached(stream, buf, readbytes);
    }
    else {
      /* read directly from source */
      return ps_read_raw(stream, buf, readbytes);
    }
  }
}

void ps_determine(Pcpstream *stream) {
  /* read a raw chunk from source */
  void *buf = ucmalloc(stream->blocksize);
  size_t got = ps_read_raw(stream, buf, stream->blocksize);

  /* check if it's binary or not */
  if(_buffer_is_binary(buf, got) != 0) {
    /* no, it's armored */
    stream->armor = 1;
    ps_read_decode(stream, stream->cache, buf, got);
  }
  else {
    /* just put the raw stuff into the cache */
    buffer_add(stream->cache, buf, got);
  }
}

size_t ps_read_decode(Pcpstream *stream, Buffer *cache, void *buf, size_t bufsize) {
  size_t zdiff = 1;
  size_t i = 0;
  Buffer *z = buffer_new(32, "ztemp");

  if(bufsize > 0) {
    /* remove newlines, comments and headers, if any */
    char *z85 = pcp_readz85string(buf, bufsize);
    buffer_add(z, z85, strlen(z85));

    /* check if we need to read more in order to get a full block */
    zdiff = stream->blocksize - strlen(z85);
    i = strlen(z85);
    free(z85);
  }
 
  if(zdiff > 0) {
    /* read in bytewise, ignore newlines and add until the block is full */
    uint8_t c;
    while (i < stream->blocksize) {
      if (ps_read_raw(stream, &c, 1) == 1) {
	if(c != '\r' && c != '\n') {
	  buffer_add8(z, c);
	  i++;
	}
      }
      else
	break;
    }
  }

  /* finally, decode it and put into cache */
  size_t binlen, outlen;
  unsigned char *bin = pcp_z85_decode(buffer_get_str(z), &binlen);
  if(bin == NULL) {
    /* it's not z85 encoded, so threat it as binary */
    stream->armor = 1;
    buffer_add_buf(stream->cache, z);
    outlen = buffer_size(stream->cache);
  }
  else {
    /* yes, successfully decoded it, put into cache */
    buffer_add(stream->cache, bin, binlen);
    outlen = binlen;
  }
  
  buffer_free(z);

  return outlen;
}

size_t ps_write(Pcpstream *stream, void *buf, size_t writebytes) {
  Buffer *z = buffer_new(32, "Pcpwritetemp");

  if(stream->armor == 1) {
    if(buffer_size(stream->cache) + writebytes < stream->blocksize) {
      /* just put it into the cache and done with it */
      buffer_add(stream->cache, buf, writebytes);
    }
    else {
      /* z85 encode cache+buf */

      /* check if there's an overlap, if yes, put it aside for the moment */
      void *aside = NULL;
      size_t overlap = (buffer_size(stream->cache) + writebytes) - stream->blocksize;
      if(overlap > 0) {
	/* yes, store the overlap, put the left part into the cache */
	aside = ucmalloc(overlap);
	memcpy(aside, buf + (writebytes - overlap), overlap); /* FIXME: check if this works */
	buffer_add(stream->cache, buf, writebytes - overlap);
      }
      else {
	/* cache+buf == blocksize */
	buffer_add(stream->cache, buf, writebytes);
      }

      /* encode the cache into z */
      ps_write_encode(stream, z);

      buffer_clear(stream->cache);
      if(aside != NULL) {
	/* there is an overlapping rest, put it into the cache
	   FIXME: write it on calling ps_close() or ad some ps_finish() function */
	buffer_add(stream->cache, aside, overlap);
      }
    }
  }
  else {
    buffer_add(z, buf, writebytes);
  }

 size_t outsize = ps_write_buf(stream, z);

 buffer_free(z);

 return outsize;
}

void ps_write_encode(Pcpstream *stream, Buffer *dst) {
  size_t zlen, i, pos;
  
  /* do z85 0 padding, manually */
  if(buffer_size(stream->cache) % 4 != 0) {
    size_t outlen = buffer_size(stream->cache);
    while (outlen % 4 != 0) 
      buffer_add8(stream->cache, 0);
  }

  /* z85 encode */
  zlen = (buffer_size(stream->cache) * 5 / 4);
  char *z85 = ucmalloc(zlen);

  zmq_z85_encode(z85, buffer_get(stream->cache), buffer_size(stream->cache));

  /* add newlines */
  pos = stream->linewr;
  for(i=0; i<zlen; ++i) {
    if(pos >= 71) {
      buffer_add8(dst, '\r');
      buffer_add8(dst, '\n');
      pos = 1;
    }
    else
      pos++;
    buffer_add8(dst, z85[i]);
  }

  /* remember where to start next */
  stream->linewr = pos;
}

size_t ps_write_buf(Pcpstream *stream, Buffer *z) {
  size_t writebytes;

  if(stream->is_buffer) {
    buffer_add(stream->b, buffer_get(z), buffer_size(z));
    writebytes =  buffer_size(z);
  }
  else {
    writebytes = fwrite(buffer_get(z), 1, buffer_size(z), stream->fd);
    if(ferror(stream->fd) != 0 || writebytes < buffer_size(z)) {
      stream->err = 1;
      writebytes = 0;
    }
  }

  return writebytes;
}

size_t ps_finish(Pcpstream *stream) {
  size_t outsize = 0;
  if(buffer_left(stream->cache) > 0) {
    Buffer *z = buffer_new(32, "Pcpwritetemp");
    ps_write_encode(stream, z);
    outsize = ps_write_buf(stream, z);
    buffer_free(z);
  }  
  return outsize;
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
