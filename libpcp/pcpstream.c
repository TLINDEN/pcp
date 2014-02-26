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
  stream->cache = NULL;
  stream->next = NULL;
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
  assert(blocksize % 4 == 0);
  stream->determine = 1;
  stream->blocksize = blocksize + (5 - (blocksize % 5));
  if(stream->cache == NULL) {
    stream->cache = buffer_new(32, "Pcpstreamcache");
    stream->next = buffer_new(32, "Pcpstreamcachenext");
  }
}

void ps_armor(Pcpstream *stream, size_t blocksize) {
  assert(blocksize % 4 == 0);
  stream->armor = 1;
  stream->blocksize = blocksize;
  if(stream->cache == NULL) {
    stream->cache = buffer_new(32, "Pcpstreamcache");
    stream->next = buffer_new(32, "Pcpstreamcachenext");
  }
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
  if(buffer_left(stream->cache) <= readbytes && buffer_left(stream->cache) > 0 && readbytes <= stream->blocksize) {
    /* enough left in current cache */
    return buffer_get_chunk(stream->cache, buf, buffer_left(stream->cache));
  }
  else {
     /* request for chunk larger than what we've got in the cache */
    Buffer *tmp = buffer_new(stream->blocksize, "Pcpreadover");

    if( buffer_left(stream->cache) > 0) {
      /* put the remaining cache into dest */
      buffer_get_chunk_tobuf(stream->cache, tmp, buffer_size(stream->cache)); 
    }

    /* how much left to fetch */
    long int left = readbytes - buffer_size(tmp);

    /* fetch and decode data until tmp is filled */
    while (left > 0) {
      /* not enough cached, fetch the next chunk */
      if(ps_read_next(stream) == 0)
	break;

      /* need to fetch more? */
      left = readbytes - (buffer_size(tmp) + buffer_size(stream->next));

      if(left < 0) {
	/* no more to fetch, in fact there's more than we need */
	/* determine overlapping bytes */
	size_t overlap = readbytes - buffer_size(tmp);

	/* avoid overflow */
	if(overlap > buffer_size(stream->next))
	  overlap = buffer_size(stream->next);

	/* add the overlap from next to tmp */
	buffer_get_chunk_tobuf(stream->next, tmp, overlap);

	/* move the rest of stream->next into cache */
	buffer_clear(stream->cache);
	buffer_get_chunk_tobuf(stream->next, stream->cache, buffer_left(stream->next)); 
	buffer_clear(stream->next);
      }
      else {
	/* we've got precisely what we need, no need to calculate any overlap
	   OR there's more to fetch, we don't have enough stuff yet,
	   put next into tmp, reset next and loop again - same behavior */
	buffer_add_buf(tmp, stream->next);
	buffer_clear(stream->next);
      }
    }

    /* return to the caller */
    left = buffer_size(tmp);
    buffer_get_chunk(tmp, buf, left);
    buffer_free(tmp);

    return left;
  }
}

/* read and decode the next chunk and put it into stream->next */
size_t ps_read_next(Pcpstream *stream) {
  if(stream->armor == 1) {
    /* fetch next chunk and decode it */
    return ps_read_decode(stream, NULL, 0);
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
  if(stream->cache == NULL) {
    return ps_read_raw(stream, buf, readbytes);
  }
  else if(buffer_size(stream->cache) > 0) {
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
  if(_buffer_is_binary(buf, got) == 0) {
    /* no, it's armored */
    stream->armor = 1;

    /* decode the first chunk */
    ps_read_decode(stream, buf, got);
    
    /* put it into the cache */
    buffer_add_buf(stream->cache, stream->next);
    buffer_clear(stream->next);
  }
  else {
    /* just put the raw stuff into the cache */
    buffer_add(stream->cache, buf, got);
  }
}

size_t ps_read_decode(Pcpstream *stream, void *buf, size_t bufsize) {
  size_t i = 0;
  uint8_t is_comment = 0;
  uint8_t c;
  Buffer *z = buffer_new(32, "ztemp");
  byte *_buf = buf;

  if(bufsize > 0) {
    for(i=0; i<bufsize; ++i) {
      c = _buf[i];
      is_comment = _parse_zchar(z, c, is_comment);
    }
  }
 
  if(buffer_size(z) <  stream->blocksize) {
    /* blocksize not full, continue with stream source */
    /* read in bytewise, ignore newlines and add until the block is full */
    while (buffer_size(z) < stream->blocksize) {
      if (ps_read_raw(stream, &c, 1) == 1) {
	is_comment = _parse_zchar(z, c, is_comment);
      }
      else
	break;
    }
  }

  /* finally, decode it and put into next */
  size_t binlen, outlen;
  byte *bin = pcp_z85_decode(buffer_get_str(z), &binlen);
  if(bin == NULL) {
    /* it's not z85 encoded, so threat it as binary */
    stream->armor = 0;
    buffer_add_buf(stream->next, z);
    outlen = buffer_size(stream->next);
  }
  else {
    /* yes, successfully decoded it, put into cache */
    buffer_add(stream->next, bin, binlen);
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
    else if(buffer_size(stream->cache) + writebytes > stream->blocksize) {
      /* buf is too large to fit into blocksize, put out the blocks we've got so far */
      buffer_add(stream->cache, buf, writebytes);

      /* encode blockwise and write directly until there's a rest */
      Buffer *tmp = buffer_new(stream->blocksize, "Pcpcopybuf");

      /* copy current cache to tmp for iteration */
      buffer_add_buf(tmp, stream->cache);

      while (buffer_left(tmp) > stream->blocksize) {
	/* iterate over tmp blockwise, encode each block, write it out until there's a rest */
	buffer_clear(stream->cache);
	buffer_get_chunk_tobuf(tmp, stream->cache, stream->blocksize);
	ps_write_encode(stream, z);
      }

      /* now, z contains a couple of z85 encoded blocks, tmp contains the
	 remainder of the write buffer, store the rest in the cache and
	 go on as nothing did happen */
      buffer_clear(stream->cache);
      buffer_add(stream->cache, buffer_get_remainder(tmp), buffer_left(tmp));
      buffer_free(tmp);
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
	   the caller needs to call ps_finish() to put it out */
	buffer_add(stream->cache, aside, overlap);
      }
    }
  }
  else {
    buffer_add(z, buf, writebytes);
  }

  if(buffer_size(z) > 0) {
    /* actually put it out */
    size_t outsize = ps_write_buf(stream, z);
    buffer_free(z);
    return outsize;
  }
  else {
    /* buf has been put into the cache only, no writing required */
    buffer_free(z);
    return writebytes;
  }
}

void ps_write_encode(Pcpstream *stream, Buffer *dst) {
  size_t zlen, i, pos;
  
  /* do z85 0 padding, manually */
  if(buffer_size(stream->cache) % 4 != 0) {
    size_t outlen = buffer_size(stream->cache);
    while (outlen % 4 != 0) {
      buffer_add8(stream->cache, 0);
      outlen = buffer_size(stream->cache);
    }
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
  if(stream->cache != NULL) {
    if(buffer_left(stream->cache) > 0) {
      Buffer *z = buffer_new(32, "Pcpwritetemp");
      ps_write_encode(stream, z);
      outsize = ps_write_buf(stream, z);
      buffer_clear(stream->cache);
      buffer_free(z);
    }
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
  if(stream->cache != NULL) {
    assert(buffer_left(stream->cache) == 0); /* there's something left in the cache, call ps_finish() */
    buffer_free(stream->cache);
  }

  if(stream->next != NULL)
    buffer_free(stream->next);

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
  /* simulate open file if there's still something in the cache */
  if(stream->cache != NULL)
    if(buffer_left(stream->cache) > 0)
      return 0;
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
