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
#include "pcpstream.h"

Pcpstream *ps_init(void) {
  Pcpstream *stream = ucmalloc(sizeof(Pcpstream));
  stream->b = NULL;
  stream->cache = NULL;
  stream->next = NULL;
  stream->fd = NULL;
  stream->save =  buffer_new(32, "Pcpstreamsavebuf");
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
  /* expand blocksize by the remainder of %5 plus another 5 bytes
     for the pad blob */
  stream->blocksize = blocksize + (blocksize / 4) + 5;
  //fprintf(stderr, "blocksize: %ld\n", stream->blocksize);
  if(stream->cache == NULL) {
    stream->cache = buffer_new(32, "Pcpstreamcachedetermine");
    stream->next = buffer_new(32, "Pcpstreamcachenextdetermin");
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

void ps_unarmor(Pcpstream *stream) {
  stream->armor = 0;
}

void ps_rewind(Pcpstream *stream, void *buf, size_t bufsize) {
  if(stream->is_buffer) {
    stream->b->offset -= bufsize;
  }
  else {
    buffer_clear(stream->save);
    buffer_add(stream->save, buf, bufsize);
  }
  stream->pos -= bufsize;
  stream->err = 0;
  stream->eof = 0;
}

size_t ps_read_raw(Pcpstream *stream, void *buf, size_t readbytes) {
  size_t gotbytes = 0;
  size_t idx = 0;

  if(buffer_left(stream->save) > 0) {
    /* something left from last rewind, first use this */
    if(buffer_left(stream->save) >= readbytes) {
      gotbytes = buffer_get_chunk(stream->save, buf, readbytes);
      if(buffer_left(stream->save) == 0)
	  buffer_clear(stream->save);
      goto rawdone;
    }
    else {
      /* fetch the remainder of the save buffer, remember how much
	 to fetch from source next */
      idx = buffer_get_chunk(stream->save, buf, buffer_left(stream->save));
      buffer_clear(stream->save);
      readbytes -= idx;
    }
  }

  // fprintf(stderr, "       ps_read_raw, idx: %ld, readbytes: %ld\n", idx, readbytes);

  if(stream->is_buffer) {
    /* check if there's enough space in our buffer */
    if(buffer_left(stream->b) < readbytes)
      readbytes = buffer_left(stream->b);

    gotbytes += buffer_get_chunk(stream->b, buf+idx, readbytes);
    if(gotbytes == 0) {
      /* this should not happen with buffers */
      stream->eof = 1;
      stream->err = 1;
    }
  }
  else {
    size_t got = fread(buf+idx, 1, readbytes, stream->fd);
    gotbytes += got;
    if(feof(stream->fd) != 0)
      stream->eof = 1;
    if(ferror(stream->fd) != 0)
      stream->err = 1;
  }


 rawdone:
  //_dump("ps_read_raw", buf, gotbytes);
  return gotbytes;
}

/* return readbytes from cache. if it is more than left in the cache
   fetch (and decode) the next chunk, append it to cache and return from
   that */

size_t ps_read_cached(Pcpstream *stream, void *buf, size_t readbytes) {
  /*
  fprintf(stderr, "%ld <= %ld && %ld <= %ld\n",
	  readbytes, buffer_left(stream->cache), readbytes, stream->blocksize) ;

  fprintf(stderr, "%d == 1 && %ld >= %ld\n",
	  ps_end(stream), readbytes, buffer_left(stream->cache));
  */
  if(readbytes <= buffer_left(stream->cache) && readbytes <= stream->blocksize) {
    /* enough left in current cache */
    // fprintf(stderr, "  get all from cache\n");
    return buffer_get_chunk(stream->cache, buf, readbytes);
  }
  else if(ps_end(stream) == 1 && readbytes >= buffer_left(stream->cache) ) {
    // fprintf(stderr, "  get rest from cache\n");
    return buffer_get_chunk(stream->cache, buf, buffer_left(stream->cache));
  }
  else {
    // fprintf(stderr, "  fetch next\n");
     /* request for chunk larger than what we've got in the cache */
    Buffer *tmp = buffer_new(stream->blocksize, "Pcpreadchunktmp");

    if( buffer_left(stream->cache) > 0) {
      /* put the remaining cache into dest */
      buffer_get_chunk_tobuf(stream->cache, tmp, buffer_left(stream->cache)); 
    }

    //#error EOF reached, cache empty, save filled, doesnt call ps_read_next()

    /* how much left to fetch */
    long int left = readbytes - buffer_size(tmp);

    /* fetch and decode data until tmp is filled */
    while (left > 0) {
      /* not enough cached, fetch the next chunk */
      // fprintf(stderr, "  fetch next read_next\n");
      if(ps_read_next(stream) == 0)
	break;
      // fprintf(stderr, "  fetch next read_continue\n");

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
  // fprintf(stderr, "      ps_read_next ps_left: %d, ps_end: %d, save_left: %ld\n", ps_left(stream), ps_end(stream), buffer_left(stream->save));
  if(ps_left(stream) == 0 || buffer_left(stream->save)) {
    if(stream->armor == 1) {
      /* fetch next chunk and decode it */
      return ps_read_decode(stream);
    }
    else {
      /* unencoded source, fetch as is */
      void *buf = ucmalloc(stream->blocksize);
      size_t got = ps_read_raw(stream, buf, stream->blocksize);
      buffer_add(stream->next, buf, got);
      free(buf);
      return got;
    }
  }
  else
    return 0;
}

size_t ps_read(Pcpstream *stream, void *buf, size_t readbytes) {
  size_t got = 0;
  if(stream->cache == NULL) {
    got = ps_read_raw(stream, buf, readbytes);
  }
  else if(buffer_size(stream->cache) > 0) {
    /* use cache */
    got = ps_read_cached(stream, buf, readbytes);
    // fprintf(stderr, "%ld = use cache directly\n", got);
  }
  else {
    /* no cache yet */
    if(stream->determine == 1 && stream->firstread == 0) {
      /* fetch the first chunk into the cache and decode, if required,
         recursively call ps_read() again to return the apropriate data */
      ps_determine(stream);
      got = ps_read(stream, buf, readbytes);
      // fprintf(stderr, "%ld = ps_read(stream, buf, readbytes);\n", got);
    }
    else if(stream->armor == 1) {
      /* z85 encoding has already been determined, therefore the cache
	 is now filled, use it then */
      got = ps_read_cached(stream, buf, readbytes);
      // fprintf(stderr, "%ld = ps_read_cached(stream, buf, readbytes);\n", got);
    }
    else {
      /* read directly from source */
      got = ps_read_raw(stream, buf, readbytes);
    }
  }

  stream->pos += got;
  // fprintf(stderr, "  ps_read(): %ld\n", got);
  return got;
}

int ps_readline(Pcpstream *stream, Buffer *line) {
  int c = -1, max = 1;
  byte b[1];

  while(c<PSMAXLINE) {
    //fprintf(stderr, "    ps_readline: call raw\n");
    if(ps_read_raw(stream, b, 1) < 1) {
      //fprintf(stderr, "      ps_readline: raw returned < 1\n");
      max = 0;
      break; /* eof or err */
    }
    if(*b == '\r') {
      //fprintf(stderr, "      ps_readline: raw found CR\n");
      continue;
    }
    else if(*b == '\n' || ps_end(stream) == 1) {
      //fprintf(stderr, "      ps_readline: raw found NL\n");
      c++;
      max = 0;
      break;
    }
    else {
      //fprintf(stderr, "      ps_readline: raw found regular\n");
      buffer_add8(line, *b);
    } 
    c++;
  }

  if(max) {
    /* maxline reached without a newline.
       backup the data we've got so far
       for further processing */
    buffer_add_buf(stream->save, line);
    buffer_clear(line);
    return -1;
  }

  // fprintf(stderr, "      ps_readline: raw return %d\n", c);

  return c;
}

void ps_determine(Pcpstream *stream) {
  /* read a raw chunk from source */
  void *buf = ucmalloc(stream->blocksize);
  size_t got = ps_read_raw(stream, buf, stream->blocksize);

  /* check if it's binary or not */
  if(_buffer_is_binary(buf, got) == 0) {
    
    /* not binary, it's armored */
    stream->armor = 1;

    /* put back raw data into read queue */
    ps_rewind(stream, buf, got);

    /* decode the first chunk */
    ps_read_decode(stream);
    
    /* put it into the cache */
    buffer_add_buf(stream->cache, stream->next);
    buffer_clear(stream->next);
  }
  else {
    /* just put the raw stuff into the cache */
    buffer_add(stream->cache, buf, got);
  }

  ucfree(buf, stream->blocksize);

  stream->firstread = 1;
}


size_t ps_read_decode(Pcpstream *stream) {
  Buffer *z = buffer_new(32, "ztemp");
  Buffer *line = buffer_new_str("line");
  PCPCTX *ptx = ptx_new();

  if(buffer_left(stream->save) > stream->blocksize){// && stream->firstread == 1) {
    /* use the save buffer instead */
    /* fprintf(stderr, "      ps_read_next get chunk from save %ld >= %ld\n", 
       buffer_left(stream->save), stream->blocksize);    */
    buffer_get_chunk_tobuf(stream->save, z, stream->blocksize);
  }
  else if(ps_left(stream) == 1 && buffer_left(stream->save) > 0 && stream->firstread == 1) {
    /* there's something left which doesn't end in a newline,
       but only if this is not our first read, in which case
       we need to run into the readline loop at least once. */
    // fprintf(stderr, "      ps_read_next which doesn't end in a newline\n");
    buffer_get_chunk_tobuf(stream->save, z, buffer_left(stream->save));
    //buffer_dump(z);
    //fatals_ifany();
  }
  else {
    /* continue reading linewise */
    // fprintf(stderr, "      ps_read_next while(%ld < %ld)\n", buffer_size(z), stream->blocksize);
    while(buffer_size(z) <  stream->blocksize) {
      buffer_clear(line);
      if(ps_readline(stream, line) >= 0) {
	//fprintf(stderr, "got: <%s>\n", buffer_get_str(line));	
	if(z85_isbegin(line) && stream->have_begin == 0) {
	  /* begin header encountered */
	  stream->have_begin = 1; /* otherwise ignore it */
	  continue;
	}
	else if(z85_isend(line)) {
	  /* end header encountered */
	  break;
	}
	else if(z85_isempty(line)) {
	  /* ignore empty lines */
	  continue;
	}
	else {
	  /* regular z85 encoded content */
	  // fprintf(stderr, "regular\n");
	  // fprintf(stderr, "       %ld + %ld > %ld\n", buffer_size(z), buffer_size(line), stream->blocksize);
	  if(buffer_size(z) + buffer_size(line) > stream->blocksize) {
	    /* we've got more than needed.
	       put what we need into z and the remainder
	       into the save buffer for further reading. */
	    /* fprintf(stderr, "overflow %ld + %ld > %ld\n",
		    buffer_size(z), buffer_size(line), stream->blocksize);
	    */
	    buffer_get_chunk_tobuf(line, z, stream->blocksize - buffer_size(z));
	    buffer_get_chunk_tobuf(line, stream->save, buffer_left(line));
	    if(!ps_left(stream)) {
	      /* only add the newline if there's no more to follow */
	      buffer_add8(stream->save, '\n');
	    }
	    break;
	  }
	  else {
	    /* not enough yet, store it and go on */
	    buffer_add_buf(z, line);
	  }
	}
      }
      else {
	// fprintf(stderr, "      ps_read_next readline returned 0\n");
	/* eof or err */
	break;
      }
    }
  }

  //fprintf(stderr, "%s\n", buffer_get_str(z));

  /* finally, decode it and put into next */
  size_t binlen, outlen;
  byte *bin = pcp_z85_decode(ptx, buffer_get_str(z), &binlen);
  //fprintf(stderr, "ps_read_decode decoding z: %ld, got: %ld\n", buffer_size(z), binlen);
  //_dump("bin", bin, binlen);
  //fatals_ifany();

  if(bin == NULL) {
    /* it's not z85 encoded, so threat it as binary */
    if(stream->firstread) {
      /* whoops, we're in the middle of z85 decoding and it failed */
      stream->eof = 1;
      stream->err = 1;
      outlen = 0;
    }
    else {
      stream->armor = 0;
      buffer_add_buf(stream->next, z);
      outlen = buffer_size(stream->next);
    }
  }
  else {
    /* yes, successfully decoded it, put into cache */
    buffer_add(stream->next, bin, binlen);
    free(bin);
    outlen = binlen;
  }

  buffer_free(z);
  buffer_free(line);
  ptx_clean(ptx);

  return outlen;
}


size_t ps_write(Pcpstream *stream, void *buf, size_t writebytes) {
  Buffer *z = buffer_new(32, "Pcpwritetemp");

  stream->is_output = 1;

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
	free(aside);
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
    writebytes = outsize;
  }
  else {
    /* buf has been put into the cache only, no writing required */
    buffer_free(z);
  }

  stream->pos += writebytes;

  return writebytes;
}

void ps_write_encode(Pcpstream *stream, Buffer *dst) {
  size_t zlen, i, pos;
  
  /* z85 encode */
  char *z85 = pcp_z85_encode(buffer_get(stream->cache), buffer_size(stream->cache), &zlen, 0);

  /* add newlines */
  pos = stream->linewr;
  for(i=0; i<zlen-1; ++i) {
    if(pos >= 71) {
      buffer_add8(dst, '\r');
      buffer_add8(dst, '\n');
      pos = 1;
    }
    else
      pos++;
    buffer_add8(dst, z85[i]);
  }

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
  if(vasprintf(&dst, fmt, ap) >= 0) {
    va_end(ap);
    size_t len = strlen(dst);

    if(stream->is_buffer) {
      buffer_add(stream->b, dst, len);
    }
    else {
      len = ps_write(stream, dst, len);
    }

    free(dst);
    return len;
  }
  va_end(ap);
  return 0;
}

void ps_close(Pcpstream *stream) {
  if(stream->cache != NULL) {
    if(stream->is_output == 1) {
      if(buffer_left(stream->cache) != 0)
	buffer_info(stream->cache);
      assert(buffer_left(stream->cache) == 0); /* there's something left in the cache, call ps_finish() */
    }
    buffer_free(stream->cache);
  }

  if(stream->next != NULL)
    buffer_free(stream->next);

  buffer_free(stream->save);

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
  /* bail out if we have errors! */
  if(ps_err(stream)) {
    return 1;
  }

  /* simulate open file if there's still something in the cache */
  if(stream->cache != NULL) {
    if(buffer_left(stream->cache) > 0) {
      return 0;
    }
  }

  /* if there's a lookahead buffer, do the same */
  if(buffer_left(stream->save) > 0) {
    return 0;
  }

  return stream->eof;
}

int ps_left(Pcpstream *stream) {
  /* used internally to determine if we reached end of source */
  if(stream->is_buffer) {
    if(buffer_left(stream->b) == 0)
      return 1; /* true, more to read */
    else
      return 0;
  }
  else {
    return feof(stream->fd);
  }
}

int ps_err(Pcpstream *stream) {
  return stream->err;
}

size_t ps_tell(Pcpstream *stream) {
  return stream->pos;
}

Buffer *ps_buffer(Pcpstream *stream) {
  return stream->b;
}

