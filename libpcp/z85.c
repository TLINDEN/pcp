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


#include "z85.h"

unsigned char *pcp_padfour(unsigned char *src, size_t srclen, size_t *dstlen) {
  size_t outlen, zerolen;
  unsigned char *dst;
 
  outlen = srclen;
  while (outlen % 4 != 0) outlen++;
  zerolen = outlen - srclen;

  dst = (unsigned char*)ucmalloc(outlen);
  memcpy(dst, src, srclen); /*  add the original */
  memset(&dst[srclen], 0, zerolen); /*  pad with zeroes  */

  *dstlen = outlen;

  return dst;
}

size_t pcp_unpadfour(unsigned char *src, size_t srclen) {
  size_t outlen;
  size_t i;

  outlen = srclen;

  for(i=srclen-1; i>0; --i) {
    if(src[i] != '\0') {
      outlen = i + 1;
      break;
    }
  }

  return outlen;
}

unsigned char *pcp_z85_decode(char *z85block, size_t *dstlen) {
  unsigned char *bin = NULL;
  size_t binlen, outlen; 

  binlen = strlen(z85block) * 4 / 5; 
  bin = ucmalloc(binlen);

  if(zmq_z85_decode(bin, z85block) == NULL) {
    fatal("zmq_z85_decode() failed, input size ! mod 5 (got %ld)", strlen(z85block));
    return NULL;
  }

  outlen = pcp_unpadfour(bin, binlen);

  *dstlen = outlen;

  return bin;
}

char *pcp_z85_encode(unsigned char *raw, size_t srclen, size_t *dstlen) {
  int pos = 0;
  size_t outlen, blocklen, zlen;

  /*  make z85 happy (size % 4) */
  unsigned char *padded = pcp_padfour(raw, srclen, &outlen);

  /*  encode to z85 */
  zlen = (outlen * 5 / 4) + 1;
  char *z85 = ucmalloc(zlen);
  z85 = zmq_z85_encode(z85, padded, outlen);


  /*  make it a 72 chars wide block */
  blocklen = (zlen + ((zlen / 72) * 2)) + 1;
  char *z85block = ucmalloc(blocklen);

  char *z = &z85[0];
  char *B = &z85block[0];

  while(*z != '\0') {
    if(pos >= 71) {
      *B++ = '\r';
      *B++ = '\n';
      pos = 1;
    }
    else {
      pos++;
    }
    *B++ = *z++;
  }
  *B = '\0';

  *dstlen = blocklen;
  free(z85); 
  free(padded);

  return z85block;
}


char *pcp_readz85file(FILE *infile) {
  unsigned char *input = NULL;
  unsigned char *tmp = NULL;
  size_t bufsize = 0;
  unsigned char byte[1];

  while(!feof(infile)) {
    if(!fread(&byte, 1, 1, infile))
      break;
    if(ferror(infile) != 0)
      break;
    tmp = realloc(input, bufsize + 1);
    input = tmp;
    memmove(&input[bufsize], byte, 1);
    bufsize ++;
  }

  if(bufsize == 0) {
    fatal("Input file is empty!\n");
    free(tmp);
    return NULL;
  }

  return pcp_readz85string(input, bufsize);
}

char *pcp_readz85string(unsigned char *input, size_t bufsize) {
  int i;
  size_t MAXLINE = 1024;

  Buffer *z = buffer_new(MAXLINE, "z");
  Buffer *line = buffer_new(MAXLINE, "line");
  char *oneline;
  int begin, end;
  begin = end = 0;
  char *out = NULL;

  for(i=0; i<bufsize; ++i) {
    if(input[i] == '\r')
      continue;
    else if(input[i] == '\n') {
      /* a line is complete */
      oneline = buffer_get_str(line);
      if(strncmp(oneline, "-----", 5) == 0 ) {
	if(begin == 0) {
	/* a begin header, reset whatever we've got so far in z buffer */
	  begin = 1;
	  buffer_clear(line);
	  buffer_clear(z);
	  continue;
	}
	else {
	  /* an end header */
	  end = 1;
	  break;
	}
      }
      else if(strchr(oneline, ' ') != NULL) {
	/* a comment */
	buffer_clear(line);
	continue;
      }
      else {
	/* regular z85 encoded content */
	buffer_add_buf(z, line);
	buffer_clear(line);
      }
    }
    else {
      /* regular line content */
      buffer_add8(line, input[i]);
    }
  }

  if(buffer_size(line) > 0 && end != 1) {
    /* something left in line buffer, probably
       newline at eof missing or no multiline input */
    buffer_add_buf(z, line);  
  }

  if(buffer_size(z) == 0) {
    fatal("empty z85 encoded string");
    goto rferr;
  }

  out = ucmalloc(buffer_size(z)+1);
  strncpy(out, buffer_get_str(z), buffer_size(z)+1);

  buffer_free(z);
  buffer_free(line);

  return out;

 rferr:
  buffer_free(z);
  buffer_free(line);

  return NULL;
}
