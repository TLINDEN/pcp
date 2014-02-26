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

uint8_t is_utf8(const byte *bytes) {
  if( (// non-overlong 2-byte
       (0xC2 <= bytes[0] && bytes[0] <= 0xDF) &&
       (0x80 <= bytes[1] && bytes[1] <= 0xBF)
       )
      ) {
    return 2;
  }
  
  if( (// excluding overlongs
       bytes[0] == 0xE0 &&
       (0xA0 <= bytes[1] && bytes[1] <= 0xBF) &&
       (0x80 <= bytes[2] && bytes[2] <= 0xBF)
       ) ||
      (// straight 3-byte
       ((0xE1 <= bytes[0] && bytes[0] <= 0xEC) ||
	bytes[0] == 0xEE ||
	bytes[0] == 0xEF) &&
       (0x80 <= bytes[1] && bytes[1] <= 0xBF) &&
       (0x80 <= bytes[2] && bytes[2] <= 0xBF)
       ) ||
      (// excluding surrogates
       bytes[0] == 0xED &&
       (0x80 <= bytes[1] && bytes[1] <= 0x9F) &&
       (0x80 <= bytes[2] && bytes[2] <= 0xBF)
       )
      ) {
    return 3;
  }

  if( (// planes 1-3
       bytes[0] == 0xF0 &&
       (0x90 <= bytes[1] && bytes[1] <= 0xBF) &&
       (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
       (0x80 <= bytes[3] && bytes[3] <= 0xBF)
       ) ||
      (// planes 4-15
       (0xF1 <= bytes[0] && bytes[0] <= 0xF3) &&
       (0x80 <= bytes[1] && bytes[1] <= 0xBF) &&
       (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
       (0x80 <= bytes[3] && bytes[3] <= 0xBF)
       ) ||
      (// plane 16
       bytes[0] == 0xF4 &&
       (0x80 <= bytes[1] && bytes[1] <= 0x8F) &&
       (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
       (0x80 <= bytes[3] && bytes[3] <= 0xBF)
       )
      ) {
    return 4;
  }

  return 0;
}

size_t _buffer_is_binary(byte *buf, size_t len) {
  size_t pos;
  byte wide[4] = {0};
  uint8_t utf = 0;
  int i;

  /* start at 1, to circumvent returning 0 if we find a match at position 0,
     which would lead the caller to believe the buffer is not binary */
  for (pos=1; pos<len; ++pos) {
    if(buf[pos] == '\0' || (buf[pos] != '\r' && buf[pos] != '\n' && isprint(buf[pos]) == 0)) {
      /* it's probably a binary char */

      /* check for utf8 */
      wide[0] = buf[pos];
      for(i=1; i<3; i++) {
	/* check for 2, 3 or 4 byte utf8 char */
	if(pos+i < len) {
	  /* only if there's enough space of course */
	  wide[i] = buf[pos+i];
	  if(is_utf8(wide) > 1) {
	    pos += i; /* jump over the utf we already found */
	    utf = 1;
	  }
	}
	else 
	  break;
      }

      if(utf == 1) {
	/* it's a utf8 char, continue checking, reset wide */
	memset(wide, 0, 4);
	continue;
      }

      break; /* if we reach this, then it's binary and not utf8, stop checking */
    }
  }
  if(pos < len)
    return pos; /* binary */
  else
    return 0; /* text */
}

uint8_t _parse_zchar(Buffer *z, uint8_t c, uint8_t is_comment) {
  if(is_comment == 1) {
    if(c == '~')
      is_comment = 0;
  }
  else {
    if(c == '~')
      is_comment = 1;
    else if(c != '\r' && c != '\n') {
      buffer_add8(z, c);
    }
  }
  return is_comment;
}

byte *pcp_padfour(byte *src, size_t srclen, size_t *dstlen) {
  size_t outlen, zerolen;
  byte *dst;
 
  outlen = srclen;
  while (outlen % 4 != 0) outlen++;
  zerolen = outlen - srclen;

  dst = (byte*)ucmalloc(outlen);
  memcpy(dst, src, srclen); /*  add the original */
  memset(&dst[srclen], 0, zerolen); /*  pad with zeroes  */

  *dstlen = outlen;

  return dst;
}

size_t pcp_unpadfour(byte *src, size_t srclen) {
  size_t outlen;
  long int i;

  outlen = srclen;

  for(i=srclen-1; i>=0; i--) {
    if(src[i] != '\0') {
      outlen = i + 1;
      break;
    }
  }

  return outlen;
}

byte *pcp_z85_decode(char *z85block, size_t *dstlen) {
  byte *bin = NULL;
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

char *pcp_z85_encode(byte *raw, size_t srclen, size_t *dstlen) {
  int pos = 0;
  size_t outlen, blocklen, zlen;

  /*  make z85 happy (size % 4) */
  byte *padded = pcp_padfour(raw, srclen, &outlen);

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
  byte *input = NULL;
  byte *tmp = NULL;
  size_t bufsize = 0;
  byte byte[1];

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

char *pcp_readz85string(byte *input, size_t bufsize) {
  size_t i;
  size_t MAXLINE = 1024;

  if(bufsize == 0) {
    fatal("Input file is empty!\n");
    return NULL;
  }

  if(_buffer_is_binary(input, bufsize) > 0) {
    fatal("input is not z85 encoded and contains pure binary data");
    return NULL;
  }

  Buffer *z = buffer_new(MAXLINE, "z");
  uint8_t is_comment = 0;
  char *out = NULL;

  for(i=0; i<bufsize; ++i)
    is_comment = _parse_zchar(z, input[i], is_comment);
  

  if(buffer_size(z) == 0) {
    fatal("empty z85 encoded string");
    goto rferr;
  }

  out = ucmalloc(buffer_size(z)+1);
  strncpy(out, buffer_get_str(z), buffer_size(z)+1);

  buffer_free(z);

  return out;

 rferr:
  buffer_free(z);

  return NULL;
}
