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

static char *begins[] = {
  /* grep -r BEGIN * | egrep "\.h:" | awk -F '-----' '{print $2}' | sed -e 's/.*BEGIN /"/' -e 's/$/",/' */
  "PCP ENCRYPTED FILE ",
  "Z85 ENCODED FILE ",
  "ED25519 SIGNED MESSAGE ",
  "ED25519 SIGNATURE ",
  "ED25519-CURVE29915 PUBLIC KEY",
  "ED25519-CURVE29915 PRIVATE KEY",
  NULL
};



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
	    break;
	  }
	}
	else 
	  break;
      }
      memset(wide, 0, 4);

      if(utf == 1) {
	/* it's a utf8 char, continue checking, reset wide */
	utf = 0;
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

byte *pcp_z85_decode(PCPCTX *ptx, char *z85block, size_t *dstlen) {
  byte *bin = NULL;
  size_t binlen, outlen; 
  size_t srclen;
 
  srclen = strlen(z85block);

  if(srclen == 0) {
    /* FIXME: check how this happens, pcpstream decoder call */
    *dstlen = 0;
    return NULL;
  }

  binlen = srclen * 4 / 5; 
  bin = ucmalloc(binlen);

  if(zmq_z85_decode(bin, z85block) == NULL) {
    fatal(ptx, "zmq_z85_decode() failed, input size ! mod 5 (got %ld)\n", strlen(z85block));
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


char *pcp_readz85file(PCPCTX *ptx, FILE *infile) {
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
    fatal(ptx, "Input file is empty!\n");
    free(tmp);
    return NULL;
  }

  return pcp_readz85string(ptx, input, bufsize);
}

char *pcp_readz85string(PCPCTX *ptx, unsigned char *input, size_t bufsize) {
  size_t i;
  size_t MAXLINE = 1024;

  if(bufsize == 0) {
    fatal(ptx, "Input file is empty!\n");
    return NULL;
  }

  if(_buffer_is_binary(input, bufsize) > 0) {
    fatal(ptx, "input is not z85 encoded and contains pure binary data\n");
    return NULL;
  }

  Buffer *z = buffer_new(MAXLINE, "z");
  Buffer *line = buffer_new(MAXLINE, "line");
  int begin, end;
  begin = end = 0;
  char *out = NULL;

  for(i=0; i<bufsize; ++i) {
    if(input[i] == '\r')
      continue;
    else if(input[i] == '\n') {
      /* a line is complete */
      if(z85_isbegin(line) && begin == 0) {
	/* a begin header, reset whatever we've got so far in z buffer */
	begin = 1;
	buffer_clear(line);
	buffer_clear(z);
	continue;
      }
      else if(z85_isend(line)){
	/* an end header */
	buffer_clear(line);
	end = 1;
	break;
      }
      else if(z85_isempty(line) || z85_iscomment(line)) {
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
  
  if(buffer_size(line) > 0 && end != 1 && z85_isencoded(line)) {
    /* something left in line buffer, probably
       newline at eof missing or no multiline input */
    buffer_add_buf(z, line);
  }

  if(buffer_size(z) == 0) {
    fatal(ptx, "empty z85 encoded string\n");
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

int z85_isencoded(Buffer *line) {
  /* we don't look for begin header here, do it separately! */
  if(!z85_isend(line) &&
     !z85_isempty(line) &&
     !z85_iscomment(line)) {
    return 1; /* z85 encoded */
  }
  else {
    return 0;
  }
}

int z85_isheader(Buffer *buf) {
  size_t len = buffer_size(buf);
  byte *line = buffer_get(buf);

  if(len < 15) {
    /* minimum requirement: "----- END -----" */
    return 0;
  }
  if(memcmp(line, "-----", 5)) {
    /* doesn't start with hyphens */
    return 0;
  }

  if(memcmp(line+(len-5), "-----", 5)) {
    /* doesn't end with hyphens */
    return 0;
  }

  /* true */
  return 1;
}

long int z85_header_startswith(Buffer *buf, char *what) {
  size_t len = buffer_size(buf);
  byte *line = buffer_get(buf);
  long int offset = 0;

  if((offset = _findoffset(line+6, len-6, what, strlen(what))) >= 0) {
    return offset;
  }

  /* nope */
  return -1;
}

int z85_isend(Buffer *buf) {
  if(! z85_isheader(buf))
    return 0;
  
  if(z85_header_startswith(buf, "END") < 0)
    return 0;

  /* true */
  return 1;
}

int z85_isbegin(Buffer *buf) {
  size_t len;
  size_t blen;
  const char *begin;
  long int offset;
  int i;

  if(! z85_isheader(buf))
    return 0;

  if((offset = z85_header_startswith(buf, "BEGIN")) < 0)
    return 0;

  /* determine type */
  len = buffer_left(buf);
  byte *line = ucmalloc(len); /* FIXME: maybe wrong, check it */
  buffer_get_chunk(buf, line, offset);
  for(i=0; (begin=begins[i]); i++ ) {
    if(begin == NULL) break;
    blen = strlen(begin);
    if(blen <= len)
      if(_findoffset(line+buf->offset, len, (char *)begin, blen) >= 0)
	return i; /* i = ENUM ZBEGINS */
  }

  /* unknown but valid */
  return -1;
}

int z85_iscomment(Buffer *buf) {
  char *line = buffer_get_str(buf);
 
  if(buffer_size(buf) > 0 && strchr(line, ' ') == NULL && strchr(line, '\t') == NULL) {
    return 0; /* non whitespace */
  }
  else {
    return 1; /* true */
  }
}

int z85_isempty(Buffer *buf) {
  byte *line = buffer_get(buf);
  size_t len = buffer_size(buf);
  size_t sp = 0;

  if(len == 0)
    return 1; /* true */

  /* lines with whitespaces only are empty as well */
  while(*line != '\0') {
    if(*line == ' ' || *line == '\t')
      sp++;
    line++;
  }

  if(sp<len)
    return 0; /* non-space chars found */
  else
    return 1; /* true */
}
