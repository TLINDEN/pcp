/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013 T.Linden.

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

    You can contact me by mail: <tlinden AT cpan DOT org>.
*/


#include "z85.h"

unsigned char *pcp_padfour(unsigned char *src, size_t srclen, size_t *dstlen) {
  size_t outlen, zerolen;
  unsigned char *dst;
 
  outlen = srclen + 1; // 1 for the pad flag
  while (outlen % 4 != 0) outlen++;
  zerolen = outlen - (srclen + 1);

  dst = (unsigned char*)ucmalloc(outlen);
  dst[0] = zerolen;             // add the number of zeros we add
  memcpy(&dst[1], src, srclen); // add the original
  memset(&dst[srclen+1], 0, zerolen); // pad with zeroes 

  *dstlen = outlen;

  return dst;
}

unsigned char *pcp_unpadfour(unsigned char *src, size_t srclen, size_t *dstlen) {
  size_t outlen;
  size_t numzeroes;
  unsigned char *dst;

  numzeroes = src[0];  // first byte tells us how many zeroes we've got
  outlen = srclen - 1 - numzeroes;
  
  dst = malloc(outlen);

  memcpy(dst, &src[1], outlen);

  *dstlen = outlen;

  return dst;
}

unsigned char *pcp_z85_decode(char *z85block, size_t *dstlen) {
  unsigned char *bin;
  int i, pos;
  size_t zlen, binlen, outlen; 

  zlen = strlen(z85block);
  char *z85 = ucmalloc(zlen+1);

  // remove newlines
  pos = 0;
  for(i=0; i<zlen+1; ++i) {
    if(z85block[i] != '\r' && z85block[i] != '\n') {
      z85[pos] = z85block[i];
      pos++;
    }
  }

  binlen = strlen (z85) * 4 / 5; 
  bin = ucmalloc(binlen);
  bin = zmq_z85_decode(bin, z85);

  unsigned char *raw = NULL;
  if(bin != NULL) {
    raw = pcp_unpadfour(bin, binlen, &outlen);
  }

  free(z85);
  free(bin); 

  *dstlen = outlen;
  return raw;
}

char *pcp_z85_encode(unsigned char *raw, size_t srclen, size_t *dstlen) {
  int pos, b;
  size_t outlen, blocklen, zlen;

  // make z85 happy (size % 4)
  unsigned char *padded = pcp_padfour(raw, srclen, &outlen);

  // encode to z85
  zlen = (outlen * 5 / 4) + 1;
  char *z85 = ucmalloc(zlen);
  z85 = zmq_z85_encode(z85, padded, outlen);


  // make it a 72 chars wide block
  blocklen = (zlen + ((zlen / 72) * 2)) + 1;
  char *z85block = ucmalloc(blocklen);

  //fprintf(stderr, "zlen: %d, outlen: %d, srclen: %d, blocklen: %d\n",
  //	  zlen, outlen, srclen, blocklen);

  pos = b = 0;
  /*
  for(i=0; i<zlen; ++i) {
    if(pos >= 71) {
      *z85block++ = '\r';
      *z85block++ = '\n';
      pos = 1;
    }
    else {
      pos++;
    }
    *z85block++ = z85[i];
  }
  */

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

  //fprintf(stderr, "z85block len: %d\n", blocklen, strlen(z85block));
  //fprintf(stderr, "z85block: <%s>\n", z85block);

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
  char *ret;
  int i, outsize, lpos, x;
  lpos = outsize = 0;
  size_t MAXLINE = 1024;

  unsigned char *out = ucmalloc(bufsize);
  char *line = ucmalloc(MAXLINE);

  for(i=0; i<bufsize; ++i) {
    if(lpos > MAXLINE) {
      // huh, now that's suspicious
      fatal("Invalid input, line is too long (%d bytes so far)!\n", lpos);
      goto rferr;
    }
    if(input[i] != '\n' && input[i] != '\r') {
      line[lpos++] = input[i];
    }
    else {
      if(line[0] != ' ' && strncmp(line, "-----", 5) != 0) {
	if(lpos > 0) {
	  for(x=0;x<lpos;++x) 
	    out[outsize+x] = line[x];
	  outsize += lpos;
	  lpos = 0;
	}
      }
      else {
	lpos = 0;
      }
    }
  }

  out[outsize+1] = '\0';

  ret = ucmalloc(outsize+1);
  memcpy(ret, out, outsize+1);

  free(out);
  free(line);

  return ret;

 rferr:
  free(out);
  free(line);

  return NULL;
}
