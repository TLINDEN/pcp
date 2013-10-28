// from https://github.com/tlinden/curve-keygen/
#ifndef _HAVE_PCP_Z85_H

#include "defines.h"
#include "zmq_z85.h"
#include "mem.h"

// convert a binary stream to one which gets accepted by zmq_z85_encode
// we pad it with zeroes and put the number of zerores in front of it 
unsigned char *pcp_unpadfour(unsigned char *src, size_t srclen, size_t *dstlen);

// the reverse of the above
unsigned char *pcp_unpadfour(unsigned char *src, size_t srclen, size_t *dstlen);

// wrapper around zmq Z85 encoding function
unsigned char *pcp_z85_decode(char *z85block, size_t *dstlen);

// the reverse of the above
char *pcp_z85_encode(unsigned char *raw, size_t srclen, size_t *dstlen);

char *pcp_readz85file(FILE *infile);

#endif // _HAVE_PCP_Z85_H
