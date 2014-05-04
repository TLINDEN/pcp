/*

Source from GIT
Licensed under the terms of the LGPL 2.1.

*/

#ifndef HAVE_BASE85_H
#define HAVE_BASE85_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "defines.h"
#include "context.h"

#undef DEBUG_85

#ifdef DEBUG_85
#define say(a) fprintf(stderr, a)
#define say1(a,b) fprintf(stderr, a, b)
#define say2(a,b,c) fprintf(stderr, a, b, c)
#else
#define say(a) do { /* nothing */ } while (0)
#define say1(a,b) do { /* nothing */ } while (0)
#define say2(a,b,c) do { /* nothing */ } while (0)
#endif


int decode_85(PCPCTX *ptx, char *dst, const char *buffer, int len);
void encode_85(char *buf, const unsigned char *data, int bytes);

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#define error(...) (fatal(ptx, __VA_ARGS__), -1)

#endif /*  HAVE_BASE85_H */
