#ifndef _HAVE_JENHASH_H
#define _HAVE_JENHASH_H

// Bob Jenkins 32bit hash function
// via: http://eternallyconfuzzled.com/tuts/algorithms/jsw_tut_hashing.aspx

#define jen_mix(a,b,c)				\
  {						\
    a -= b; a -= c; a ^= ( c >> 13 );		\
    b -= c; b -= a; b ^= ( a << 8 );		\
    c -= a; c -= b; c ^= ( b >> 13 );		\
    a -= b; a -= c; a ^= ( c >> 12 );		\
    b -= c; b -= a; b ^= ( a << 16 );		\
    c -= a; c -= b; c ^= ( b >> 5 );		\
    a -= b; a -= c; a ^= ( c >> 3 );		\
    b -= c; b -= a; b ^= ( a << 10 );		\
    c -= a; c -= b; c ^= ( b >> 15 );		\
  }

#define JEN_PSALT 0xD9A03
#define JEN_SSALT 0xC503B

unsigned jen_hash ( unsigned char *k, unsigned length, unsigned initval );

#endif // _HAVE_JENHASH_H
