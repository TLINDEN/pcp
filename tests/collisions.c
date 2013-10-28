/*
  Run: 
  
  ./col -l 1000000 | sort | uniq -c | sort | grep -v "1 " | wc -l

  This generates the hashes and shows the number of collisions.
  Hash algorithm can be selected by commandline options, see col -h.

  Algorithms from:
  http://eternallyconfuzzled.com/tuts/algorithms/jsw_tut_hashing.aspx
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sodium.h>
#include <limits.h>

// lib
#include "mem.h"
#include "defines.h"
#include "digital_crc32.h"

#define ROUNDS 10

unsigned djb_hash ( void *key, int len ) {
  unsigned char *p = key;
  unsigned h = 0;
  int i;
  
  for ( i = 0; i < len; i++ )
    h = 33 * h ^ p[i];
  
  return h;
}

unsigned fnv_hash ( void *key, int len ) {
  unsigned char *p = key;
  unsigned h = 2166136261;
  int i;
  
  for ( i = 0; i < len; i++ )
    h = ( h * 16777619 ) ^ p[i];
  
  return h;
}

unsigned sax_hash ( void *key, int len ) {
  unsigned char *p = key;
  unsigned h = 0;
  int i;
  
  for ( i = 0; i < len; i++ )
    h ^= ( h << 5 ) + ( h >> 2 ) + p[i];
  
  return h;
}

unsigned oat_hash ( void *key, int len ) {
  unsigned char *p = key;
  unsigned h = 0;
  int i;
 
  for ( i = 0; i < len; i++ ) {
    h += p[i];
    h += ( h << 10 );
    h ^= ( h >> 6 );
  }
 
  h += ( h << 3 );
  h ^= ( h >> 11 );
  h += ( h << 15 );
 
  return h;
}


//#define jen_hashsize(n) ( 1U << (n) )
//#define jen_hashmask(n) ( jen_hashsize ( n ) - 1 )
  
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
 
unsigned jen_hash ( unsigned char *k, unsigned length, unsigned initval ) {
  unsigned a, b;
  unsigned c = initval;
  unsigned len = length;
 
  a = b = 0x9e3779b9;
  
  while ( len >= 12 ) {
    a += ( k[0] + ( (unsigned)k[1] << 8 ) 
	   + ( (unsigned)k[2] << 16 )
	   + ( (unsigned)k[3] << 24 ) );
    b += ( k[4] + ( (unsigned)k[5] << 8 ) 
	   + ( (unsigned)k[6] << 16 )
         + ( (unsigned)k[7] << 24 ) );
    c += ( k[8] + ( (unsigned)k[9] << 8 ) 
	   + ( (unsigned)k[10] << 16 )
	   + ( (unsigned)k[11] << 24 ) );
    
    jen_mix ( a, b, c );
    
    k += 12;
    len -= 12;
  }
  
  c += length;
  
  switch ( len ) {
  case 11: c += ( (unsigned)k[10] << 24 );
  case 10: c += ( (unsigned)k[9] << 16 );
  case 9 : c += ( (unsigned)k[8] << 8 );
    /* First byte of c reserved for length */
  case 8 : b += ( (unsigned)k[7] << 24 );
  case 7 : b += ( (unsigned)k[6] << 16 );
  case 6 : b += ( (unsigned)k[5] << 8 );
  case 5 : b += k[4];
  case 4 : a += ( (unsigned)k[3] << 24 );
  case 3 : a += ( (unsigned)k[2] << 16 );
  case 2 : a += ( (unsigned)k[1] << 8 );
  case 1 : a += k[0];
  }
  
  jen_mix ( a, b, c );
  
  return c;
}







char *keyid(int h, char *id, byte *pub, byte *sec) {
  uint32_t s, p;
  p = s = 0;
  switch (h) {
  case 1:
    p = oat_hash(pub, 32);
    s = oat_hash(sec, 32);
    break;
  case 2:
    p = digital_crc32(pub, 32);
    s = digital_crc32(sec, 32);
    break;
  case 3:
    p = djb_hash(pub, 32);
    s = djb_hash(sec, 32);
    break;
  case 4:
    p = fnv_hash(pub, 32);
    s = fnv_hash(sec, 32);
    break;
  case 5:
    p = sax_hash(pub, 32);
    s = sax_hash(sec, 32);
    break;
  case 6:
    p = jen_hash(pub, 32, 0xd4a1);
    s = jen_hash(sec, 32, 0xe8c0);
    break;
  }
  snprintf(id, 17, "%08X%08X", p, s);
  return id;
}


void usage () {
  fprintf(stderr, "Options:\n");
  fprintf(stderr,  " -o          use Jenkins OAT hashing\n");
  fprintf(stderr,  " -c          use CRC32 checksums\n");
  fprintf(stderr,  " -d          use DJB hash\n");
  fprintf(stderr,  " -s          use SAX hash\n");
  fprintf(stderr,  " -f          use FNV hash \n");
  fprintf(stderr,  " -j          use Jenkins hash \n");
  fprintf(stderr,  " -l <rounds> specify rounds, default: 10\n");
  fprintf(stderr,  " -h   print this help message\n");
  fprintf(stderr,  "When complete, check the output for collisions:\n");
  fprintf(stderr,  "cat hashfile | sort | uniq -c | sort | grep -v \"1 \" | wc -l\n");
  exit(1);
}

int main(int argc, char **argv) {
  byte public[32] = { 0 };
  byte secret[32] = { 0 };
  char *id = ucmalloc(17);
  int i;
  int opt;
  int h = 1;
  long long rounds = ROUNDS;

  while (1) {
    opt = getopt(argc, argv, "jsfdochl:");

    if(opt == -1) {
      break;
    }

    switch (opt)  {
    case 'o':
      h = 1;
      break;
    case 'c':
      h = 2;
      break;
    case 'd':
      h = 3;
      break;
    case 'f':
      h = 4;
      break;
    case 's':
      h = 5;
      break;
    case 'j':
      h = 6;
      break;
    case 'l':
      rounds = strtoll(optarg, NULL, 10);
      break;
    case 'h':
      usage();
    }
  }


  for(i=0; i<rounds; i++) {
    crypto_box_keypair (public, secret);
    id = keyid(h, id, public, secret);
    printf("%s\n", id);
  }

  return 0;
}
