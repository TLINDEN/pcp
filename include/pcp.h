#ifndef _HAVE_PCP
#define _HAVE_PCP

#ifdef __cplusplus
extern "C" {
#endif

#include <err.h>
#include <errno.h>
#include <inttypes.h>   /* uint32_t */
#include <limits.h>
#include <sodium.h>
#include <stddef.h>   /* ptrdiff_t */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>   /* exit() */
#include <string.h>
#include <string.h>   /* memcmp,strlen */
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include CONFIG_H_FILE

// +++ from libpcp/crypto.h: +++




size_t pcp_sodium_box(unsigned char **cipher,
                      unsigned char *cleartext,
                      size_t clearsize,
                      unsigned char *nonce,
                      unsigned char *secret,
                      unsigned char *public);

int pcp_sodium_verify_box(unsigned char **cleartext, unsigned char* message,
                          size_t messagesize, unsigned char *nonce,
                          unsigned char *secret, unsigned char *public);

unsigned char *pcp_box_encrypt(pcp_key_t *secret, pcp_pubkey_t *public,
                               unsigned char *message, size_t messagesize,
			       size_t *csize);

unsigned char *pcp_box_decrypt(pcp_key_t *secret, pcp_pubkey_t *public,
                               unsigned char *cipher, size_t ciphersize,
			       size_t *dsize);


// +++ from libpcp/getpass.h: +++


/*
 * (unportable) functions to turn on/off terminal echo
 * using termios functions. might compile however on
 * most unices, tested on FreeBSD only.
 */




void pcp_echo_off();
void pcp_echo_on();
char *pcp_get_stdin();
char *pcp_get_passphrase(char *prompt);


// +++ from libpcp/key.h: +++


#ifdef __cplusplus
extern "C" {
#endif



/*
  PCP private key structure. Most fields are self explanatory.
  Some notes:

  'encrypted' contains the encrypted secret key. If it's set,
  the field 'secret' which contains the clear secret key will
  be zeroed with random values, the first byte will be 0.

  'nonce' contains the nonce required to decrypt the encrypted
  secret, if set.

  'serial' is a random number.

  'id' is a string containing the hex values of the CRC32 checksum
  of the public and secret key.

  Upon creation everything will be filled with random bytes.
  String fields will contain a string followed by 0 followed
  by the rest of the pre-filled random bytes. To denote a string
  field as empty, the first byte will be set to 0.

  There are dynamically calculated attributes as well:

  'checksum' is a 256 bit SHA hash of the public key returned
  by pcpkey_getchecksum() or pcppubkey_getchecksum().

  'random id' is a random art ascii image returned by
  pcppubkey_get_art() or pcpkey_get_art(), calculated from
  the public key.

  If exported to a single file or printed, the structure will
  be encoded using Z85 encoding.

 */
struct _pcp_key_t {
  byte public[32];
  byte secret[32];
  byte nonce[24];
  byte encrypted[48];
  char owner[255];
  char mail[255];
  char id[17];
  long ctime;
  uint32_t version;
  uint32_t serial;
  uint8_t type;
  UT_hash_handle hh;
};

struct _pcp_pubkey_t {
  byte public[32];
  char owner[255];
  char mail[255];
  char id[17];
  long ctime;
  uint32_t version;
  uint32_t serial;
  uint8_t type;
  UT_hash_handle hh;
};

typedef struct _pcp_key_t pcp_key_t;
typedef struct _pcp_pubkey_t pcp_pubkey_t;

pcp_key_t *pcpkey_hash;
pcp_pubkey_t *pcppubkey_hash;

void pcp_cleanhashes();
pcp_key_t *pcpkey_new ();

char *pcppubkey_get_art(pcp_pubkey_t *k);
char *pcpkey_get_art(pcp_key_t *k);

pcp_key_t *pcpkey_encrypt(pcp_key_t *key, char *passphrase);
pcp_key_t *pcpkey_decrypt(pcp_key_t *key, char *passphrase);
pcp_pubkey_t *pcpkey_pub_from_secret(pcp_key_t *key);
char *pcp_getkeyid(pcp_key_t *k);
unsigned char *pcppubkey_getchecksum(pcp_pubkey_t *k);
unsigned char *pcpkey_getchecksum(pcp_key_t *k);
void pcp_inithashes();

pcp_key_t *pcpkey_exists(char *id);
pcp_pubkey_t *pcppubkey_exists(char *id);

pcp_key_t * key2be(pcp_key_t *k);
pcp_key_t *key2native(pcp_key_t *k);
pcp_pubkey_t * pubkey2be(pcp_pubkey_t *k);
pcp_pubkey_t *pubkey2native(pcp_pubkey_t *k);

unsigned char * pcp_gennonce();

void pcpedit_key(char *keyid);

// proprietary key derivation function. derives an
// secure encryption key from the given passphrase by
// calculating a SALSA20 hash from it HCYCLES times.
// 
// turns the result into a proper CURVE25519 secret
// key. allocates memory for key and it is up to the
// user to free it after use.
// 
// deprecation warning: maybe removed once the libsodium
// developers incorporated some key derivation function
// into libsodium. so far, there's none but word goes
// that perhaps something like scrypt() from the star
// distribution may be added in the future.
unsigned char *pcp_derivekey(char *passphrase);

pcp_key_t *pcp_derive_pcpkey (pcp_key_t *ours, char *theirs);

#ifdef __cplusplus
}
#endif


// +++ from libpcp/mac.h: +++




// how many times do we hash the passphrase
#define HCYCLES 128000

// encrypt some arbitrary cleartext using
// a curve25519 secret key  and a given nonce.
//
// expects a pointer to the target binary
// stream containing the encrypted data,
// the cleartext string, its size, the nonce
// (24 bytes) and the secret key (32 bytes).
//
// allocates memory for the returned cipher
// and it is up to the user to free it after use.
//
// returns the size of the returned cipherstream.
// in case of an error, the cipher will be set
// to NULL.
size_t pcp_sodium_mac(unsigned char **cipher,
                      unsigned char *cleartext,
                      size_t clearsize,
                      unsigned char *nonce,
                      unsigned char *key);

// does the opposite of pcp_sodium_mac and decrypts
// a given encrypted binary stream using a nonce and
// a secret key (sizes: see above).
//
// allocates memory for the returned cleartext and
// it is up to the user to free it after use.
//
// returns 0 if decryption and verification were
// successful, otherwise -1. 
int pcp_sodium_verify_mac(unsigned char **cleartext,
                          unsigned char* message,
                          size_t messagesize,
                          unsigned char *nonce,
                          unsigned char *key);





// +++ from libpcp/mem.h: +++



// simple malloc()  wrapper 
// behaves like calloc(), which
// I don't have here.
// 
// exits if there's no more memory
// available.
void *ucmalloc(size_t s);

// the same but it fills the pointer with random values
void *urmalloc(size_t s);

// dito.
void *ucfree(void *ptr);



// +++ from libpcp/pad.h: +++




#ifdef DEBUG
#define ZPADCHAR 48
#else
#define ZPADCHAR 0
#endif

// prepends a binary stream with a number of
// \0's as required by the secret_box and
// secret_box_open functions of libsodium.
//
// parameters:
//
// padded:    destination array (ref)
// unpadded:  source array without padding
// padlen:    length of padding
// unpadlen:  length of source array
//
// turns "efa5" into "00000000efa5" with padlen 8
//
// if DEBUG is set, destination will be padded with
// the character '0', NOT the integer 0.
//
// allocates memory for padded and it is up to the
// user to free it after use.
//
// sample call:
//
// char unpadded[] = {0xef, 0xa5};
// unsigned char *padded;
// pcp_pad_prepend(&padded, unpadded, 8, 2);
//
// the result, padded, would be 10 bytes long, 8
// bytes for the leading zeros and 2 for the content
// of the original unpadded.
void pcp_pad_prepend(unsigned char **padded, unsigned char *unpadded,
		 size_t padlen, size_t unpadlen);

// removes zero's of a binary stream, which is
// the reverse of pcp_pad_prepend().
//
// parameters:
// 
// unpadded:   destination array (ref), with padding removed
// padded:     source array with padding
// padlen:     length of padding
// unpadlen:   length of source array
//
// turns "00000000efa5" into "efa5" with padlen 8
//
// allocates memory for unpadded and it is up to the
// user to free it after use.
//
// sample call:
//
// char padded[] = {0x0, 0x0, 0x0, 0x0, 0xef, 0xa5};
// unsigned char *unpadded;
// pcp_pad_remove(unpadded, padded, 4, 2);
//
// the result, unpadded would be 2 bytes long containing
// only the 2 bytes we want to have with zeros removed.
void pcp_pad_remove(unsigned char **unpadded, unsigned char *padded,
		size_t padlen, size_t unpadlen);



// +++ from libpcp/platform.h: +++


#if defined(CONFIG_H_FILE)
#elif defined(HAVE_CONFIG_H)
#else
#error Need either CONFIG_H_FILE or HAVE_CONFIG_H defined.
#endif

#ifdef HAVE_ENDIAN_H
# include <endian.h>
#else // no endian.h
# ifdef HAVE_SYS_ENDIAN_H
#   include <sys/endian.h>
#   ifdef HAVE_BETOH32
      // openbsd, use aliases
#     define be32toh betoh32
#     define htobe32 hto32be
#   endif
# else // no sys/endian.h
#   if __BYTE_ORDER == __BIG_ENDIAN
#     define be32toh(x)	((void)0)
#     define htobe32(x)	((void)0)
#   else
#     ifdef HAVE_ARPA_INET_H
#       include <arpa/inet.h>
#     else
#       ifdef HAVE_NETINET_IN_H
#         include <netinet/in.h>
#       else
#         error Need either netinet/in.h or arpa/inet.h for ntohl() and htonl()
#       endif
#     endif
#     define be32toh(x)	((u_int32_t)ntohl((u_int32_t)(x)))
#     define htobe32(x)	((u_int32_t)htonl((u_int32_t)(x)))
#   endif
#  endif // HAVE_SYS_ENDIAN_H
#endif // HAVE_ENDIAN_H


#ifndef HAVE_ARC4RANDOM_BUF
// shitty OS. we've got to use other stuff


static inline FILE *__getranddev() {
  FILE *R;
  if((R = fopen("/dev/urandom", "rb")) == NULL) {
    // not even this is here! what a shame
    if((R = fopen("/dev/random", "rb")) == NULL) {
      // not available or depleted. that's too bad
      fprintf(stderr, "ERROR: /dev/urandom not available, /dev/random is depleted.\n");
      fprintf(stderr, "That's horrible for you but a nightmare for me. I die. Bye.\n");
      exit(2);
    }
  }
  return R;
}

static inline u_int32_t arc4random() {
  uint32_t x;
  FILE *R = __getranddev();
  fread(&x, sizeof(uint32_t), 1, R);
  fclose(R);
  return x;
}

static inline void arc4random_buf(void *buf, size_t nbytes) {
  FILE *R = __getranddev();
  fread(buf, nbytes, 1, R);
  fclose(R);
}


#endif




// +++ from libpcp/randomart.h: +++

/* $OpenBSD: key.c,v 1.70 2008/06/11 21:01:35 grunk Exp $ */
/*
 * read_bignum():
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// key_fingerprint_randomart comitted by Alexander von Gernler in rev 1.70



// from openssh key.c

#ifndef MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
# define MIN(a,b) (((a)<(b))?(a):(b))
#endif


char *key_fingerprint_randomart(unsigned char *dgst_raw, unsigned int dgst_raw_len);


// +++ from libpcp/vault.h: +++





struct _vault_t {
  char *filename;
  FILE *fd;
  uint8_t unsafed;
  uint8_t isnew;
  uint32_t size;
  time_t modified;
  mode_t mode;
  uint32_t version;
  byte checksum[32];
};

struct _vault_header_t {
  byte fileid;
  uint32_t version;
  byte checksum[32];
};

struct _vault_item_header_t {
  byte type;
  uint32_t size;
  uint32_t version;
  byte checksum[32];
};

typedef struct _vault_t vault_t;
typedef struct _vault_header_t vault_header_t;
typedef struct _vault_item_header_t vault_item_header_t;

vault_t *pcpvault_init(char *filename);
vault_t *pcpvault_new(char *filename, int is_tmp);
int pcpvault_create(vault_t *vault);
int pcpvault_additem(vault_t *vault, void *item, size_t itemsize, uint8_t type, uint8_t do_hash);
int pcpvault_close(vault_t *vault);
int pcpvault_fetchall(vault_t *vault);
int pcpvault_writeall(vault_t *vault);
void pcpvault_copy(vault_t *tmp, vault_t *vault);
void pcpvault_unlink(vault_t *tmp);
unsigned char *pcpvault_create_checksum(vault_t *vault);
void pcpvault_update_checksum(vault_t *vault);

vault_header_t * vh2be(vault_header_t *h);
vault_header_t * vh2native(vault_header_t *h);
vault_item_header_t * ih2be(vault_item_header_t *h);
vault_item_header_t * ih2native(vault_item_header_t *h);


// +++ from libpcp/version.h: +++


#define PCP_VERSION_MAJOR 0
#define PCP_VERSION_MINOR 0
#define PCP_VERSION_PATCH 1

#define PCP_MAKE_VERSION(major, minor, patch) \
    ((major) * 10000 + (minor) * 100 + (patch))
#define PCP_VERSION \
    PCP_MAKE_VERSION(PCP_VERSION_MAJOR, PCP_VERSION_MINOR, PCP_VERSION_PATCH)

int pcp_version();


// +++ from libpcp/z85.h: +++

// from https://github.com/tlinden/curve-keygen/


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

#ifdef __cplusplus
}
#endif


#endif
