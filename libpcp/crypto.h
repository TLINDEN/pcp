#ifndef _HAVE_PCP_CRYPTO_H
#define _HAVE_PCP_CRYPTO_H

#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <sodium.h>
#include <stdlib.h>

#include "defines.h"
#include "mem.h"
#include "key.h"

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

#endif // _HAVE_PCP_CRYPTO_H
