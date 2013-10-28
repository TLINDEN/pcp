#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sodium.h>
#include <limits.h>

#include "mem.h"
#include "defines.h"
#include "keyprint.h"
#include "key.h"
#include "vault.h"

void mkinv(pcp_key_t *k, int type);
void mkinvp(pcp_pubkey_t *k, int type);
void mkinvv(const char *name, int type);
FILE *F(char *filename);

void pr(char *t, unsigned char *b, size_t s);
