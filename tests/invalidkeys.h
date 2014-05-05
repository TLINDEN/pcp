#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <limits.h>

#include "mem.h"
#include "defines.h"
#include "keyprint.h"
#include "key.h"
#include "vault.h"

void mkinvalid_secret(PCPCTX *ptx, pcp_key_t *k, int type);
void mkinvalid_public(pcp_key_t *k, int type);
void mkinvv(PCPCTX *ptx, const char *name, int type);
FILE *F(char *filename);

void pr(char *t, unsigned char *b, size_t s);
