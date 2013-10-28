#ifndef _HAVE_PCP_KEYPRINT_H
#define _HAVE_PCP_KEYPRINT_H

#include "mem.h"
#include "key.h"
#include "vault.h"

void pcp_dumpkey(pcp_key_t *k);
void pcp_dumppubkey(pcp_pubkey_t *k);

void pcpkey_print(pcp_key_t *key, FILE *out);
void pcppubkey_print(pcp_pubkey_t *key, FILE *out);

void pcpkey_printshortinfo(pcp_key_t *key);
void pcppubkey_printshortinfo(pcp_pubkey_t *key);

void pcpkey_printlineinfo(pcp_key_t *key);
void pcppubkey_printlineinfo(pcp_pubkey_t *key);

void pcptext_key(char *keyid);
void pcptext_vault(vault_t *vault);

#endif // _HAVE_PCP_KEYPRINT_H
