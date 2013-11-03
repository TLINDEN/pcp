#ifndef _HAVE_KEYMGMT_H
#define _HAVE_KEYMGMT_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "randomart.h"
#include "mac.h"
#include "key.h"
#include "pcp.h"
#include "vault.h"
#include "defines.h"
#include "readpass.h"
#include "keyprint.h"

#define _WITH_GETLINE

char *pcp_getstdin(const char *prompt);
int pcp_storekey (pcp_key_t *key);
void pcp_keygen();
void pcp_listkeys();
void pcp_exportsecret(char *keyid, int useid, char *outfile);
pcp_key_t *pcp_getrsk(pcp_key_t *s, char *recipient, char *passwd);
void pcp_exportpublic(char *keyid, char *recipient, char *passwd, char *outfile);
char *pcp_normalize_id(char *keyid);
pcp_key_t *pcp_find_primary_secret();
int pcp_importpublic (vault_t *vault, FILE *in);
int pcp_sanitycheck_pub(pcp_pubkey_t *key);
int pcp_importsecret (vault_t *vault, FILE *in);
int pcp_sanitycheck_key(pcp_key_t *key);
void pcpdelete_key(char *keyid);
char *pcp_find_id_byrec(char *recipient);

#endif // _HAVE_KEYMGMT_H
