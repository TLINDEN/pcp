/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013 T.Linden.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    You can contact me by mail: <tlinden AT cpan DOT org>.
*/


#ifndef _HAVE_KEYMGMT_H
#define _HAVE_KEYMGMT_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <wctype.h>

#include "randomart.h"
#include "key.h"
#include "pcp.h"
#include "vault.h"
#include "defines.h"
#include "readpass.h"
#include "keyprint.h"
#include "keyhash.h"
#include "util.h"
#include "buffer.h"
#include "mgmt.h"
#include "context.h"

#define _WITH_GETLINE

char *pcp_getstdin(const char *prompt);
int pcp_storekey (pcp_key_t *key);
void pcp_keygen(char *passwd);
void pcp_listkeys();

void pcp_exportsecret(char *keyid, int useid, char *outfile, int armor, char *passwd);
void pcp_exportpublic(char *keyid, char *passwd, char *outfile, int format, int armor);

pcp_key_t *pcp_getrsk(pcp_key_t *s, char *recipient, char *passwd);
char *pcp_normalize_id(char *keyid);
pcp_key_t *pcp_find_primary_secret();

int pcp_import (vault_t *vault, FILE *in, char *passwd);

void pcpdelete_key(char *keyid);
char *pcp_find_id_byrec(char *recipient);
void pcpedit_key(char *keyid);

#endif /*  _HAVE_KEYMGMT_H */
