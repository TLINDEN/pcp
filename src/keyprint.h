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


#ifndef _HAVE_PCP_KEYPRINT_H
#define _HAVE_PCP_KEYPRINT_H

#include "mem.h"
#include "key.h"
#include "vault.h"
#include "pcp.h"
#include "keymgmt.h"
#include "keyhash.h"
#include "base85.h"

void pcpkey_print(pcp_key_t *key, FILE *out);
void pcppubkey_print(pcp_pubkey_t *key, FILE *out);

void pcpkey_printshortinfo(pcp_key_t *key);
void pcppubkey_printshortinfo(pcp_pubkey_t *key);

void pcpkey_printlineinfo(pcp_key_t *key);
void pcppubkey_printlineinfo(pcp_pubkey_t *key);

void pcptext_key(char *keyid);
void pcptext_vault(vault_t *vault);
int pcptext_infile(char *infile);

void pcpexport_yaml(char *outfile);
void pcpprint_bin(FILE *out, unsigned char *data, size_t len);

#endif /*  _HAVE_PCP_KEYPRINT_H */
