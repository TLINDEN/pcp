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


#ifndef _HAVE_PCP_H
#define _HAVE_PCP_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <compat_getopt.h>

/*  lib */
#include "mem.h"
#include "z85.h"
#include "zmq_z85.h"
#include "z85util.h"
#include "version.h"
#include "vault.h"
#include "context.h"

/*  subs */
#include "keymgmt.h"
#include "usage.h"
#include "encryption.h"
#include "signature.h"
#include "keyhash.h"
#include "plist.h"

/*  operation modi */
/*  perl -e '$x=0; while ($x<100000) { $x++; $x *= 1.7; printf "0x%08X: %d\n", $x, $x }' */
#define PCP_MODE_KEYGEN        0x00000001
#define PCP_MODE_LISTKEYS      0x00000004
#define PCP_MODE_EXPORT_SECRET 0x00000009
#define PCP_MODE_EXPORT_PUBLIC 0x00000011
#define PCP_MODE_IMPORT        0x00000020
#define PCP_MODE_ENCRYPT_ME    0x00000038
#define PCP_MODE_DELETE_KEY    0x00000061
#define PCP_MODE_TEXT          0x000000A6
#define PCP_MODE_EDIT          0x0000011D
#define PCP_MODE_ENCRYPT       0x000001E7
#define PCP_MODE_DECRYPT       0x0000033D
#define PCP_MODE_ZENCODE       0x00000584
#define PCP_MODE_ZDECODE       0x00000962
#define PCP_MODE_SIGN          0x00000FF6
#define PCP_MODE_VERIFY        0x00001B25
#define PCP_MODE_YAML          0x00002E27

/*
0x00001B25
0x00002E27
0x00004E77
0x00008566
0x0000E2CA
0x0001818C
0x00028F70
*/

#define PCP_HELP_INTRO "This is Pretty Curved Privacy. Licensed under the GPLv3. This is\n" \
"BETA software. Use with care. NOT intended for production use.\n"

/* some globals */
vault_t *vault;
PCPCTX *ptx;
int debug;

void version();
void usage();
char *default_vault();

#endif /*  _HAVE_PCP_H */
