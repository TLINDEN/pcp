/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013-2016 T.v.Dein.

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

    You can contact me by mail: <tom AT vondein DOT org>.
*/


#ifndef _HAVE_PCP_KEYSIG_H
#define _HAVE_PCP_KEYSIG_H

#include <string.h>
#include <stdio.h>

#include "defines.h"
#include "platform.h"
#include "mem.h"
#include "structs.h"
#include "buffer.h"
#include "key.h"

#define PCP_RAW_KEYSIGSIZE sizeof(pcp_keysig_t) - sizeof(UT_hash_handle)

/* put a keysig into a buffer, convert to big endian while at it */
void pcp_keysig2blob(Buffer *b, pcp_keysig_t *s);

/* same, but allocs buffer */
Buffer *pcp_keysigblob(pcp_keysig_t *s);

/* fetch a keysig from a buffer, usually loaded from vault */
pcp_keysig_t *pcp_blob2keysig(Buffer *blob);

/* debug print a keysig */
void pcp_dumpkeysig(pcp_keysig_t *s);

#endif /*  _HAVE_PCP_KEYSIG_H */
