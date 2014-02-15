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


#ifndef _HAVE_ENCRYPTION_H
#define _HAVE_ENCRYPTION_H

#include <stdio.h>
#include <string.h>

#include "defines.h"
#include "key.h"
#include "crypto.h"
#include "pcp.h"
#include "uthash.h"
#include "z85.h"
#include "keyprint.h"
#include "keyhash.h"
#include "plist.h"
#include "pcpstream.h"

int pcpdecrypt(char *id, int useid, char *infile, char *outfile, char *passwd, int verify);
int pcpencrypt(char *id, char *infile, char *outfile, char *passwd, plist_t *recipient, int signcrypt);

#endif /*  _HAVE_ENCRYPTION_H */
