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

#ifndef _HAVE_SIGNATURE_H
#define _HAVE_SIGNATURE_H

#include <stdio.h>
#include <string.h>

#include "defines.h"
#include "key.h"
#include "ed.h"
#include "pcp.h"
#include "uthash.h"
#include "z85.h"
#include "pcpstream.h"
#include "context.h"

int pcpsign(char *infile, char *outfile, char *passwd, int z85, int detach);
int pcpverify(char *infile, char *sigfile, char *id, int detach);



#endif /*  _HAVE_SIGNATURE_H */
