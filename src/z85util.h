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


#ifndef _HAVE_PCP_Z85
#define _HAVE_PCP_Z85

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "mem.h"
#include "z85.h"
#include "zmq_z85.h"
#include "defines.h"
#include "context.h"

extern PCPCTX *ptx;

int pcpz85_encode(char *infile, char *outfile);
int pcpz85_decode(char *infile, char *outfile);

#endif 
