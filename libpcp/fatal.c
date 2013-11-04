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


#include "defines.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void fatal(const char * fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  
  vasprintf(&PCP_ERR, fmt, ap);

  va_end(ap);

  PCP_ERRSET = 1;
}

void fatals_reset() {
  PCP_ERRSET = 0;
}

void fatals_ifany() {
  if(PCP_ERRSET == 1) {
    fprintf(stderr, PCP_ERR);
    if(errno) {
      fprintf(stderr, "Error: %s\n", strerror(errno));
    }
    free(PCP_ERR);
    PCP_EXIT = 1;
  }
}
