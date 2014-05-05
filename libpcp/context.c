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

#define _GNU_SOURCE /* vasprintf() linux */


#include "context.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

PCPCTX *ptx_new() {
  PCPCTX *p = ucmalloc(sizeof(PCPCTX));
  p->pcp_err = NULL;
  p->pcp_errset = 0;
  p->pcp_exit = 0;
  p->verbose = 0;
  p->pcpkey_hash = NULL;
  p->pcppubkey_hash = NULL;
  p->pcpkeysig_hash = NULL;

  return p;
}

void ptx_clean(PCPCTX *ptx) {
  if(ptx->pcp_errset)
    free(ptx->pcp_err);

  pcphash_clean(ptx);

  free(ptx);
}


void fatal(PCPCTX *ptx, const char * fmt, ...) {
  va_list ap;
  va_start(ap, fmt);

  char *err = NULL;//ptx->pcp_err;
  
  if(vasprintf(&err, fmt, ap) >= 0) {
    va_end(ap);
    ptx->pcp_errset = 1;
    if(ptx->pcp_err != NULL) {
      free(ptx->pcp_err);
    }
    ptx->pcp_err = err;
  }
  else {
    fprintf(stderr, "Could not store fatal error message %s!\n", fmt);
    ptx->pcp_errset = 1;
  }
}

void fatals_reset(PCPCTX *ptx) {
  ptx->pcp_errset = 0;
}

void fatals_ifany(PCPCTX *ptx) {
  if(ptx->pcp_errset == 1) {
    fprintf(stderr, "%s", ptx->pcp_err);
    if(errno) {
      fprintf(stderr, "Error: %s\n", strerror(errno));
    }
    ptx->pcp_exit = 1;
  }
}

void final(const char * fmt, ...) {
  va_list ap;
  va_start(ap, fmt);

  char *err = NULL;
  
  if(vasprintf(&err, fmt, ap) >= 0) {
    va_end(ap);
  }

  fprintf(stderr, "ABORT: %s", err);

  abort();
}
