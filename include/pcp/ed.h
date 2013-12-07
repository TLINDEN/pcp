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

#ifndef _HAVE_PCP_ED_H
#define _HAVE_PCP_ED_H

#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "defines.h"
#include "platform.h"
#include "mem.h"
#include "key.h"

struct _pcp_sig_t {
  byte edsig[crypto_sign_BYTES];
  char id[17];
  uint64_t ctime;
  uint32_t version;
};

typedef struct _pcp_sig_t pcp_sig_t;

int pcp_ed_verify(unsigned char *input, size_t inputlen,
		  pcp_sig_t *sig, pcp_pubkey_t *p);

pcp_sig_t *pcp_ed_sign(unsigned char *message,
			   size_t messagesize, pcp_key_t *s);

pcp_sig_t *sig2native(pcp_sig_t *k);
pcp_sig_t *sig2be(pcp_sig_t *k);

pcp_sig_t *pcp_ed_newsig(unsigned char *hash, char *id);

#endif // _HAVE_PCP_ED_H
