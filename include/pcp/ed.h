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

/*
 ED25519 signatures. Currently unbuffered
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
#include "keyhash.h"
#include "util.h"

/* sign a message of messagesize using s->edsecret, if it works
   return message+signature (size: messagesize + crypto_sign_BYTES),
   returns NULL otherwise */
unsigned char *pcp_ed_sign(unsigned char *message, size_t messagesize, pcp_key_t *s);

/* verify a signature of siglen size using p->edpub, if the signature verifies
   return the raw message with the signature removed (size: siglen - crypto_sign_BYTES),
   returns NULL otherwise */
unsigned char * pcp_ed_verify(unsigned char *signature, size_t siglen, pcp_pubkey_t *p);

/* same as pcp_ed_sign() but work on i/o directly, we're making a hash
   of the input 32k-wise, copy in=>out, sign the hash and append the
   sig only to the output */
size_t pcp_ed_sign_buffered(FILE *in, FILE *out, pcp_key_t *s, int z85);

pcp_pubkey_t *pcp_ed_verify_buffered(FILE *in, pcp_pubkey_t *p);

size_t pcp_ed_detachsign_buffered(FILE *in, FILE *out, pcp_key_t *s);
pcp_pubkey_t *pcp_ed_detachverify_buffered(FILE *in, FILE *sigfd, pcp_pubkey_t *p);

#endif /*  _HAVE_PCP_ED_H */
