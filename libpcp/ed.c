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

#include "ed.h"

int pcp_ed_verify(unsigned char *input, size_t inputlen, pcp_sig_t *sig, pcp_pubkey_t *p) {
  unsigned char *message = ucmalloc(inputlen + crypto_sign_BYTES);
  unsigned char *tmpsig  = ucmalloc(inputlen + crypto_sign_BYTES); // from sig
  size_t mlen = 0;

  memcpy(tmpsig, sig->edsig, crypto_sign_BYTES);
  memcpy(&tmpsig[crypto_sign_BYTES], input, inputlen);

  if(crypto_sign_open(message, &mlen, tmpsig, inputlen + crypto_sign_BYTES, p->edpub) != 0) {
    fatal("Failed to open the signature using the public key 0x%s!\n", p->id);
    goto errve1;
  }

  if(memcmp(message, input, inputlen) != 0) {
    fatal("Failed to verify the signature, signed messages differ!\n");
    goto errve1;
  }

  free(tmpsig);
  free(message);
  return 0;

 errve1:
  free(message);
  free(tmpsig);
  return 1;
}



pcp_sig_t *pcp_ed_sign(unsigned char *message, size_t messagesize, pcp_key_t *s) {
  size_t mlen = messagesize + crypto_sign_BYTES;
  unsigned char *tmp = ucmalloc(mlen);
  unsigned char *signature = ucmalloc(crypto_sign_BYTES);

  crypto_sign(tmp, &mlen, message, messagesize, s->edsecret);

  memcpy(signature, tmp, crypto_sign_BYTES);

  pcp_sig_t *sig = pcp_ed_newsig(signature, s->id);

  memset(tmp, 0, mlen);
  free(tmp);

  return sig;
}

pcp_sig_t *pcp_ed_newsig(unsigned char *hash, char *id) {
  pcp_sig_t *sig = ucmalloc(sizeof(pcp_sig_t));
  sig->version = PCP_SIG_VERSION;
  sig->ctime = (long)time(0);
  memcpy(sig->edsig, hash, crypto_sign_BYTES);
  memcpy(sig->id, id, 17);
  return sig;
}

pcp_sig_t *sig2native(pcp_sig_t *s) {
#ifdef __BIG_ENDIAN
  return s;
#else
  s->version = be32toh(s->version);
  s->ctime   = be64toh(s->ctime);
  return s;
#endif
}

pcp_sig_t *sig2be(pcp_sig_t *s) {
#ifdef __BIG_ENDIAN
  return s;
#else
  s->version = htobe32(s->version);
  s->ctime   = htobe64(s->ctime);
  return s;
#endif
}

