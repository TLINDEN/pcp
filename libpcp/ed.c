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
  
  unsigned char *hash = ucmalloc(crypto_hash_sha256_BYTES + crypto_sign_BYTES); // from sig
  unsigned char *check = ucmalloc(crypto_hash_sha256_BYTES); // from file
  size_t mlen = 0;

  if(crypto_sign_open(hash, &mlen, sig->edsig, crypto_hash_sha256_BYTES + crypto_sign_BYTES, p->public) != 0) {
    fatal("Failed to open the signature using the public key 0x%s!\n", p->id);
    goto errve1;
  }

  crypto_hash_sha256(check, input, inputlen);

  if(memcmp(check, hash, crypto_hash_sha256_BYTES) != 0) {
    fatal("Failed to verify the signature, hashes differ!\n");
    goto errve1;
  }

  free(hash);
  free(check);
  return 0;

 errve1:
  free(hash);
  free(check);
  return 1;
}

pcp_sig_t *pcp_ed_sign(unsigned char *message, size_t messagesize, pcp_key_t *s) {
  unsigned char *hash = ucmalloc(crypto_hash_sha256_BYTES);
  size_t slen = crypto_hash_sha256_BYTES + crypto_sign_BYTES;
  unsigned char *signature = ucmalloc(slen);

  crypto_hash_sha256(hash, message, messagesize);

  crypto_sign(signature, &slen, hash, crypto_hash_sha256_BYTES, s->secret);

  pcp_sig_t *sig = pcp_ed_newsig(signature, s->id);

  return sig;
}

pcp_sig_t *pcp_ed_newsig(unsigned char *hash, char *id) {
  pcp_sig_t *sig = ucmalloc(sizeof(pcp_sig_t));
  sig->version = PCP_SIG_VERSION;
  sig->ctime = (long)time(0);
  memcpy(sig->edsig, hash, crypto_hash_sha256_BYTES + crypto_sign_BYTES);
  memcpy(sig->id, id, 17);
  return sig;
}

pcp_sig_t *sig2native(pcp_sig_t *s) {
  s->version = be32toh(s->version);
  s->ctime   = be64toh(s->ctime);
  return s;
}

pcp_sig_t *sig2be(pcp_sig_t *s) {
  s->version = htobe32(s->version);
  s->ctime   = htobe64(s->ctime);
  return s;
}

