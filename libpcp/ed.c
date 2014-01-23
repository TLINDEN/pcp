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

unsigned char * pcp_ed_verify(unsigned char *signature, size_t siglen, pcp_pubkey_t *p) {
  unsigned char *message = ucmalloc(siglen - crypto_sign_BYTES);
  size_t mlen;

  if(crypto_sign_open(message, &mlen, signature, siglen, p->edpub) != 0) {
    fatal("Failed to open the signature using the public key 0x%s!\n", p->id);
    goto errve1;
  }

  return message;

 errve1:
  free(message);
  return NULL;
}

unsigned char *pcp_ed_sign(unsigned char *message, size_t messagesize, pcp_key_t *s) {
  size_t mlen = messagesize + crypto_sign_BYTES;
  unsigned char *signature = ucmalloc(mlen);

  crypto_sign(signature, &mlen, message, messagesize, s->edsecret);

  return signature;
}

size_t pcp_ed_sign_buffered(FILE *in, FILE *out, pcp_key_t *s, int z85) {
  unsigned char in_buf[PCP_BLOCK_SIZE];
  size_t cur_bufsize = 0;
  crypto_generichash_state *st = ucmalloc(sizeof(crypto_generichash_state));
  unsigned char hash[crypto_generichash_BYTES_MAX];

  crypto_generichash_init(st, NULL, 0, 0);

  if(z85)
    fprintf(out, "%s\nHash: Blake2\n\n", PCP_SIG_HEADER);

  while(!feof(in)) {
    cur_bufsize = fread(&in_buf, 1, PCP_BLOCK_SIZE, in);
    if(cur_bufsize <= 0)
      break;

    crypto_generichash_update(st, in_buf, cur_bufsize);
    fwrite(in_buf, cur_bufsize, 1, out);
  }

  if(ferror(out) != 0) {
    fatal("Failed to write encrypted output!\n");
    free(st);
    return 0;
  }

  crypto_generichash_final(st, hash, crypto_generichash_BYTES_MAX);

  size_t mlen = + crypto_sign_BYTES + crypto_generichash_BYTES_MAX;
  unsigned char *signature = ucmalloc(mlen);
  crypto_sign(signature, &mlen, hash, crypto_generichash_BYTES_MAX, s->edsecret);

  if(z85) {
    if(in_buf[cur_bufsize] != '\n')
      fprintf(out, "\n");
    fprintf(out, "%s\nVersion: PCP v%d.%d.%d\n\n", PCP_SIG_START, PCP_VERSION_MAJOR, PCP_VERSION_MINOR, PCP_VERSION_PATCH);
    size_t zlen;
    char *z85encoded = pcp_z85_encode((unsigned char*)signature, crypto_sign_BYTES, &zlen);
    fprintf(out, "%s\n%s\n", z85encoded, PCP_SIG_END);
  }
  else {
    fwrite(signature, crypto_sign_BYTES, 1, out);
  }

  if(fileno(in) != 0)
    fclose(in);
  if(fileno(out) != 1)
    fclose(out);

  free(st);

  return mlen; // ???
}
