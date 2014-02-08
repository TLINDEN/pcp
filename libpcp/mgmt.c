/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013-2014 T.v.Dein.

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

    You can contact me by mail: <tom AT vondein DOT org>.
*/


#include "mgmt.h"


Buffer *pcp_get_rfc_pub (pcp_pubkey_t *key, pcp_key_t *sk) {
  Buffer *out = buffer_new(320, "bo1");
  Buffer *raw = buffer_new(256, "bs1");

  /* add the header */
  buffer_add8(out, PCP_KEY_VERSION);
  buffer_add32(out, key->ctime);
  buffer_add8(out, EXP_PK_CIPHER);

  /* add the keys */
  buffer_add(raw, key->edpub, 32);
  buffer_add(raw, key->edpub, 32);
  buffer_add(raw, key->pub, 32);

  /* add the sig header */
  buffer_add8(raw, EXP_SIG_VERSION);
  buffer_add8(raw, EXP_SIG_TYPE);
  buffer_add8(raw, EXP_SIG_CIPHER);
  buffer_add8(raw, EXP_HASH_CIPHER);
  buffer_add16(raw, 5); /* we add 5 sub sigs always */

  /* add sig ctime */
  buffer_add32be(raw, 4);
  buffer_add8(raw, EXP_SIG_SUB_CTIME);
  buffer_add32be(raw, time(0));

  /* add sig expire time */
  buffer_add32be(raw, 4);
  buffer_add8(raw, EXP_SIG_SUB_SIGEXPIRE);
  buffer_add32be(raw, time(0) + 31536000);

  /* add key expire time */
  buffer_add32be(raw, 4);
  buffer_add8(raw, EXP_SIG_SUB_KEYEXPIRE);
  buffer_add32be(raw, key->ctime + 31536000);

  /* add name notation sub*/
  size_t notation_size = strlen(key->owner) + 4 + 5;
  buffer_add32be(raw, notation_size);
  buffer_add8(raw, EXP_SIG_SUB_NOTATION);
  buffer_add16be(raw, 5);
  buffer_add16be(raw, strlen(key->owner));
  buffer_add(raw, "owner", 5);
  buffer_add(raw, key->owner, strlen(key->owner));

  /* add mail notation sub */
  notation_size = strlen(key->mail) + 4 + 4;
  buffer_add32be(raw, notation_size);
  buffer_add8(raw, EXP_SIG_SUB_NOTATION);
  buffer_add16be(raw, 4);
  buffer_add16be(raw, strlen(key->mail));
  buffer_add(raw, "mail", 4);
  buffer_add(raw, key->mail, strlen(key->mail));

  /* add key flags */
  buffer_add32be(raw, 1);
  buffer_add8(raw, 27);
  buffer_add8(raw, 0x02 & 0x08 & 0x80);

  /* create a hash from the PK material and the raw signature packet */
  crypto_generichash_state *st = ucmalloc(sizeof(crypto_generichash_state));
  unsigned char *hash = ucmalloc(crypto_generichash_BYTES_MAX);

  crypto_generichash_init(st, NULL, 0, 0);
  crypto_generichash_update(st, buffer_get(raw), buffer_size(raw));
  crypto_generichash_final(st, hash, crypto_generichash_BYTES_MAX);

  /* sign the hash */
  unsigned char *sig = pcp_ed_sign(hash, crypto_generichash_BYTES_MAX, sk->secret);

  /* append the signature packet to the output */
  buffer_add(out, buffer_get(raw), buffer_size(raw));

  /* append the signed hash */
  buffer_add(out, sig, crypto_generichash_BYTES_MAX + crypto_generichash_BYTES_MAX);

  /* and that's it. wasn't that easy? :) */
  buffer_free(raw);
  memset(hash, 0, crypto_generichash_BYTES_MAX);
  free(hash);
  memset(sig, 0, crypto_generichash_BYTES_MAX + crypto_generichash_BYTES_MAX);
  free(sig);

  return out;
}
