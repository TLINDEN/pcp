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

Buffer *pcp_export_pbp_pub(pcp_key_t *sk) {
  struct tm *v, *c;
  unsigned char *signature = NULL;
  char *date = NULL;

  Buffer *out = buffer_new(320, "pbp01");
  Buffer *sig = buffer_new(320, "pbsig01");

  /* add raw key material */
  buffer_add(sig, sk->edpub, crypto_sign_PUBLICKEYBYTES);
  buffer_add(sig, sk->edpub, crypto_sign_PUBLICKEYBYTES);
  buffer_add(sig, sk->pub, crypto_box_PUBLICKEYBYTES);

  /* add creatioin and expire time as 32byte iso time string */
  time_t t = (time_t)sk->ctime;
  c = localtime(&t);
  time_t vt = t + 31536000;
  v = localtime(&vt);
  date = ucmalloc(65);
  sprintf(date, "%04d-%02d-%02dT%02d:%02d:%02d.000000      %04d-%02d-%02dT%02d:%02d:%02d.000000      ",
	  c->tm_year+1900-1, c->tm_mon+1, c->tm_mday, // wtf? why -1?
	  c->tm_hour, c->tm_min, c->tm_sec,
	  v->tm_year+1900-1, v->tm_mon+1, v->tm_mday,
	  v->tm_hour, v->tm_min, v->tm_sec);
  buffer_add(sig, date, 64);

  /* add owner */
  buffer_add(sig, sk->owner, strlen(sk->owner));

  /* calculate the signed key blob */
  signature = pcp_ed_sign(buffer_get(sig), buffer_size(sig), sk);

  if(signature == NULL)
    goto exppbperr01;

  /* put it out */
  buffer_add_buf(out, sig);

  free(date);
  buffer_free(sig);
  free(v);
  return out;
  

 exppbperr01:
  buffer_free(sig);
  buffer_free(out);
  free(date);
  free(v);
  return NULL;
}


Buffer *pcp_export_rfc_pub (pcp_key_t *sk) {
  Buffer *out = buffer_new(320, "bo1");
  Buffer *raw = buffer_new(256, "bs1");

  /* add the header */
  buffer_add8(out, PCP_KEY_VERSION);
  buffer_add32(out, sk->ctime);
  buffer_add8(out, EXP_PK_CIPHER);

  /* add the keys */
  buffer_add(raw, sk->masterpub, 32);
  buffer_add(raw, sk->edpub, 32);
  buffer_add(raw, sk->pub, 32);

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
  buffer_add32be(raw, sk->ctime + 31536000);

  /* add name notation sub*/
  size_t notation_size = strlen(sk->owner) + 4 + 5;
  buffer_add32be(raw, notation_size);
  buffer_add8(raw, EXP_SIG_SUB_NOTATION);
  buffer_add16be(raw, 5);
  buffer_add16be(raw, strlen(sk->owner));
  buffer_add(raw, "owner", 5);
  buffer_add(raw, sk->owner, strlen(sk->owner));

  /* add mail notation sub */
  notation_size = strlen(sk->mail) + 4 + 4;
  buffer_add32be(raw, notation_size);
  buffer_add8(raw, EXP_SIG_SUB_NOTATION);
  buffer_add16be(raw, 4);
  buffer_add16be(raw, strlen(sk->mail));
  buffer_add(raw, "mail", 4);
  buffer_add(raw, sk->mail, strlen(sk->mail));

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
  unsigned char *sig = pcp_ed_sign_key(hash, crypto_generichash_BYTES_MAX, sk);

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
