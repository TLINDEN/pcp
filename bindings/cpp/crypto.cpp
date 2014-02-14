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

#include "crypto++.h"


using namespace std;
using namespace pcp;

Crypto::Crypto(Key &skey, PubKey &pkey) {
  P = pkey;
  S = skey;
  havevault = false;
  pcphash_init();
  pcphash_add(P.K, PCP_KEY_TYPE_PUBLIC);
}

Crypto::Crypto(Vault &v, Key &skey, PubKey &pkey) {
  P = pkey;
  S = skey;
  vault = v;
  havevault = true;
}

bool Crypto::encrypt(FILE *in, FILE *out, bool sign) {
  pcp_pubkey_t *pubhash = NULL;
  HASH_ADD_STR( pubhash, id, P.K);
  size_t clen = pcp_encrypt_file(in, out, S.K, pubhash, sign);
  if(clen <= 0)
     throw exception();
  return true;
}

bool Crypto::decrypt(FILE *in, FILE *out, bool verify) {
  if(pcp_decrypt_file(in, out, S.K, NULL, verify) <= 0)
    throw exception();
  return true;
}



