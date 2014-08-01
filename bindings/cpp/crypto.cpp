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

Crypto::Crypto(PcpContext *C, Key &skey, PubKey &pkey) {
  P = pkey;
  S = skey;
  PTX = C;
  havevault = false;
  vault = Vault();
  P.is_stored(true);
  S.is_stored(true);
  pcphash_add(PTX->ptx, P.K, PCP_KEY_TYPE_PUBLIC);
  pcphash_add(PTX->ptx, S.K, PCP_KEY_TYPE_SECRET);
}

Crypto::Crypto(PcpContext *C, Vault &v, Key &skey, PubKey &pkey) {
  P = pkey;
  S = skey;
  PTX = C;
  vault = v;
  havevault = true;
}

Crypto::~Crypto() {
}

bool Crypto::encrypt(FILE *in, FILE *out, bool sign) {
  pcp_pubkey_t *pubhash = NULL;
  HASH_ADD_STR( pubhash, id, P.K);
  Pcpstream *pin = ps_new_file(in);
  Pcpstream *pout = ps_new_file(out);

  size_t clen = pcp_encrypt_stream(PTX->ptx, pin, pout, S.K, pubhash, sign);
  if(clen <= 0)
     throw exception(PTX);
  ps_close(pin);
  ps_close(pout);
  return true;
}

bool Crypto::decrypt(FILE *in, FILE *out, bool verify) {
  Pcpstream *pin = ps_new_file(in);
  Pcpstream *pout = ps_new_file(out);

  if(pcp_decrypt_stream(PTX->ptx, pin, pout, S.K, NULL, verify) <= 0)
    throw exception(PTX);
  ps_close(pin);
  ps_close(pout);
  return true;
}



