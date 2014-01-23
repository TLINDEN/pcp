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

#include "sign++.h"

using namespace std;
using namespace pcp;

Signature::Signature(Key &skey) {
  S = skey;
  havevault = false;
  sig = NULL;
}

Signature::Signature(PubKey &pkey) {
  P = pkey;
  havevault = false;
  sig = NULL;
}

Signature::Signature(Key &skey, PubKey &pkey) {
  P = pkey;
  S = skey;
  havevault = false;
  sig = NULL;
}

Signature::Signature(Vault &v) {
  vault = v;
  havevault = true;
  sig = NULL;
  S = vault.get_primary();
}

Signature::~Signature() {
  if(sig != NULL)
    free(sig);
}

unsigned char *Signature::sign(std::vector<unsigned char> message) {
  unsigned char *m = (unsigned char *)ucmalloc(message.size());
  for(size_t i=0; i<message.size(); ++i)
    m[i] = message[i];
  return Signature::sign(m, message.size());
}

unsigned char *Signature::sign(unsigned char *message, size_t mlen) {
  if(! S)
    throw exception("Error: cannot sign without a secret key, use another constructor.");

  if(S.is_encrypted())
    throw exception("Error: cannot sign with an encrypted secret key, decrypt it before using.");

  sig = pcp_ed_sign(message, mlen, S.K);

  if(sig == NULL)
    throw exception();

  return sig;
}

bool Signature::verify(vector<unsigned char> message) {
  unsigned char *m = (unsigned char *)ucmalloc(message.size());
  for(size_t i=0; i<message.size(); ++i)
    m[i] = message[i];
  bool _b = Signature::verify(m, message.size());
  free(m);
  return _b;
}

bool Signature::verify(unsigned char *signature, size_t mlen) {
  unsigned char *message;

  if(!P) {
    throw exception("No public key specified, unable to verify.");
  }

  message = pcp_ed_verify(signature, mlen, P.K);
  if(message != NULL) {
    return true;
  }
  else {
    throw exception();
  }
}
