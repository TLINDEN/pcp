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

std::string Signature::sign(std::vector<unsigned char> message) {
  unsigned char *m = (unsigned char *)ucmalloc(message.size());
  for(size_t i=0; i<message.size(); ++i)
    m[i] = message[i];
  string _s = Signature::sign(m, message.size());
  free(m);
  return _s;
}

std::string Signature::sign(std::string message) {
  unsigned char *m = (unsigned char *)ucmalloc(message.size() + 1);
  memcpy(m, message.c_str(), message.size());
  string _s = Signature::sign(m, message.size() + 1);
  free(m);
  return _s;
}

std::string Signature::sign(unsigned char *message, size_t mlen) {
  if(! S)
    throw exception("Error: cannot sign without a secret key, use another constructor.");

  if(S.is_encrypted())
    throw exception("Error: cannot sign with an encrypted secret key, decrypt it before using.");

  size_t zlen;
  sig = pcp_ed_sign(message, mlen, S.K);

  if(sig == NULL)
    throw exception();

  sig2be(sig);
  char *encoded = pcp_z85_encode((unsigned char *)sig, sizeof(pcp_sig_t), &zlen);
  sig2native(sig);

  if(encoded == NULL)
    throw exception();
 
  // FIXME: who free()s encoced?
  return string((char *)encoded);
}

bool Signature::verify(string signature, vector<unsigned char> message) {
  unsigned char *m = (unsigned char *)ucmalloc(message.size());
  for(size_t i=0; i<message.size(); ++i)
    m[i] = message[i];
  bool _b = Signature::verify(signature, m, message.size());
  free(m);
  return _b;
}

bool Signature::verify(string signature, string message) {
  unsigned char *m = (unsigned char *)ucmalloc(message.size() + 1);
  memcpy(m, message.c_str(), message.size());
  bool _b = Signature::verify(signature, m, message.size() + 1);
  free(m);
  return _b;
}

bool Signature::verify(string signature, unsigned char *message, size_t mlen) {
  size_t clen;
  unsigned char *decoded = pcp_z85_decode((char *)signature.c_str(), &clen);

  if(decoded == NULL)
    throw exception();

  if(clen != sizeof(pcp_sig_t)) {
    free(decoded);
    throw exception("Error: decoded signature didn't result to a proper sized sig!");
  }

  sig = (pcp_sig_t *)decoded;
  sig2native(sig);

  string sigid = string((char *)sig->id);

  if(!P) {
    if(havevault) {
      if(vault.pubkey_exists(sigid)) {
	P = vault.get_public(sigid);
      }
      else {
	throw exception("Unable to verify, signed using an unknown key.");
      }
    }
    else {
      throw exception("No public key and no vault specified, unable to verify.");
    }
  }
  else {
    if(P.get_id() != sigid) {
      throw exception("Specified public key doesn't match the signers key.");
    }
  }

  if(pcp_ed_verify(message, mlen, sig, P.K) == 0) {
    return true;
  }
  else {
    throw exception();
  }
}
