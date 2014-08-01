/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013-2014 T.c.Dein.

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

#include "sign++.h"

using namespace std;
using namespace pcp;

Signature::Signature(PcpContext *ptx, Key &skey) {
  S = skey;
  PTX = ptx;
  sig = Buf("sign2");
  havevault = false;
  Signedby = NULL;
}

Signature::Signature(PcpContext *C,PubKey &pkey) {
  P = pkey;
  PTX = C;
  havevault = false;
  sig = Buf("sign1");
  Signedby = NULL;
}

Signature::Signature(PcpContext *C,Key &skey, PubKey &pkey) {
  P = pkey;
  S = skey;
  PTX = C;
  havevault = false;
  Signedby = NULL;
}

Signature::Signature(PcpContext *C,Vault &v) {
  vault = v;
  havevault = true;
  PTX = C;
  S = vault.get_primary();
  Signedby = NULL;
}

Signature::~Signature() {
  if(Signedby != NULL)
    delete Signedby;
}

bool Signature::sign(std::vector<unsigned char> message) {
  if(! S)
    throw exception(PTX, "Error: cannot sign without a secret key, use another constructor.");

  if(S.is_encrypted())
    throw exception(PTX, "Error: cannot sign with an encrypted secret key, decrypt it before using.");

  char n[] = "signvec";
  Buffer *m = buffer_new(32, n);

  for(size_t i=0; i<message.size(); ++i)
    buffer_add8(m, message[i]);

  Pcpstream *p = ps_new_inbuffer(m);
  bool ok = Signature::sign(p);
  ps_close(p);
  buffer_free(m);

  if(!ok)
    throw exception(PTX);

  return true;
}

bool Signature::sign(unsigned char *message, size_t mlen) {
  if(! S)
    throw exception(PTX, "Error: cannot sign without a secret key, use another constructor.");

  if(S.is_encrypted())
    throw exception(PTX, "Error: cannot sign with an encrypted secret key, decrypt it before using.");

  char n[] = "signchar";
  Buffer *m = buffer_new(32, n);
  buffer_add(m, message, mlen);
  Pcpstream *p = ps_new_inbuffer(m);

  bool ok = Signature::sign(p);
  ps_close(p);
  buffer_free(m);

  if(! ok)
    throw exception(PTX);

  return true;
}

bool Signature::sign(Pcpstream *message) {
  Pcpstream *out = ps_new_outbuffer();

  size_t sigsize = pcp_ed_sign_buffered(PTX->ptx, message, out, S.K, 0);

  if(sigsize > 0) {
    Buffer *o = ps_buffer(out);
    sig.add_buf(o);
  }
  else {
    ps_close(out);
    return false;
  }
  ps_close(out);

  return true;
}

bool Signature::verify(vector<unsigned char> message) {
  if(!P) {
    throw exception(PTX, "No public key specified, unable to verify.");
  }

  Buf _sig = Buf();

  for(size_t i=0; i<message.size(); ++i)
    _sig.add8(message[i]);

  return Signature::verify(_sig);
}

bool Signature::verify(unsigned char *signature, size_t mlen) {
  if(!P) {
    throw exception(PTX, "No public key specified, unable to verify.");
  }

  Buf _sig = Buf();
  _sig.add(signature, mlen);

  return Signature::verify(_sig);
}


bool Signature::verify(Buf &_sig) {
  Pcpstream *p = ps_new_inbuffer(_sig.get_buffer());

  /* 
     we need to exclude current public key from free'ing
     because it's used as a hash in ed.c:276.
   */
  P.is_stored(true);

  pcp_pubkey_t *pub = pcp_ed_verify_buffered(PTX->ptx, p, P.K);

  ps_close(p);

  if(pub != NULL) {
    Signedby = new PubKey(PTX, pub);
    return true;
  }
  else {
    throw exception(PTX);
  }
}
