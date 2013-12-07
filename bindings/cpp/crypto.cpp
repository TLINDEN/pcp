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
}

Crypto::Crypto(Vault &v, Key &skey, PubKey &pkey) {
  P = pkey;
  S = skey;
  vault = v;
  havevault = true;
}

string Crypto::encrypt(string message) {
  unsigned char *m = (unsigned char *)ucmalloc(message.size() + 1);
  memcpy(m, message.c_str(), message.size());
  return Crypto::encrypt(m, message.size() + 1);
}

string Crypto::encrypt(vector<unsigned char> message) {
  unsigned char *m = (unsigned char *)ucmalloc(message.size());
  for(size_t i=0; i<message.size(); ++i)
    m[i] = message[i];
  return Crypto::encrypt(m, message.size());
}

string Crypto::encrypt(unsigned char *message, size_t mlen) {
  if(S.is_encrypted())
    throw exception("Error: cannot encrypt with an encrypted secret key, decrypt it before using.");

  size_t clen, zlen, rlen;
  unsigned char *cipher;

  cipher = pcp_box_encrypt(S.K, P.K, message, mlen, &clen);

  if(cipher == NULL)
    throw exception();

  rlen = clen + crypto_hash_BYTES;
  unsigned char *combined = (unsigned char *)ucmalloc(rlen);
  unsigned char *hash = (unsigned char *)ucmalloc(crypto_hash_BYTES);

  crypto_hash(hash, (unsigned char*)S.K->id, 16);
  memcpy(combined, hash, crypto_hash_BYTES);
  memcpy(&combined[crypto_hash_BYTES], cipher, clen);

  // combined consists of:
  // keyid|nonce|cipher
  char *encoded = pcp_z85_encode(combined, rlen, &zlen);

  if(encoded == NULL)
    throw exception();

  return string((char *)encoded);
}

ResultSet Crypto::decrypt(string cipher) {
 if(S.is_encrypted())
    throw exception("Error: cannot decrypt with an encrypted secret key, decrypt it before using.");

  size_t clen;
  unsigned char *combined = pcp_z85_decode((char *)cipher.c_str(), &clen);

  if(combined == NULL)
    throw exception();

  unsigned char *encrypted = (unsigned char*)ucmalloc(clen - crypto_hash_BYTES);
  unsigned char *hash = (unsigned char*)ucmalloc(crypto_hash_BYTES);
  unsigned char *check = (unsigned char*)ucmalloc(crypto_hash_BYTES);

  memcpy(hash, combined, crypto_hash_BYTES);
  memcpy(encrypted, &combined[crypto_hash_BYTES], clen - crypto_hash_BYTES);

  PubKey sender;
  crypto_hash(check, (unsigned char*)P.K->id, 16);

  if(memcmp(check, hash, crypto_hash_BYTES) != 0) {
    if(havevault) {
      PubKeyMap pmap = vault.pubkeys();
      for(PubKeyIterator it=pmap.begin(); it != pmap.end(); ++it) {
	crypto_hash(check, (unsigned char*)it->first.c_str(), 16);
	if(memcmp(check, hash, crypto_hash_BYTES) == 0) {
	  sender = it->second;
	  break;
	}
      }
    }
  }
  else {
    sender = P;
  }

  if(!sender) {
    free(combined);
    free(hash);
    free(check);
    free(encrypted);
    throw exception("No public key usable for decryption found!");
  }

  size_t dlen;
  unsigned char *decrypted = (unsigned char*)pcp_box_decrypt(S.K, sender.K,
                                             encrypted,
                                             clen - crypto_hash_BYTES, &dlen);

  if(decrypted == NULL) {
    free(combined);
    free(hash);
    free(check);
    free(encrypted);
    throw exception();
  }

  ResultSet r;
  r.Uchar  = decrypted;
  r.String = string((char *)decrypted);
  r.Size   = dlen;

  for(size_t i=0; i<dlen; ++i)
    r.Vector.push_back(decrypted[i]);

  free(combined);
  free(hash);
  free(check);
  free(encrypted);
  
  return r;
}



