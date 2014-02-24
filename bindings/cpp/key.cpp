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

#include "vault++.h"
#include "key++.h"

using namespace std;
using namespace pcp;

Key::Key() {
  stored = false;
  K = NULL;
}

Key::Key(bool generate) {
  stored = false;
  K = pcpkey_new();
}

Key::Key(const string& passphrase) {
  stored = false;
  K = pcpkey_new();
  K = pcpkey_encrypt(K, (char *)passphrase.c_str());
}

Key::Key(const string& passphrase,
	 const string& owner,
	 const string& mail) {
  stored = false;
  pcp_key_t *_K = pcpkey_new();
  K = pcpkey_encrypt(_K, (char *)passphrase.c_str());
  memcpy(K->owner, owner.c_str(), owner.length()+1);
  memcpy(K->mail, mail.c_str(), mail.length()+1);
  //  free(_K);
}

Key::Key(pcp_key_t *k) {
  stored = false;
  K = k;
}

Key::Key(pcp_key_t *k, bool store) {
  stored = new bool(store);
  K = k;
}

Key::Key(string &z85encoded, string &passphrase) {
  stored = false;

  if(z85encoded.length() == 0)
    throw pcp::exception("Error: zero length input");

  pcp_key_t *key = pcp_import_secret((unsigned char *)z85encoded.c_str(), z85encoded.length(), (char *)passphrase.c_str());

  if(key == NULL)
    throw pcp::exception();

  if(pcp_sanitycheck_key(key) != 0) {
    free(key);
    throw pcp::exception();
  }

  K = key;
}

Key::~Key() {
  if (! stored) {
    free(K);
  }
}

Key& Key::operator = (const Key &k) {
  K = k.K;
  return *this;
}

string Key::export_secret(const string &passphrase) {
  Buffer *exported_sk;

  if(passphrase.length() == 0)
    throw pcp::exception("Error: empty passphrase");

  exported_sk =  pcp_export_secret(K, (char *)passphrase.c_str());

  if(exported_sk == NULL)
    throw pcp::exception();

  size_t zlen;
  char *z85 = pcp_z85_encode(buffer_get(exported_sk), buffer_size(exported_sk), &zlen);

  string out =  string(EXP_SK_HEADER) + "\r\n" + string(z85) + "\r\n" + string(EXP_SK_FOOTER) + "\r\n";

  return out;
}

string Key::export_public() {
  Buffer *exported_pk;

  exported_pk =  pcp_export_rfc_pub(K);

  if(exported_pk == NULL)
    throw pcp::exception();

  size_t zlen;
  char *z85 = pcp_z85_encode(buffer_get(exported_pk), buffer_size(exported_pk), &zlen);

  string out =  string(EXP_PK_HEADER) + "\r\n" + string(z85) + "\r\n" + string(EXP_PK_FOOTER) + "\r\n";

  return out;
}


bool pcp::operator!(Key& k) {
  if(k.K == NULL)
    return true;
  else
    return false;
}


void Key::encrypt(const string& passphrase) {
  K = pcpkey_encrypt(K, (char *)passphrase.c_str());
  if(PCP_ERRSET == 1)
    throw exception();
}

void Key::decrypt(const string& passphrase) {
  K = pcpkey_decrypt(K, (char *)passphrase.c_str());
  if(PCP_ERRSET == 1)
    throw exception();
}

PubKey Key::get_public() {
  return PubKey(pcpkey_pub_from_secret(K));
}

string Key::get_id() {
  string id = K->id;
  return id;
}

string Key::get_owner() {
  string o = K->owner;
  return o;
}

string Key::get_mail() {
  string m = K->mail;
  return m;
}

void Key::set_owner(const string& owner) {
  memcpy(K->owner, owner.c_str(), owner.length()+1);
}

void Key::set_mail(const string& mail) {
  memcpy(K->mail, mail.c_str(), mail.length()+1);
}

void Key::is_stored(bool s) {
  stored = s;
}

bool Key::is_stored() {
  return stored;
}

bool Key::is_encrypted() {
  if(K->secret[0] == '\0')
    return true;
  else
    return false;
}

// class Key ends here.




PubKey::PubKey() {
  stored = false;
  K = NULL;
}


PubKey::PubKey(pcp_pubkey_t *k) {
  stored = false;
  K = k;
}

PubKey::PubKey(pcp_pubkey_t *k, bool store) {
  stored = store;
  K = k;
}

PubKey::PubKey(string &z85encoded) {
  stored = false;

  if(z85encoded.length() == 0)
    throw pcp::exception("Error: zero length input");

  Buf blob("pub", 256);
  blob.add(z85encoded.c_str(), z85encoded.length());

  pcp_ks_bundle_t *KS = pcp_import_pub(buffer_get(blob.get_buffer()), buffer_size(blob.get_buffer()));

  if(KS == NULL) {
    throw pcp::exception();
  }
  pcp_pubkey_t *pub = KS->p;

  if(pcp_sanitycheck_pub(pub) != 0) {
    free(KS->p);
    free(KS->s);
    free(KS);
    throw pcp::exception();
  }

  K = pub;
}

PubKey::~PubKey() {
  if (! stored) {
    free(K);
  }
}

PubKey& PubKey::operator = (const PubKey &k) {
  K = k.K;
  return *this;
}

bool pcp::operator!(PubKey& k) {
  if(k.K == NULL) {
    return true;
  }
  else {
    return false;
  }
}

string PubKey::get_id() {
  string id = K->id;
  return id;
}

string PubKey::get_owner() {
  string o = K->owner;
  return o;
}

string PubKey::get_mail() {
  string m = K->mail;
  return m;
}

void PubKey::is_stored(bool s) {
  stored = s;
}

bool PubKey::is_stored() {
  return stored;
}

