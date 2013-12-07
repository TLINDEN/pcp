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

#include "pcp++.h"

using namespace std;
using namespace pcp;

Vault::Vault() {
  V = NULL;
}

Vault::Vault(string filename) {
  pcphash_init();
  V = pcpvault_init((char *)filename.c_str());
  if (V == NULL)
    throw pcp::exception();
}

Vault::~Vault() {
  pcpvault_close(V);
  pcphash_clean();
}

std::map<std::string, Key> Vault::keys() {
  std::map<std::string, Key> kmap;

  pcp_key_t *k = NULL;
  pcphash_iterate(k) {
    kmap.insert ( pair<string,Key>(string(k->id), Key(k, true)) );
  }

  return kmap;
}

std::map<std::string, PubKey> Vault::pubkeys() {
  std::map<std::string, PubKey> kmap;

  pcp_pubkey_t *k = NULL;
  pcphash_iteratepub(k) {
    kmap.insert ( pair<string,PubKey>(string(k->id), PubKey(k, true)) );
  }

  return kmap;
}

int Vault::key_count() {
  return pcphash_count();
}

int Vault::pubkey_count() {
  return pcphash_countpub();
}

void Vault::key_add(Key &key) {
  if(V->isnew == 1 || HASH_COUNT(pcpkey_hash) == 0) {
    key.K->type = PCP_KEY_TYPE_MAINSECRET;
  }

  if(pcpvault_addkey(V, (void *)key.K, key.K->type) != 0)
    throw pcp::exception();
  key.is_stored(true);
}

void Vault::pubkey_add(PubKey &key) {
  if(pcpvault_addkey(V, (void *)key.K, key.K->type) != 0)
    throw pcp::exception();
  key.is_stored(true);
}

bool Vault::key_exists(string &id) {
  pcp_key_t *s = pcphash_keyexists((char *)id.c_str());
  if(s == NULL)
    return false;
  else
    return true;
}

bool Vault::pubkey_exists(string &id) {
  pcp_pubkey_t *p = pcphash_pubkeyexists((char *)id.c_str());
  if(p == NULL)
    return false;
  else
    return true;
}

void Vault::key_delete(std::string &id) {
  pcp_pubkey_t *p = pcphash_pubkeyexists((char *)id.c_str());
  
  if(p != NULL) {
    // delete public
    HASH_DEL(pcppubkey_hash, p);
    free(p);
    V->unsafed = 1;
  }
  else {
    pcp_key_t *s = pcphash_keyexists((char *)id.c_str());
    if(s != NULL) {
      // delete secret
      HASH_DEL(pcpkey_hash, s);
      free(s);
      V->unsafed = 1;
    }
    else {
      throw exception("Key not found!\n");
    }
  }
}

Key Vault::get_primary() {
  pcp_key_t *k = NULL;
  pcphash_iterate(k) {
    if(k->type == PCP_KEY_TYPE_MAINSECRET) {
      return Key(k);
    }
  }

  if(Vault::key_count() == 1) {
    pcphash_iterate(k) {
      return Key(k);
    }
  }

  // too bad
  throw exception("No primary key found in vault.");
}

Key Vault::get_secret(std::string &id) {
  pcp_key_t *k = NULL;
  pcphash_iterate(k) {
    if(memcmp(k->id, id.c_str(), 16) == 0) {
      return Key(k);
    }
  }
  throw exception("Secret key doesn't exist in vault.");
}


PubKey Vault::get_public(std::string &id) {
  pcp_pubkey_t *k = NULL;
  pcphash_iteratepub(k) {
    if(memcmp(k->id, id.c_str(), 16) == 0) {
      return PubKey(k);
    }
  }
  throw exception("Public key doesn't exist in vault.");
}
