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


#ifndef _HAVE_PCPPP_VAULT_H
#define _HAVE_PCPPP_VAULT_H

#include <pcp.h>
#include <vector>
#include <string>
#include <sstream>
#include <map>
#include <stdexcept>
#include <iostream>

#include "key++.h"

namespace pcp {
  
  typedef std::map<std::string, Key> KeyMap;
  typedef std::map<std::string, PubKey> PubKeyMap;

  typedef std::map<std::string,Key>::iterator KeyIterator;
  typedef std::map<std::string,PubKey>::iterator PubKeyIterator;


  // the vault
  class Vault {
  private:
    vault_t *V;
    PcpContext PTX;

  public:
    // constructors
    Vault();
    Vault(PcpContext P);
    Vault(PcpContext P, std::string filename);

    // destructor
    ~Vault();

    // methods
    KeyMap keys();
    PubKeyMap pubkeys();

    bool key_exists(std::string &id);
    bool pubkey_exists(std::string &id);

    int key_count();
    int pubkey_count();

    void key_add(Key &key);
    void pubkey_add(PubKey &key);

    void key_delete(std::string &id);

    Key get_primary();
    Key get_secret(std::string &id);
    PubKey get_public(std::string &id);
  };


};

#endif // _HAVE_PCPPP_VAULT_H
