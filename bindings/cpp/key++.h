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


#ifndef _HAVE_PCPPP_KEY_H
#define _HAVE_PCPPP_KEY_H

#include <pcp.h>
#include <vector>
#include <string>
#include <iostream>

#include "helpers++.h"

namespace pcp {

  class PubKey {
  private:
    bool stored;

  public:
    pcp_pubkey_t *K;

    // constructors
    PubKey();
    PubKey(pcp_pubkey_t *k);
    PubKey(pcp_pubkey_t *k, bool store);
    PubKey(std::string &z85encoded);

    // destructors
    ~PubKey();

    // operators
    PubKey& operator = (const PubKey &k);

    std::string get_id();
    std::string get_owner();
    std::string get_mail();

    void is_stored(bool s);
    bool is_stored();

    std::string to_text();
  };

  bool operator!(PubKey& k);
  std::ostream& operator<<(std::ostream& output, PubKey& k);



  class Key {
  private:
    bool stored;

  public:
    // make access to the underlying struct easier
    pcp_key_t *K;

    // constructors
    Key();
    Key(bool generate);
    Key(const std::string& passphrase);
    Key(const std::string& passphrase,
	const std::string& owner,
	const std::string& mail);
    Key(pcp_key_t *k);
    Key(pcp_key_t *k, bool store);
    Key(std::string &z85encoded);

    // destructor
    ~Key();

    // operators
    Key& operator = (const Key &k);

    // methods
    void encrypt(const std::string& passphrase);
    void decrypt(const std::string& passphrase);
    PubKey get_public();
    std::string get_id();
    std::string get_owner();
    std::string get_mail();

    void set_owner(const std::string& owner);
    void set_mail(const std::string& mail);
    void is_stored(bool s);
    bool is_stored();
    bool is_encrypted();
    bool is_primary();

    std::string to_text();
  };

  // << and >> operators
  bool operator!(Key& k);
  std::ostream& operator<<(std::ostream& output, Key& k);
};


#endif // _HAVE_PCPPP_KEY_H
