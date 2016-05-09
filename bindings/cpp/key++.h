/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013-2016 T.v.Dein.

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
#include "buffer++.h"
#include "ptx++.h"

namespace pcp {

  class PubKey {
  private:
    bool stored;

  public:
    pcp_pubkey_t *K;
    PcpContext *PTX;

    // constructors
    PubKey(PcpContext *P);
    PubKey();
    PubKey(PcpContext *P, pcp_pubkey_t *k);
    PubKey(PcpContext *P, pcp_pubkey_t *k, bool store);
    PubKey(PcpContext *P, std::string &z85encoded);

    // destructors
    ~PubKey();

    // operators
    PubKey& operator = (const PubKey &k);

    std::string get_id();
    std::string get_owner();
    std::string get_mail();

    void is_stored(bool s);
    bool is_stored();
  };

  bool operator!(PubKey& k);
  std::ostream& operator<<(std::ostream& output, PubKey& k);



  class Key {
  private:
    bool stored;

  public:
    // make access to the underlying struct easier
    pcp_key_t *K;
    PcpContext *PTX;

    // constructors
    Key();
    Key(PcpContext *P);
    Key(PcpContext *P, bool generate);
    Key(PcpContext *P, const std::string& passphrase);
    Key(PcpContext *P, const std::string& passphrase,
        const std::string& owner,
        const std::string& mail);
    Key(PcpContext *P, pcp_key_t *k);
    Key(PcpContext *P, pcp_key_t *k, bool store);
    Key(PcpContext *P, std::string &z85encoded, std::string& passphrase);

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

    std::string export_secret(const std::string& passphrase);
    std::string export_public();

  };

  // << and >> operators
  bool operator!(Key& k);
  //std::ostream& operator<<(std::ostream& output, Key& k);
};


#endif // _HAVE_PCPPP_KEY_H
