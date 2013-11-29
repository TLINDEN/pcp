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


#ifndef _HAVE_PCPPP_H
#define _HAVE_PCPPP_H

#include <pcp.h>

#include <string>
#include <sstream>
#include <vector>
#include <map>
#include <stdexcept>
#include <iostream>


namespace pcp {
  
  class exception : public std::runtime_error {
  private:
    std::string getfatals() {
      std::string msg;
      if(PCP_ERRSET == 1) {
	msg = PCP_ERR;
      }
      if(errno) {
	msg += std::string("\nError: ") + std::string(strerror(errno)) + std::string("\n");
      }
      return msg;
    }
  public:
    exception(const std::string & msg) : runtime_error(msg) { }
  exception() : runtime_error(getfatals()) { }
  };





  class PubKey {
  private:
    pcp_pubkey_t *K;
    bool stored;

  public:
    // constructors
    PubKey();
    PubKey(const PubKey &k);
    PubKey(pcp_pubkey_t *k);

    // destructors
    ~PubKey();

    // operators
    PubKey& operator = (const PubKey &k);


    std::string get_id();
    std::string get_owner();
    std::string get_mail();
    pcp_pubkey_t *get_key();
    void is_stored(bool s);
    bool is_stored();
  };

  std::istream& operator>>(std::istream& input, PubKey& k);
  std::ostream& operator<<(std::ostream& output, PubKey& k);



  class Key {
  private:
    pcp_key_t *K;
    bool stored;

  public:
    // constructors
    Key();
    Key(bool generate);
    Key(const std::string& passphrase);
    Key(const std::string& passphrase,
	const std::string& owner,
	const std::string& mail);
    Key(const Key &k);
    Key(pcp_key_t *k);

    // destructors
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
    pcp_key_t *get_key();

    void set_owner(const std::string& owner);
    void set_mail(const std::string& mail);
    void is_stored(bool s);
    bool is_stored();
    bool is_encrypted();
  };

  // << and >> operators
  std::istream& operator>>(std::istream& input, Key& k);
  std::ostream& operator<<(std::ostream& output, Key& k);

};




#endif // _HAVE_PCPPP_H
