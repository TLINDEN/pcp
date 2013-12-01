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
#include <vector>
#include <string>
#include <sstream>
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



  class ResultSet {
  public:
    std::string String;
    std::vector<unsigned char> Vector;
    unsigned char *Uchar;
    size_t Size;

    ~ResultSet() { free(Uchar); }
  };


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

  std::istream& operator>>(std::istream& input, PubKey& k);
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

    std::string encrypt(PubKey &recipient, std::vector<unsigned char> message);
    std::string encrypt(PubKey &recipient, std::string message);
    std::string encrypt(PubKey &recipient, unsigned char *message, size_t mlen);

    ResultSet decrypt(PubKey &sender, std::string cipher);
  };

  // << and >> operators
  std::istream& operator>>(std::istream& input, Key& k);
  std::ostream& operator<<(std::ostream& output, Key& k);


  typedef std::map<std::string, Key> KeyMap;
  typedef std::map<std::string, PubKey> PubKeyMap;

  typedef std::map<std::string,Key>::iterator KeyIterator;
  typedef std::map<std::string,PubKey>::iterator PubKeyIterator;

  // the vault
  class Vault {
  private:
    vault_t *V;

  public:
    // constructors
    Vault();
    Vault(std::string filename);

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
  };


};




#endif // _HAVE_PCPPP_H
