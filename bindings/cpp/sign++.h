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


#ifndef _HAVE_PCPPP_SIGN_H
#define _HAVE_PCPPP_SIGN_H

#include <pcp.h>
#include <string>
#include <iostream>

#include "vault++.h"
#include "key++.h"
#include "sign++.h"
#include "helpers++.h"

namespace pcp {

  class Signature {
  private:
    bool havevault;

  public:
    PubKey P;
    Key S;
    Vault vault;
    pcp_sig_t *sig;

    // constructors
    Signature(Key &skey); // sign only
    Signature(PubKey &pkey); // verify only
    Signature(Key &skey, PubKey &pkey); // both/bulk
    Signature(Vault &v);

    // destructor
    ~Signature();

    // PK signature methods
    // sender pubkey is P
    std::string sign(std::vector<unsigned char> message);
    std::string sign(std::string message);
    std::string sign(unsigned char *message, size_t mlen);

    // verify using P or use vault if defined
    bool verify(std::string signature, std::string message);
    bool verify(std::string signature, std::vector<unsigned char> message);
    bool verify(std::string signature, unsigned char *message, size_t mlen);
  };
};

#endif // _HAVE_PCPPP_SIGN_H
