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


#ifndef _HAVE_PCPPP_HELPERS_H
#define _HAVE_PCPPP_HELPERS_H

#include <pcp.h>
#include <vector>
#include <string>
#include <sstream>
#include <stdexcept>
#include <iostream>

#include "ptx++.h"

namespace pcp {
  
  class exception : public std::runtime_error {
  private:
    PCPCTX *ptx;
    std::string getfatals(PcpContext *P) {
      std::string msg;
      PCPCTX *ptx = P->ptx;
      if(ptx->pcp_errset == 1) {
	msg = ptx->pcp_err;
      }
      if(errno) {
	msg += std::string("\nError: ")
	    + std::string(strerror(errno))
	    + std::string("\n");
      }
      return msg;
    }
  public:
  exception(PcpContext *P, const std::string & msg) : runtime_error(msg) { ptx = P->ptx; }
  exception(PcpContext *P) : runtime_error(getfatals(P)) { }
  };



  class ResultSet {
  public:
    std::string String;
    std::vector<unsigned char> Vector;
    unsigned char *Uchar;
    size_t Size;

    ~ResultSet() { free(Uchar); }
  };

};


#endif // _HAVE_PCPPP_HELPERS_H
