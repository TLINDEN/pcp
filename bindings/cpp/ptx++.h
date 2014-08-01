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


#ifndef _HAVE_PCPPP_PTX_H
#define _HAVE_PCPPP_PTX_H

#include <pcp.h>
#include <vector>
#include <string>
#include <iostream>

#include "helpers++.h"

namespace pcp {

  class PcpContext {
  private:
    bool iscopy;

  public:
    PCPCTX *ptx;

    // constructors
    PcpContext();

    // destructor
    ~PcpContext();

    // copy constructor. holds the same pointer
    // as the original and doesn't free()
    PcpContext& operator = (const PcpContext *PTX);
    PcpContext(const PcpContext *PTX);    
  };
};


#endif // _HAVE_PCPPP_PTX_H
