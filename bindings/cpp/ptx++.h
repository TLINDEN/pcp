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
  public:
    PCPCTX *ptx;

    // constructors
    PcpContext();

    // clean up, wo don't do it in the destructor,
    // since it will be called multiple times otherwise
    void done();
  };
};


#endif // _HAVE_PCPPP_PTX_H
