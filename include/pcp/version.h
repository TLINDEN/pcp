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


#ifndef _HAVE_PCP_VERSION
#define _HAVE_PCP_VERSION

#define PCP_VERSION_MAJOR 0
#define PCP_VERSION_MINOR 1
#define PCP_VERSION_PATCH 3

#define PCP_MAKE_VERSION(major, minor, patch) \
    ((major) * 10000 + (minor) * 100 + (patch))
#define PCP_VERSION \
    PCP_MAKE_VERSION(PCP_VERSION_MAJOR, PCP_VERSION_MINOR, PCP_VERSION_PATCH)

int pcp_version();

#endif // _HAVE_PCP_VERSION
