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


#ifndef _HAVE_PCP_PLATFORM_H
#define _HAVE_PCP_PLATFORM_H

#include "config.h"

#ifdef HAVE_ENDIAN_H
# include <endian.h>
#else // no endian.h
# ifdef HAVE_SYS_ENDIAN_H
#   include <sys/endian.h>
#   ifdef HAVE_BETOH32
      // openbsd, use aliases
#     define be32toh betoh32
#     define htobe32 hto32be
#   endif
# else // no sys/endian.h
#   if __BYTE_ORDER == __BIG_ENDIAN
#     define be32toh(x)	((void)0)
#     define htobe32(x)	((void)0)
#   else
#     ifdef HAVE_ARPA_INET_H
#       include <arpa/inet.h>
#     else
#       ifdef HAVE_NETINET_IN_H
#         include <netinet/in.h>
#       else
#         error Need either netinet/in.h or arpa/inet.h for ntohl() and htonl()
#       endif
#     endif
#     define be32toh(x)	((u_int32_t)ntohl((u_int32_t)(x)))
#     define htobe32(x)	((u_int32_t)htonl((u_int32_t)(x)))
#   endif
#  endif // HAVE_SYS_ENDIAN_H
#endif // HAVE_ENDIAN_H


#ifndef HAVE_ARC4RANDOM_BUF
// shitty OS. we're using libsodium's implementation

#include <sodium.h>

static inline u_int32_t arc4random() {
  return randombytes_random();
}

static inline void arc4random_buf(void *buf, size_t nbytes) {
  randombytes(buf, nbytes);
}


#endif


#endif /* !_HAVE_PCP_PLATFORM_H */

