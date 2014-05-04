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

#include "scrypt.h"

byte* pcp_scrypt(PCPCTX *ptx, char *passwd, size_t passwdlen, byte *nonce, size_t noncelen) {
  uint8_t *dk = ucmalloc(64); /*  resulting hash */

  /*  constants */
  uint64_t N = 1 << 14;
  uint32_t r = 8;
  uint32_t p = 1;
  size_t buflen = 64;

  if (crypto_scrypt((byte *)passwd, passwdlen, (uint8_t *)nonce, noncelen, N, r, p, dk, buflen) == 0) {
    return dk;
  }
  else {
    fatal(ptx, "crypto_scrypt() failed");
    return NULL;
  }

  return NULL;
}
