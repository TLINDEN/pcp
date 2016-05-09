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

#include "scrypt.h"
#include "util.h"

byte* pcp_scrypt(PCPCTX *ptx, char *passwd, size_t passwdlen, byte *nonce, size_t noncelen) {
  byte *dk = smalloc(64);
  byte *salt = malloc(crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
  
  crypto_generichash(salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES,
                   nonce, noncelen, NULL, 0);

  int status = crypto_pwhash_scryptsalsa208sha256(dk, 64, passwd, passwdlen, salt,
                                                  crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
                                                  crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);

  ucfree(salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
  if (status == 0) {
    return dk;
  }
  else {
    fatal(ptx, "crypto_pwhash_scryptsalsa208sha256() failed\n");
    return NULL;
  }
}

