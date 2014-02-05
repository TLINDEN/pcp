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


#ifndef _HAVE_PCP_MAC
#define _HAVE_PCP_MAC

#include <strings.h>
#include <stdlib.h>
#include <errno.h>
#include <sodium.h>
#include "pad.h"
#include "mem.h"


/*  how many times do we hash the passphrase */
#define HCYCLES 128000

/*  encrypt some arbitrary cleartext using */
/*  a curve25519 secret key  and a given nonce. */
/*  */
/*  expects a pointer to the target binary */
/*  stream containing the encrypted data, */
/*  the cleartext string, its size, the nonce */
/*  (24 bytes) and the secret key (32 bytes). */
/*  */
/*  allocates memory for the returned cipher */
/*  and it is up to the user to free it after use. */
/*  */
/*  returns the size of the returned cipherstream. */
/*  in case of an error, the cipher will be set */
/*  to NULL. */
size_t pcp_sodium_mac(unsigned char **cipher,
                      unsigned char *cleartext,
                      size_t clearsize,
                      unsigned char *nonce,
                      unsigned char *key);

/*  does the opposite of pcp_sodium_mac and decrypts */
/*  a given encrypted binary stream using a nonce and */
/*  a secret key (sizes: see above). */
/*  */
/*  allocates memory for the returned cleartext and */
/*  it is up to the user to free it after use. */
/*  */
/*  returns 0 if decryption and verification were */
/*  successful, otherwise -1.  */
int pcp_sodium_verify_mac(unsigned char **cleartext,
                          unsigned char* message,
                          size_t messagesize,
                          unsigned char *nonce,
                          unsigned char *key);




#endif /*  _HAVE_PCP_MAC */
