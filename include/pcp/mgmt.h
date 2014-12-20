/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2014 T.v.Dein.

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

    You can contact me by mail: <tom AT vondein DOT org>.
*/

/*
  key management, namely import and export routines.
  we're working with buffers only, no direct file i/o */

#ifndef _HAVE_PCP_MGMT_H
#define _HAVE_PCP_MGMT_H

#if defined __linux__ || defined __GNU__ || defined __GLIBC__
#  ifndef _DEFAULT_SOURCE
#    define _DEFAULT_SOURCE 1
#  endif
#
#  ifndef _XOPEN_SOURCE
#    define _XOPEN_SOURCE 1
#  endif
#
#  ifndef _GNU_SOURCE
#    define _GNU_SOURCE 1
#  endif
#else
#  define _BSD_SOURCE 1
#endif

#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "defines.h"
#include "platform.h"
#include "structs.h"
#include "mem.h"
#include "ed.h"
#include "key.h"
#include "keysig.h"
#include "buffer.h"
#include "scrypt.h"
#include "context.h"

/* key management api, export, import, yaml and stuff */


/**
 * \defgroup PubKeyExport KEYEXPORT
 * @{

 Functions to export and import keys in various formats.
 */





/** RFC4880 alike public key export with some modifications.

  RFC4880 alike public key export with the following modifications:

   - Key material is native to us and not specified in the
     rfc for curve25519/ed25519. Therefore we're doing it like
     so: mp|sp|cp
     where mp = master keysigning public key (ed25519), 32 bytes
           sp = signing public key (ed25519), 32 bytes
	   cp = encryption public key (curve25519), 32 bytes

   - The various cipher (algorithm) id's are unspecified for
     our native ciphers. Therefore I created them, starting at
     33 (afaik 22 is the last officially assigned one). Once
     those cipher numbers become official, I'll use them instead
     of my own.

   - We use 64 bit integers for times everywhere (ctime, expire, etc),
     to be year 2038 safe. Note, that this is a violation of the
     RFC spec. However, said RFC have to be modified to fit 2038
     anc beyond anyways. This applies for the keyfile ctime as
     well for the key sig sub fields containing time values.

   - The exported public key packet contains a signature. We're
     filling out all required fields. A signature has a variable
     number of sig sub packets. We use only these types:

            2 = Signature Creation Time     (8 byte)
            3 = Signature Expiration Time   (8 byte)
            9 = Key Expiration Time         (8 bytes)
           20 = Notation Data               (4 byte flags, N bytes name+value)
           27 = Key Flags                   (1 byte, use 0x02, 0x08 and 0x80
  
   - We use 3 notation fields:
     * "owner", which contains the owner name, if set
     * "mail", which contains the emailaddress, if set
     * "serial", which contains the 32bit serial number

   - The actual signature field consists of the blake2 hash of
     (mp|sp|cp|keysig) followed by the nacl signature. However, we do
     not put an extra 16byte value of the hash, since the nacl
     signature already contains the full hash. So, an implementation
     could simply pull the fist 16 bytes of said hash to get
     the same result.

   - The mp keypair will be used for signing. The recipient can
     verify the signature, since mp is included.

   - While we put expiration dates for the key and the signature
     into the export as the rfc demands, we ignore them. Key expiring
     is not implemented in PCP yet.

  So, a full pubkey export looks like this

         version
         ctime
         cipher
         3 x raw keys            \
         sigheader                > calc hash from this
           sigsubs (header+data) /
         hash
         signature

  We use big-endian always.

  Unlike RC4880 public key exports, we're using Z85 encoding if
  armoring have been requested by the user. Armored output has
  a header and a footer line, however they are ignored by the
  parser and are therefore optional. Newlines, if present, are
  optional as well.

  http://tools.ietf.org/html/rfc4880#section-5.2.3

  The key sig blob will be saved in the Vault if we import a public key
  unaltered, so we can verify the signature at will anytime. When exporting
  a foreign public key, we will just put out that key sig blob to the
  export untouched.

  Currently PCP only support self-signed public key exports.

  We only support one key signature per key. However, it would be easily
  possible to support foreign keysigs as well in the future.


\param sk a secret key structure of type pcp_key_t. The secret keys
          in there have to be already decrypted.

\return the function returns a Buffer object containing the binary
        blob in the format described above.
  
*/
Buffer *pcp_export_rfc_pub (pcp_key_t *sk);


/** Export a public key in PBP format.
  Export a public key in the format described at
  https://github.com/stef/pbp/blob/master/doc/fileformats.txt

  \param sk a secret key structure of type pcp_key_t. The secret keys
            in there have to be already decrypted.

  \return the function returns a Buffer object containing the binary
          blob in the format described above.
 */
Buffer *pcp_export_pbp_pub(pcp_key_t *sk);

/** Export a public key in yaml format.
    Export a public key in yaml format.

    \param sk a secret key structure of type pcp_key_t. The secret keys
            in there have to be already decrypted.

    \return the function returns a Buffer object containing the binary
            blob containing a YAML string.
*/
Buffer *pcp_export_yaml_pub(pcp_key_t *sk);

/** Export a public key in perl code format.
    Export a public key in perl code format.

    \param sk a secret key structure of type pcp_key_t. The secret keys
            in there have to be already decrypted.

    \return the function returns a Buffer object containing the binary
            blob containing a perl code string (a hash definition).
*/
Buffer *pcp_export_perl_pub(pcp_key_t *sk);

/** Export a public key in C code format.
    Export a public key in C code format.

    \param sk a secret key structure of type pcp_key_t. The secret keys
            in there have to be already decrypted.

    \return the function returns a Buffer object containing the binary
            blob containing a C code string.
*/
Buffer *pcp_export_c_pub(pcp_key_t *sk);

/** Export secret key.

   Export a secret key.

   Secret key are exported in proprietary format.

   The exported binary blob is symmetrically encrypted using the NACL
   function crypto_secret(). The passphrase will be used to derive an
   encryption key using the STAR function scrypt().

   The binary data before encryption consists of:

   - ED25519 master signing secret
   - Curve25519 encryption secret
   - ED25519 signing secret
   - ED25519 master signing public
   - Curve25519 encryption public
   - ED25519 signing public
   - Optional notations, currently supported are the 'owner' and 'mail' attributes.
     If an attribute is empty, the len field contains zero.
     -# len(VAL) (2 byte uint)
     -# VAL (string without trailing zero)
   - 8 byte creation time (epoch)
   - 4 byte key version
   - 4 byte serial number

   The encrypted cipher will be prepended with the random nonce used
   to encrypt the data and looks after encryption as such:

     Nonce | Cipher

     \param[in] ptx context.

   \param sk a secret key structure of type pcp_key_t. The secret keys
          in there have to be already decrypted.

   \param passphrase the passphrase to be used to encrypt the export,
          a null terminated char array.

    \return the function returns a Buffer object containing the binary
            blob in the format described above.
*/
Buffer *pcp_export_secret(PCPCTX *ptx, pcp_key_t *sk, char *passphrase);

pcp_ks_bundle_t *pcp_import_binpub(PCPCTX *ptx, byte *raw, size_t rawsize);
pcp_ks_bundle_t *pcp_import_pub(PCPCTX *ptx, byte *raw, size_t rawsize); /* FIXME: deprecate */
pcp_ks_bundle_t *pcp_import_pub_rfc(PCPCTX *ptx, Buffer *blob);
pcp_ks_bundle_t *pcp_import_pub_pbp(PCPCTX *ptx, Buffer *blob);

/* import secret key */
pcp_key_t *pcp_import_binsecret(PCPCTX *ptx, byte *raw, size_t rawsize, char *passphrase);
pcp_key_t *pcp_import_secret(PCPCTX *ptx, byte *raw, size_t rawsize, char *passphrase);
pcp_key_t *pcp_import_secret_native(PCPCTX *ptx, Buffer *cipher, char *passphrase);

/* helpers */
int _check_keysig_h(PCPCTX *ptx, Buffer *blob, rfc_pub_sig_h *h);
int _check_hash_keysig(PCPCTX *ptx, Buffer *blob, pcp_pubkey_t *p, pcp_keysig_t *sk);
int _check_sigsubs(PCPCTX *ptx, Buffer *blob, pcp_pubkey_t *p, rfc_pub_sig_s *subheader);

#endif // _HAVE_PCP_MGMT_H

/**@}*/
