/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2014-2016 T.v.Dein.

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
#
#  ifndef __USE_XOPEN
#    define __USE_XOPEN 1
#  endif
#
#else
#  define _BSD_SOURCE 1
#endif

#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#ifdef HAVE_JSON
#include <jansson.h>
#endif

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

/* key management api, export, import, and stuff */


/**
 * \defgroup PubKeyExport KEYEXPORT
 * @{

 Functions to export and import keys in various formats.
 */





/** RFC4880 alike public key export with some modifications.

 (Refer to the INTERNALS section of the pcp(1) manual page for details.

\param sk a secret key structure of type pcp_key_t. The secret keys
          in there have to be already decrypted.

\return the function returns a Buffer object containing the binary
        blob in the format described above.
  
*/
Buffer *pcp_export_rfc_pub (PCPCTX *ptx, pcp_key_t *sk);



/** Export a public key in PBP format.
  Export a public key in the format described at
  https://github.com/stef/pbp/blob/master/doc/fileformats.txt

  \param sk a secret key structure of type pcp_key_t. The secret keys
            in there have to be already decrypted.

  \return the function returns a Buffer object containing the binary
          blob in the format described above.
 */
Buffer *pcp_export_pbp_pub(pcp_key_t *sk);

/** Export secret key.

   Export a secret key. (refer to the INTERNALS section of the pcp(1) manual page for details).

   \param[in] ptx context.

   \param sk a secret key structure of type pcp_key_t. The secret keys
          in there have to be already decrypted.

   \param passphrase the passphrase to be used to encrypt the export,
          a null terminated char array.

    \return the function returns a Buffer object containing the binary
            blob in the format described above.
*/
Buffer *pcp_export_secret(PCPCTX *ptx, pcp_key_t *sk, char *passphrase);

#ifdef HAVE_JSON
/** Export public key from a secret key in JSON format

    \param[in] sk a secret key structure of type pcp_key_t. The secret keys
            in there have to be already decrypted.
    \param[in] sig the keysig blob.

    \return the function returns a Buffer object containing the binary
            blob containing a JSON string.
 */
Buffer *pcp_export_json_pub(PCPCTX *ptx, pcp_key_t *sk, byte *sig, size_t siglen);

/** Export secret key in JSON format

    \param[in] sk a secret key structure of type pcp_key_t. The secret keys
            in there have to be already decrypted.
    \param[in] nonce the nonce used to encrypt secret keys
    \param[in] cipher the encrypted secret keys
    \param[in] clen len of cipher

    \return the function returns a Buffer object containing the binary
            blob containing a JSON string.
 */
Buffer *pcp_export_json_secret(PCPCTX *ptx, pcp_key_t *sk, byte *nonce, byte *cipher, size_t clen);

/** Convert secret key struct into JSON struct

    \param[in] sk a secret key structure of type pcp_key_t.
    \param[in] sig the keysig blob, maybe NULL.

    \return returns a json_t structure (see libjansson docs for details)
*/
json_t *pcp_sk2json(pcp_key_t *sk, byte *sig,size_t siglen);

/** Convert public key struct into JSON struct

    \param[in] pk a public key structure of type pcp_key_t.
    \param[in] sig the keysig blob, maybe NULL.

    \return returns a json_t structure (see libjansson docs for details)
*/
json_t *pcp_pk2json(pcp_pubkey_t *pk);

pcp_ks_bundle_t *pcp_import_pub_json(PCPCTX *ptx, byte *raw, size_t rawsize);
Buffer *pcp_import_secret_json(PCPCTX *ptx, Buffer *json);

#endif

pcp_ks_bundle_t *pcp_import_pub(PCPCTX *ptx, byte *raw, size_t rawsize);
pcp_ks_bundle_t *pcp_import_binpub(PCPCTX *ptx, byte *raw, size_t rawsize);
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
