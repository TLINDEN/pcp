#ifndef _HAVE_PCP_KEYPAIR_H
#define _HAVE_PCP_KEYPAIR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/endian.h> // FIXME: put portable thing from scrypt here

#include "defines.h"
#include "mem.h"
#include "mac.h"
#include "randomart.h"
#include "version.h"
#include "z85.h"
#include "uthash.h"
#include "jenhash.h"

/*
  PCP private key structure. Most fields are self explanatory.
  Some notes:

  'encrypted' contains the encrypted secret key. If it's set,
  the field 'secret' which contains the clear secret key will
  be zeroed with random values, the first byte will be 0.

  'nonce' contains the nonce required to decrypt the encrypted
  secret, if set.

  'serial' is a random number.

  'id' is a string containing the hex values of the CRC32 checksum
  of the public and secret key.

  Upon creation everything will be filled with random bytes.
  String fields will contain a string followed by 0 followed
  by the rest of the pre-filled random bytes. To denote a string
  field as empty, the first byte will be set to 0.

  There are dynamically calculated attributes as well:

  'checksum' is a 256 bit SHA hash of the public key returned
  by pcpkey_getchecksum() or pcppubkey_getchecksum().

  'random id' is a random art ascii image returned by
  pcppubkey_get_art() or pcpkey_get_art(), calculated from
  the public key.

  If exported to a single file or printed, the structure will
  be encoded using Z85 encoding.

 */
struct _pcp_key_t {
  byte public[32];
  byte secret[32];
  byte nonce[24];
  byte encrypted[48];
  char owner[255];
  char mail[255];
  char id[17];
  long ctime;
  uint32_t version;
  uint32_t serial;
  uint8_t type;
  UT_hash_handle hh;
};

struct _pcp_pubkey_t {
  byte public[32];
  char owner[255];
  char mail[255];
  char id[17];
  long ctime;
  uint32_t version;
  uint32_t serial;
  uint8_t type;
  UT_hash_handle hh;
};

typedef struct _pcp_key_t pcp_key_t;
typedef struct _pcp_pubkey_t pcp_pubkey_t;

pcp_key_t *pcpkey_hash;
pcp_pubkey_t *pcppubkey_hash;

void pcp_cleanhashes();
pcp_key_t *pcpkey_new ();

char *pcppubkey_get_art(pcp_pubkey_t *k);
char *pcpkey_get_art(pcp_key_t *k);

pcp_key_t *pcpkey_encrypt(pcp_key_t *key, char *passphrase);
pcp_key_t *pcpkey_decrypt(pcp_key_t *key, char *passphrase);
pcp_pubkey_t *pcpkey_pub_from_secret(pcp_key_t *key);
char *pcp_getkeyid(pcp_key_t *k);
unsigned char *pcppubkey_getchecksum(pcp_pubkey_t *k);
unsigned char *pcpkey_getchecksum(pcp_key_t *k);
void pcp_inithashes();

pcp_key_t *pcpkey_exists(char *id);
pcp_pubkey_t *pcppubkey_exists(char *id);

pcp_key_t * key2be(pcp_key_t *k);
pcp_key_t *key2native(pcp_key_t *k);
pcp_pubkey_t * pubkey2be(pcp_pubkey_t *k);
pcp_pubkey_t *pubkey2native(pcp_pubkey_t *k);

unsigned char * pcp_gennonce();

void pcpedit_key(char *keyid);

#ifdef __cplusplus
}
#endif

#endif // _HAVE_PCP_KEYPAIR_H
