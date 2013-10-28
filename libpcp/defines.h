#ifndef _DEFINES_H
#define _DEFINES_H

typedef unsigned char   byte;           //  Single unsigned byte = 8 bits
typedef unsigned short  dbyte;          //  Double byte = 16 bits
typedef unsigned int    qbyte;          //  Quad byte = 32 bits

// key stuff
#define PCP_KEY_HEADER "----- BEGIN PCP SECRET KEY -----"
#define PCP_KEY_FOOTER "------ END PCP SECRET KEY ------"

#define PCP_PUBKEY_HEADER "----- BEGIN PCP PUBLIC KEY -----"
#define PCP_PUBKEY_FOOTER "------ END PCP PUBLICKEY ------"

#define PCP_ENFILE_HEADER "----- BEGIN PCP ENCRYPTED FILE -----"
#define PCP_ENFILE_FOOTER "------ END PCP ENCRYPTED FILE ------"

#define PCP_ZFILE_HEADER "----- BEGIN Z85 ENCODED FILE -----"
#define PCP_ZFILE_FOOTER "------ END Z85 ENCODED FILE ------"

#define PCP_ME "Pretty Curved Privacy"

#define PCP_KEY_VERSION 0x00000001U
#define PCP_KEY_PRIMITIVE "CURVE25519-ED25519-SALSA20-POLY1305"

#define PCP_KEY_TYPE_MAINSECRET 0x01
#define PCP_KEY_TYPE_SECRET     0x02
#define PCP_KEY_TYPE_PUBLIC     0x03

// how many times do we hash a passphrase
#define HCYCLES 128000

// save typing, dammit
#define PCP_ENCRYPT_PAD crypto_secretbox_ZEROBYTES + crypto_secretbox_NONCEBYTES

// vault id
#define PCP_VAULT_ID 0xC4
#define PCP_VAULT_VERSION 0x01

char *PCP_ERR;
byte PCP_ERRSET;
int PCP_EXIT;

//set error
void fatal(const char * fmt, ...);

// fetch error
void fatals_ifany();

#endif // _DEFINES_H
