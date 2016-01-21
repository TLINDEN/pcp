PCP_RAW_CODE = '''

typedef enum {
    JSON_OBJECT,
    JSON_ARRAY,
    JSON_STRING,
    JSON_INTEGER,
    JSON_REAL,
    JSON_TRUE,
    JSON_FALSE,
    JSON_NULL
} json_type;

typedef struct json_t {
    json_type type;
    size_t refcount;
} json_t;

/*** ./gencffi.pl: from ../../include/pcp/defines.h:183 */
typedef unsigned char   byte;

/*** ./gencffi.pl: from ../../include/pcp/defines.h:183 */
typedef unsigned short  dbyte;

/*** ./gencffi.pl: from ../../include/pcp/defines.h:183 */
typedef unsigned int    qbyte;

/*** ./gencffi.pl: from ../../include/pcp/plist.h:83 */
typedef struct _plist_t plist_t;

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
typedef struct _pcp_key_t pcp_key_t;

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
typedef struct _pcp_pubkey_t pcp_pubkey_t;

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
typedef struct _pbp_pubkey_t pbp_pubkey_t;

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
typedef struct _pcp_rec_t pcp_rec_t;

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
typedef struct _pcp_keysig_t pcp_keysig_t;

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
typedef struct _pcp_ctx_t PCPCTX;

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
typedef struct _vault_t vault_t;

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
typedef struct _vault_header_t vault_header_t;

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
typedef struct _vault_item_header_t vault_item_header_t;

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
typedef struct _pcp_buffer Buffer;

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
typedef struct _pcp_stream_t Pcpstream;

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
typedef struct _pcp_rfc_pubkey_header_t rfc_pub_h;

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
typedef struct _pcp_rfc_pubkey_0x21_t  rfc_pub_k;

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
typedef struct _pcp_rfc_pubkey_sigheader_0x21_t rfc_pub_sig_h;

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
typedef struct _pcp_rfc_pubkey_sigsub_0x21_t rfc_pub_sig_s;

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
typedef struct _pcp_ks_bundle_t pcp_ks_bundle_t;
/*** ./gencffi.pl: from ../../include/pcp/plist.h:83 */
struct _plist_t {
  char *value;
  struct _plist_t *next;
  struct _plist_t *first;
};

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
struct _pcp_key_t {
  byte masterpub[LEDPUB];    /**< ED25519 master public key signing key */
  byte mastersecret[LEDSEC]; /**< ED25519 master secret key signing key */
  byte pub[LBOXPUB];         /**< Curve25519 encryption public key */
  byte secret[LBOXSEC];      /**< Curve25519 encryption secret key */
  byte edpub[LEDPUB];        /**< ED25519 public signing key */
  byte edsecret[LEDSEC];     /**< ED25519 secret signing key */
  byte nonce[LNONCE];        /**< random nonce used to encrypt secret keys */
  byte encrypted[LSEC];      /**< concatenated and encrypted secret keys */
  char owner[255];           /**< the key owner, string */
  char mail[255];            /**< mail address of the owner, string */
  char id[17];               /**< key-id, used internally only, jenhash of public keys */
  uint8_t type;              /**< key type: MASTER_SECRET or SECRET */
  uint64_t ctime;            /**< creation time, epoch */
  uint32_t version;          /**< key version */
  uint32_t serial;           /**< serial number of the key, randomly generated */
  byte hh[56];
};

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
struct _pcp_pubkey_t {
  byte masterpub[LEDPUB];    /**< ED25519 master public key signing key */
  byte pub[LBOXPUB];         /**< Curve25519 encryption public key */
  byte edpub[LEDPUB];        /**< ED25519 public signing key (FIXME: huh? 2 of them???) */
  char owner[255];           /**< the key owner, string */
  char mail[255];            /**< mail address of the owner, string */
  char id[17];               /**< key-id, used internally only, jenhash of public keys */
  uint8_t type;              /**< key type: MASTER_SECRET or SECRET */
  uint64_t ctime;            /**< creation time, epoch */
  uint32_t version;          /**< key version */
  uint32_t serial;           /**< serial number of the key, randomly generated */
  uint8_t valid;             /**< 1 if import signature verified, 0 if not */
  byte signature[128]; /**< raw binary blob of pubkey export signature */
  byte hh[56];
};

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
struct _pbp_pubkey_t {
  byte masterpub[32];
  byte edpub[32];
  byte pub[32];
  char iso_ctime[32];
  char iso_expire[32];
  char name[1024];
};

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
struct _pcp_rec_t {
  size_t ciphersize; /**< the size of the encrypted recipient list */
  byte *cipher;      /**< contains the whole encrypted recipient list */
  pcp_key_t *secret; /**< the secret key of the recipient for signing */
  pcp_pubkey_t *pub; /**< if verification were ok, contains the public key of the signer */
};

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
struct _pcp_keysig_t {
  uint8_t type;
  uint32_t size;
  char id[17];
  byte checksum[LSHA];
  byte *blob;
  byte hh[56];
};

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
struct _pcp_ctx_t {
  char *pcp_err;    /**< last error message. retrieve with fatals_ifany() */
  byte pcp_errset;  /**< indicates if an error occurred. */
  int  pcp_exit;    /**< exit code for pcp commandline utility */
  int  verbose;     /**< enable verbose output */
  int  json;        /**< enable json i/o */
  pcp_key_t *pcpkey_hash;       /**< hash containing for keys */
  pcp_pubkey_t *pcppubkey_hash; /**< hash for keys. */
  pcp_keysig_t *pcpkeysig_hash; /**< hash for key sigs */
};

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
struct _vault_t {
  char *filename;    /**< The filename of the vault (full path) */
  FILE *fd;          /**< Filehandle if opened */
  uint8_t unsafed;   /**< Flag to tell if the file needs to be written */
  uint8_t isnew;     /**< Flag to tell if the vault has been newly created */
  uint32_t size;     /**< Filesize */
  time_t modified;   /**< mtime */
  mode_t mode;       /**< File mode */
  uint32_t version;  /**< Vault version */
  byte checksum[LSHA]; /**< SHA256 checksum over the whole vault */
};

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
struct _vault_header_t {
  uint8_t fileid;    /**< File id, proprietary. Marks the vault as a vault */
  uint32_t version;  /**< File version */
  byte checksum[LSHA]; /**< SHA256 checksum over the whole vault */
};

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
struct _vault_item_header_t {
  uint8_t type;       /**< Item type (secret key, public, key, keysig, \see _PCP_KEY_TYPES */
  uint32_t size;      /**< Size of the item */
  uint32_t version;   /**< Version of the item */
  byte checksum[LSHA];  /**< SHA256 checksum of the item */
};

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
struct _pcp_buffer {
  char *name;        /**< just for convenience in error messages and the like, so we know which buffer cause trouble */
  uint8_t allocated; /**< marks the buffer as allocated */
  size_t blocksize;  /**< the blocksize to use when resizing, also used for initial malloc() */
  size_t size;       /**< stores the current allocated size of the object */
  size_t offset;     /**< current read position */
  size_t end;        /**< current write position, data end. maybe less than size. */
  uint8_t isstring;  /**< treat as char array/string */
  void *buf;         /**< the actual storage buffer */
};

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
struct _pcp_stream_t {
  FILE *fd;          /**< The backend FILE stream */
  Buffer *b;         /**< The backend Buffer object */
  Buffer *cache;     /**< The caching Buffer object (for look ahead read) */
  Buffer *next;      /**< The caching Next-Buffer object (for look ahead read) */
  Buffer *save;      /**< Temporary buffer to backup overflow data */
  uint8_t is_buffer; /**< Set to 1 if the backend is a Buffer */
  uint8_t eof;       /**< Set to 1 if EOF reached */
  uint8_t err;       /**< Set to 1 if an error occured */
  uint8_t armor;     /**< Set to 1 if Z85 en/de-coding is requested */
  uint8_t determine; /**< Set to 1 to automatically determine armor mode */
  uint8_t firstread; /**< Internal flag, will be set after first read() */
  size_t  linewr;    /**< Used for Z85 writing, number of chars written on last line */
  size_t  blocksize; /**< Blocksize used for z85, if requested */
  uint8_t is_output; /**< marks the stream as output stream */
  uint8_t have_begin; /**< flag to indicate we already got the begin header, if any */
  size_t pos;        /**< remember i/o position */
};

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
struct _pcp_rfc_pubkey_header_t {
  uint8_t version;
  uint64_t ctime;
  uint8_t cipher;
};

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
struct _pcp_rfc_pubkey_0x21_t {
  byte sig_ed25519_pub[32];
  byte ed25519_pub[32];
  byte curve25519_pub[32];
};

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
struct _pcp_rfc_pubkey_sigheader_0x21_t {
  uint8_t version;
  uint8_t type;
  uint8_t pkcipher;
  uint8_t hashcipher;
  uint16_t numsubs;
};

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
struct _pcp_rfc_pubkey_sigsub_0x21_t {
  uint32_t size;
  uint8_t type;
};

/*** ./gencffi.pl: from ../../include/pcp/structs.h:379 */
struct _pcp_ks_bundle_t {
  pcp_pubkey_t *p;
  pcp_keysig_t *s;
};
/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
Buffer *buffer_new(size_t blocksize, char *name);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
Buffer *buffer_new_str(char *name);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
Buffer *buffer_new_buf(char *name, void *data, size_t datasize);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
void buffer_init(Buffer *b, size_t blocksize, char *name);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
void buffer_free(Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
void buffer_clear(Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
void buffer_rewind(Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
void buffer_add(Buffer *b, const void *data, size_t len);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
void buffer_add_buf(Buffer *dst, Buffer *src);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
void buffer_add_str(Buffer *b, const char * fmt, ...);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
void buffer_add_hex(Buffer *b, void *data, size_t len);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
void buffer_resize(Buffer *b, size_t len);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
int buffer_done(Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
size_t buffer_get_chunk(Buffer *b, void *buf, size_t len);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
size_t buffer_get_chunk_tobuf(Buffer *b, Buffer *dst, size_t len);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
byte *buffer_get(Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
char *buffer_get_str(Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
byte *buffer_get_remainder(Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
size_t buffer_extract(Buffer *b, void *buf, size_t offset, size_t len);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
size_t buffer_fwd_offset(Buffer *b, size_t fwdby);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
void buffer_dump(const Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
void buffer_info(const Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
size_t buffer_size(const Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
size_t buffer_left(const Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
uint8_t buffer_get8(Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
uint16_t buffer_get16(Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
uint32_t buffer_get32(Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
uint64_t buffer_get64(Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
uint16_t buffer_get16na(Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
uint32_t buffer_get32na(Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
uint64_t buffer_get64na(Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
uint8_t  buffer_last8(Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
uint16_t buffer_last16(Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
uint32_t buffer_last32(Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
uint64_t buffer_last64(Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
size_t buffer_fd_read(Buffer *b, FILE *in, size_t len);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
void buffer_add8(Buffer *b, uint8_t v);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
void buffer_add16(Buffer *b, uint16_t v);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
void buffer_add32(Buffer *b, uint32_t v);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
void buffer_add64(Buffer *b, uint64_t v);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
void buffer_add16be(Buffer *b, uint16_t v);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
void buffer_add32be(Buffer *b, uint32_t v);

/*** ./gencffi.pl: from ../../include/pcp/buffer.h:654 */
void buffer_add64be(Buffer *b, uint64_t v);

/*** ./gencffi.pl: from ../../include/pcp/context.h:96 */
PCPCTX *ptx_new();

/*** ./gencffi.pl: from ../../include/pcp/context.h:96 */
void ptx_clean(PCPCTX *ptx);

/*** ./gencffi.pl: from ../../include/pcp/context.h:96 */
void fatal(PCPCTX *ptx, const char * fmt, ...);

/*** ./gencffi.pl: from ../../include/pcp/context.h:96 */
void fatals_ifany(PCPCTX *ptx);

/*** ./gencffi.pl: from ../../include/pcp/context.h:96 */
void fatals_reset(PCPCTX *ptx);

/*** ./gencffi.pl: from ../../include/pcp/context.h:96 */
void final(const char * fmt, ...);

/*** ./gencffi.pl: from ../../include/pcp/context.h:96 */
void ptx_dump(PCPCTX *ptx);

/*** ./gencffi.pl: from ../../include/pcp/crypto.h:354 */
size_t pcp_encrypt_stream_sym(PCPCTX *ptx, Pcpstream *in, Pcpstream* out, byte *symkey, int havehead, pcp_rec_t *recsign);

/*** ./gencffi.pl: from ../../include/pcp/crypto.h:354 */
size_t pcp_decrypt_stream(PCPCTX *ptx, Pcpstream *in, Pcpstream* out, pcp_key_t *s, byte *symkey, int verify, int anon);

/*** ./gencffi.pl: from ../../include/pcp/crypto.h:354 */
size_t pcp_decrypt_stream_sym(PCPCTX *ptx, Pcpstream *in, Pcpstream* out, byte *symkey, pcp_rec_t *recverify);

/*** ./gencffi.pl: from ../../include/pcp/crypto.h:354 */
int pcp_checksum(PCPCTX *ptx, Pcpstream *in, byte *checksum, byte *key, size_t keylen);

/*** ./gencffi.pl: from ../../include/pcp/crypto.h:354 */
pcp_rec_t *pcp_rec_new(byte *cipher, size_t clen, pcp_key_t *secret, pcp_pubkey_t *pub);

/*** ./gencffi.pl: from ../../include/pcp/crypto.h:354 */
void pcp_rec_free(pcp_rec_t *r);

/*** ./gencffi.pl: from ../../include/pcp/crypto.h:354 */
byte *_gen_ctr_nonce(uint64_t ctr);

/*** ./gencffi.pl: from ../../include/pcp/crypto.h:354 */
uint64_t _get_nonce_ctr(byte *nonce);

/*** ./gencffi.pl: from ../../include/pcp/ed.h:202 */
byte *pcp_ed_sign(byte *message, size_t messagesize, pcp_key_t *s);

/*** ./gencffi.pl: from ../../include/pcp/ed.h:202 */
byte *pcp_ed_verify(PCPCTX *ptx, byte *signature, size_t siglen, pcp_pubkey_t *p);

/*** ./gencffi.pl: from ../../include/pcp/ed.h:202 */
byte *pcp_ed_verify_key(PCPCTX *ptx, byte *signature, size_t siglen, pcp_pubkey_t *p);

/*** ./gencffi.pl: from ../../include/pcp/ed.h:202 */
size_t pcp_ed_sign_buffered(PCPCTX *ptx, Pcpstream *in, Pcpstream *out, pcp_key_t *s, int z85);

/*** ./gencffi.pl: from ../../include/pcp/ed.h:202 */
pcp_pubkey_t *pcp_ed_verify_buffered(PCPCTX *ptx, Pcpstream *in, pcp_pubkey_t *p);

/*** ./gencffi.pl: from ../../include/pcp/ed.h:202 */
size_t pcp_ed_detachsign_buffered(Pcpstream *in, Pcpstream *out, pcp_key_t *s);

/*** ./gencffi.pl: from ../../include/pcp/ed.h:202 */
pcp_pubkey_t *pcp_ed_detachverify_buffered(PCPCTX *ptx, Pcpstream *in, Pcpstream *sigfd, pcp_pubkey_t *p);

/*** ./gencffi.pl: from ../../include/pcp/getpass.h:22 */
void pcp_echo_off();

/*** ./gencffi.pl: from ../../include/pcp/getpass.h:22 */
void pcp_echo_on();

/*** ./gencffi.pl: from ../../include/pcp/getpass.h:22 */
char *pcp_get_stdin();

/*** ./gencffi.pl: from ../../include/pcp/getpass.h:22 */
char *pcp_get_passphrase(char *prompt);

/*** ./gencffi.pl: from ../../include/pcp/jenhash.h:25 */
unsigned jen_hash ( unsigned char *k, unsigned length, unsigned initval );

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
pcp_key_t *pcpkey_new ();

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
void pcp_keypairs(byte *msk, byte *mpk, byte *csk, byte *cpk, byte *esk, byte *epk);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
char *pcppubkey_get_art(pcp_pubkey_t *k);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
char *pcpkey_get_art(pcp_key_t *k);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
pcp_key_t *pcpkey_encrypt(PCPCTX *ptx, pcp_key_t *key, char *passphrase);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
pcp_key_t *pcpkey_decrypt(PCPCTX *ptx, pcp_key_t *key, char *passphrase);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
pcp_pubkey_t *pcpkey_pub_from_secret(pcp_key_t *key);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
char *pcp_getkeyid(pcp_key_t *k);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
char *pcp_getpubkeyid(pcp_pubkey_t *k);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
byte *pcppubkey_getchecksum(pcp_pubkey_t *k);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
byte *pcpkey_getchecksum(pcp_key_t *k);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
pcp_key_t * key2be(pcp_key_t *k);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
pcp_key_t *key2native(pcp_key_t *k);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
pcp_pubkey_t * pubkey2be(pcp_pubkey_t *k);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
pcp_pubkey_t *pubkey2native(pcp_pubkey_t *k);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
byte * pcp_gennonce();

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
byte *pcp_derivekey(PCPCTX *ptx, char *passphrase, byte *nonce);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
void pcp_seckeyblob(Buffer *b, pcp_key_t *k);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
void pcp_pubkeyblob(Buffer *b, pcp_pubkey_t *k);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
Buffer *pcp_keyblob(void *k, int type);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
int pcp_sanitycheck_pub(PCPCTX *ptx, pcp_pubkey_t *key);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
int pcp_sanitycheck_key(PCPCTX *ptx, pcp_key_t *key);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
void pcp_dumpkey(pcp_key_t *k);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
void pcp_dumppubkey(pcp_pubkey_t *k);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
void pcpkey_setowner(pcp_key_t *key, char *owner, char *mail);

/*** ./gencffi.pl: from ../../include/pcp/key.h:320 */
double pcp_getentropy(char *source);

/*** ./gencffi.pl: from ../../include/pcp/keyhash.h:153 */
void pcphash_del(PCPCTX *ptx, void *key, int type);

/*** ./gencffi.pl: from ../../include/pcp/keyhash.h:153 */
void pcphash_clean(PCPCTX *ptx);

/*** ./gencffi.pl: from ../../include/pcp/keyhash.h:153 */
void pcphash_cleanpub(pcp_pubkey_t *pub);

/*** ./gencffi.pl: from ../../include/pcp/keyhash.h:153 */
pcp_key_t *pcphash_keyexists(PCPCTX *ptx, char *id);

/*** ./gencffi.pl: from ../../include/pcp/keyhash.h:153 */
pcp_pubkey_t *pcphash_pubkeyexists(PCPCTX *ptx, char *id);

/*** ./gencffi.pl: from ../../include/pcp/keyhash.h:153 */
void pcphash_add(PCPCTX *ptx, void *key, int type);

/*** ./gencffi.pl: from ../../include/pcp/keyhash.h:153 */
int pcphash_count(PCPCTX *ptx);

/*** ./gencffi.pl: from ../../include/pcp/keyhash.h:153 */
int pcphash_countpub(PCPCTX *ptx);

/*** ./gencffi.pl: from ../../include/pcp/keyhash.h:153 */
pcp_keysig_t *pcphash_keysigexists(PCPCTX *ptx, char *id);

/*** ./gencffi.pl: from ../../include/pcp/keysig.h:52 */
pcp_keysig_t *keysig2be(pcp_keysig_t *s);

/*** ./gencffi.pl: from ../../include/pcp/keysig.h:52 */
pcp_keysig_t *keysig2native(pcp_keysig_t *s);

/*** ./gencffi.pl: from ../../include/pcp/keysig.h:52 */
Buffer *pcp_keysig2blob(pcp_keysig_t *s);

/*** ./gencffi.pl: from ../../include/pcp/keysig.h:52 */
pcp_keysig_t *pcp_keysig_new(Buffer *blob);

/*** ./gencffi.pl: from ../../include/pcp/keysig.h:52 */
void pcp_dumpkeysig(pcp_keysig_t *s);

/*** ./gencffi.pl: from ../../include/pcp/mem.h:58 */
void *ucmalloc(size_t s);

/*** ./gencffi.pl: from ../../include/pcp/mem.h:58 */
void *smalloc(size_t s);

/*** ./gencffi.pl: from ../../include/pcp/mem.h:58 */
void *urmalloc(size_t s);

/*** ./gencffi.pl: from ../../include/pcp/mem.h:58 */
void *srmalloc(size_t s);

/*** ./gencffi.pl: from ../../include/pcp/mem.h:58 */
void *ucrealloc(void *d, size_t oldlen, size_t newlen);

/*** ./gencffi.pl: from ../../include/pcp/mem.h:58 */
void ucfree(void *d, size_t len);

/*** ./gencffi.pl: from ../../include/pcp/mem.h:58 */
void sfree(void *d);

/*** ./gencffi.pl: from ../../include/pcp/mgmt.h:188 */
Buffer *pcp_export_rfc_pub (PCPCTX *ptx, pcp_key_t *sk);

/*** ./gencffi.pl: from ../../include/pcp/mgmt.h:188 */
Buffer *pcp_export_pbp_pub(pcp_key_t *sk);

/*** ./gencffi.pl: from ../../include/pcp/mgmt.h:188 */
Buffer *pcp_export_secret(PCPCTX *ptx, pcp_key_t *sk, char *passphrase);

/*** ./gencffi.pl: from ../../include/pcp/mgmt.h:188 */
Buffer *pcp_export_json_pub(PCPCTX *ptx, pcp_key_t *sk, byte *sig, size_t siglen);

/*** ./gencffi.pl: from ../../include/pcp/mgmt.h:188 */
Buffer *pcp_export_json_secret(PCPCTX *ptx, pcp_key_t *sk, byte *nonce, byte *cipher, size_t clen);

/*** ./gencffi.pl: from ../../include/pcp/mgmt.h:188 */
json_t *pcp_sk2json(pcp_key_t *sk, byte *sig,size_t siglen);

/*** ./gencffi.pl: from ../../include/pcp/mgmt.h:188 */
json_t *pcp_pk2json(pcp_pubkey_t *pk);

/*** ./gencffi.pl: from ../../include/pcp/mgmt.h:188 */
pcp_ks_bundle_t *pcp_import_pub_json(PCPCTX *ptx, byte *raw, size_t rawsize);

/*** ./gencffi.pl: from ../../include/pcp/mgmt.h:188 */
Buffer *pcp_import_secret_json(PCPCTX *ptx, Buffer *json);

/*** ./gencffi.pl: from ../../include/pcp/mgmt.h:188 */
pcp_ks_bundle_t *pcp_import_pub(PCPCTX *ptx, byte *raw, size_t rawsize);

/*** ./gencffi.pl: from ../../include/pcp/mgmt.h:188 */
pcp_ks_bundle_t *pcp_import_binpub(PCPCTX *ptx, byte *raw, size_t rawsize);

/*** ./gencffi.pl: from ../../include/pcp/mgmt.h:188 */
pcp_ks_bundle_t *pcp_import_pub_rfc(PCPCTX *ptx, Buffer *blob);

/*** ./gencffi.pl: from ../../include/pcp/mgmt.h:188 */
pcp_ks_bundle_t *pcp_import_pub_pbp(PCPCTX *ptx, Buffer *blob);

/*** ./gencffi.pl: from ../../include/pcp/mgmt.h:188 */
pcp_key_t *pcp_import_binsecret(PCPCTX *ptx, byte *raw, size_t rawsize, char *passphrase);

/*** ./gencffi.pl: from ../../include/pcp/mgmt.h:188 */
pcp_key_t *pcp_import_secret(PCPCTX *ptx, byte *raw, size_t rawsize, char *passphrase);

/*** ./gencffi.pl: from ../../include/pcp/mgmt.h:188 */
pcp_key_t *pcp_import_secret_native(PCPCTX *ptx, Buffer *cipher, char *passphrase);

/*** ./gencffi.pl: from ../../include/pcp/mgmt.h:188 */
int _check_keysig_h(PCPCTX *ptx, Buffer *blob, rfc_pub_sig_h *h);

/*** ./gencffi.pl: from ../../include/pcp/mgmt.h:188 */
int _check_hash_keysig(PCPCTX *ptx, Buffer *blob, pcp_pubkey_t *p, pcp_keysig_t *sk);

/*** ./gencffi.pl: from ../../include/pcp/mgmt.h:188 */
int _check_sigsubs(PCPCTX *ptx, Buffer *blob, pcp_pubkey_t *p, rfc_pub_sig_s *subheader);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
Pcpstream *ps_init(void);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
Pcpstream *ps_new_file(FILE *backendfd);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
Pcpstream *ps_new_inbuffer(Buffer *b);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
Pcpstream *ps_new_outbuffer();

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
size_t ps_read(Pcpstream *stream, void *buf, size_t readbytes);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
size_t ps_write(Pcpstream *stream, void *buf, size_t writebytes);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
size_t ps_finish(Pcpstream *stream);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
size_t ps_print(Pcpstream *stream, const char * fmt, ...);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
size_t ps_tell(Pcpstream *stream);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
Buffer *ps_buffer(Pcpstream *stream);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
void ps_close(Pcpstream *stream);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
int ps_end(Pcpstream *stream);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
int ps_err(Pcpstream *stream);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
void ps_setdetermine(Pcpstream *stream, size_t blocksize);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
void ps_armor(Pcpstream *stream, size_t blocksize);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
void ps_unarmor(Pcpstream *stream);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
size_t ps_read_decode(Pcpstream *stream);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
void ps_determine(Pcpstream *stream);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
size_t ps_read_next(Pcpstream *stream);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
size_t ps_read_cached(Pcpstream *stream, void *buf, size_t readbytes);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
size_t ps_read_raw(Pcpstream *stream, void *buf, size_t readbytes);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
void ps_write_encode(Pcpstream *stream, Buffer *dst);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
size_t ps_write_buf(Pcpstream *stream, Buffer *z);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
int ps_left(Pcpstream *stream);

/*** ./gencffi.pl: from ../../include/pcp/pcpstream.h:291 */
int ps_readline(Pcpstream *stream, Buffer *line);

/*** ./gencffi.pl: from ../../include/pcp/randomart.h:54 */
char *key_fingerprint_randomart(unsigned char *dgst_raw, unsigned int dgst_raw_len);

/*** ./gencffi.pl: from ../../include/pcp/readpass.h:69 */
int pcp_readpass_fromprog(PCPCTX *ptx, char **passwd, const char *askpass);

/*** ./gencffi.pl: from ../../include/pcp/scrypt.h:42 */
byte * pcp_scrypt(PCPCTX *ptx, char *passwd, size_t passwdlen, byte *nonce, size_t noncelen);

/*** ./gencffi.pl: from ../../include/pcp/util.h:128 */
char *_lc(char *in);

/*** ./gencffi.pl: from ../../include/pcp/util.h:128 */
long int _findoffset(byte *bin, size_t binlen, char *sigstart, size_t hlen);

/*** ./gencffi.pl: from ../../include/pcp/util.h:128 */
void _xorbuf(byte *iv, byte *buf, size_t xlen);

/*** ./gencffi.pl: from ../../include/pcp/util.h:128 */
void _dump(char *n, byte *d, size_t s);

/*** ./gencffi.pl: from ../../include/pcp/util.h:128 */
char *_bin2hex(byte *bin, size_t len);

/*** ./gencffi.pl: from ../../include/pcp/util.h:128 */
size_t _hex2bin(const char *hex_str, unsigned char *byte_array, size_t byte_array_max);

/*** ./gencffi.pl: from ../../include/pcp/util.h:128 */
int cst_time_memcmp(const void *m1, const void *m2, size_t n);

/*** ./gencffi.pl: from ../../include/pcp/vault.h:230 */
vault_t *pcpvault_init(PCPCTX *ptx, char *filename);

/*** ./gencffi.pl: from ../../include/pcp/vault.h:230 */
vault_t *pcpvault_new(PCPCTX *ptx, char *filename, int is_tmp);

/*** ./gencffi.pl: from ../../include/pcp/vault.h:230 */
int pcpvault_create(PCPCTX *ptx, vault_t *vault);

/*** ./gencffi.pl: from ../../include/pcp/vault.h:230 */
int pcpvault_additem(PCPCTX *ptx, vault_t *vault, void *item, size_t itemsize, uint8_t type);

/*** ./gencffi.pl: from ../../include/pcp/vault.h:230 */
int pcpvault_addkey(PCPCTX *ptx, vault_t *vault, void *item, uint8_t type);

/*** ./gencffi.pl: from ../../include/pcp/vault.h:230 */
int pcpvault_close(PCPCTX *ptx, vault_t *vault);

/*** ./gencffi.pl: from ../../include/pcp/vault.h:230 */
void pcpvault_free(vault_t *vault);

/*** ./gencffi.pl: from ../../include/pcp/vault.h:230 */
int pcpvault_fetchall(PCPCTX *ptx, vault_t *vault);

/*** ./gencffi.pl: from ../../include/pcp/vault.h:230 */
int pcpvault_writeall(PCPCTX *ptx, vault_t *vault);

/*** ./gencffi.pl: from ../../include/pcp/vault.h:230 */
int pcpvault_copy(PCPCTX *ptx, vault_t *tmp, vault_t *vault);

/*** ./gencffi.pl: from ../../include/pcp/vault.h:230 */
void pcpvault_unlink(vault_t *tmp);

/*** ./gencffi.pl: from ../../include/pcp/vault.h:230 */
byte *pcpvault_create_checksum(PCPCTX *ptx);

/*** ./gencffi.pl: from ../../include/pcp/vault.h:230 */
void pcpvault_update_checksum(PCPCTX *ptx, vault_t *vault);

/*** ./gencffi.pl: from ../../include/pcp/vault.h:230 */
vault_header_t * vh2be(vault_header_t *h);

/*** ./gencffi.pl: from ../../include/pcp/vault.h:230 */
vault_header_t * vh2native(vault_header_t *h);

/*** ./gencffi.pl: from ../../include/pcp/vault.h:230 */
vault_item_header_t * ih2be(vault_item_header_t *h);

/*** ./gencffi.pl: from ../../include/pcp/vault.h:230 */
vault_item_header_t * ih2native(vault_item_header_t *h);

/*** ./gencffi.pl: from ../../include/pcp/version.h:35 */
int pcp_version();

/*** ./gencffi.pl: from ../../include/pcp/z85.h:166 */
byte *pcp_padfour(byte *src, size_t srclen, size_t *dstlen);

/*** ./gencffi.pl: from ../../include/pcp/z85.h:166 */
byte *pcp_z85_decode(PCPCTX *ptx, char *z85block, size_t *dstlen);

/*** ./gencffi.pl: from ../../include/pcp/z85.h:166 */
char *pcp_z85_encode(byte *raw, size_t srclen, size_t *dstlen, int doblock);

/*** ./gencffi.pl: from ../../include/pcp/z85.h:166 */
char *pcp_readz85file(PCPCTX *ptx, FILE *infile);

/*** ./gencffi.pl: from ../../include/pcp/z85.h:166 */
char *pcp_readz85string(PCPCTX *ptx, byte *input, size_t bufsize);

/*** ./gencffi.pl: from ../../include/pcp/z85.h:166 */
uint8_t is_utf8(const byte * bytes);

/*** ./gencffi.pl: from ../../include/pcp/z85.h:166 */
size_t _buffer_is_binary(byte *buf, size_t len);

/*** ./gencffi.pl: from ../../include/pcp/z85.h:166 */
uint8_t _parse_zchar(Buffer *z, uint8_t c, uint8_t is_comment);

/*** ./gencffi.pl: from ../../include/pcp/z85.h:166 */
long int z85_header_startswith(Buffer *buf, char *what);

/*** ./gencffi.pl: from ../../include/pcp/z85.h:166 */
int z85_isheader(Buffer *buf);

/*** ./gencffi.pl: from ../../include/pcp/z85.h:166 */
int z85_isend(Buffer *buf);

/*** ./gencffi.pl: from ../../include/pcp/z85.h:166 */
int z85_isbegin(Buffer *buf);

/*** ./gencffi.pl: from ../../include/pcp/z85.h:166 */
int z85_iscomment(Buffer *buf);

/*** ./gencffi.pl: from ../../include/pcp/z85.h:166 */
int z85_isempty(Buffer *line);

/*** ./gencffi.pl: from ../../include/pcp/z85.h:166 */
int z85_isencoded(Buffer *line);

/*** ./gencffi.pl: from ../../include/pcp/zmq_z85.h:31 */
uint8_t *zmq_z85_decode (uint8_t *dest, char *string);

/*** ./gencffi.pl: from ../../include/pcp/zmq_z85.h:31 */
char *zmq_z85_encode (char *dest, uint8_t *data, size_t size);'''

# ./gencffi.pl: from ../../include/pcp/defines.h:183
PCP_ASYM_CIPHER = 5


# ./gencffi.pl: from ../../include/pcp/defines.h:183
PCP_BLOCK_SIZE = 32 * 1024


# ./gencffi.pl: from ../../include/pcp/defines.h:183
EXP_PK_HEADER = "----- BEGIN ED25519-CURVE29915 PUBLIC KEY -----"


# ./gencffi.pl: from ../../include/pcp/defines.h:183
EXP_SK_FOOTER = "----- END ED25519-CURVE29915 PRIVATE KEY -----"


# ./gencffi.pl: from ../../include/pcp/defines.h:183
PCP_ENFILE_HEADER = "----- BEGIN PCP ENCRYPTED FILE -----\r\n"


# ./gencffi.pl: from ../../include/pcp/defines.h:183
EXP_FORMAT_NATIVE = 1


# ./gencffi.pl: from ../../include/pcp/defines.h:183
PBP_COMPAT_SALT = "qa~t](84z<1t<1oz:ik.@IRNyhG=8q(on9}4#!/_h#a7wqK{Nt$T?W>,mt8NqYq&6U<GB1$,<$j>,rSYI2GRDd:Bcm"


# ./gencffi.pl: from ../../include/pcp/defines.h:183
EXP_HASH_CIPHER = 0x22


# ./gencffi.pl: from ../../include/pcp/defines.h:183
EXP_HASH_NAME = "BLAKE2"


# ./gencffi.pl: from ../../include/pcp/defines.h:183
EXP_SIG_SUB_NOTATION = 20


# ./gencffi.pl: from ../../include/pcp/defines.h:183
EXP_SIG_CIPHER_NAME = "ED25519"


# ./gencffi.pl: from ../../include/pcp/defines.h:183
EXP_SIG_CIPHER = 0x23


# ./gencffi.pl: from ../../include/pcp/defines.h:183
PCP_ZFILE_HEADER = "----- BEGIN Z85 ENCODED FILE -----"


# ./gencffi.pl: from ../../include/pcp/defines.h:183
PCP_SIG_END = "----- END ED25519 SIGNATURE -----"


# ./gencffi.pl: from ../../include/pcp/defines.h:183
EXP_PK_CIPHER = 0x21


# ./gencffi.pl: from ../../include/pcp/defines.h:183
PCP_RFC_CIPHER = 0x21 


# ./gencffi.pl: from ../../include/pcp/defines.h:183
PCP_ASYM_CIPHER_ANON = 6


# ./gencffi.pl: from ../../include/pcp/defines.h:183
PCP_ENFILE_FOOTER = "\r\n----- END PCP ENCRYPTED FILE -----\r\n"


# ./gencffi.pl: from ../../include/pcp/defines.h:183
PCP_SYM_CIPHER = 23


# ./gencffi.pl: from ../../include/pcp/defines.h:183
EXP_SIG_TYPE = 0x1F 


# ./gencffi.pl: from ../../include/pcp/defines.h:183
EXP_SIG_SUB_KEYFLAGS = 27


# ./gencffi.pl: from ../../include/pcp/defines.h:183
EXP_SK_HEADER = "----- BEGIN ED25519-CURVE29915 PRIVATE KEY -----"


# ./gencffi.pl: from ../../include/pcp/defines.h:183
PCP_SIGPREFIX = "\nnacl-"


# ./gencffi.pl: from ../../include/pcp/defines.h:183
PCP_ME = "Pretty Curved Privacy"


# ./gencffi.pl: from ../../include/pcp/defines.h:183
PCP_ZFILE_FOOTER = "----- END Z85 ENCODED FILE -----"


# ./gencffi.pl: from ../../include/pcp/defines.h:183
EXP_SIG_SUB_SIGEXPIRE = 3


# ./gencffi.pl: from ../../include/pcp/defines.h:183
EXP_SIG_SUB_CTIME = 2


# ./gencffi.pl: from ../../include/pcp/defines.h:183
EXP_PK_FOOTER = "----- END ED25519-CURVE29915 PUBLIC KEY -----"


# ./gencffi.pl: from ../../include/pcp/defines.h:183
PCP_VAULT_ID = 14


# ./gencffi.pl: from ../../include/pcp/defines.h:183
PCP_ASYM_CIPHER_ANON_SIG = 7


# ./gencffi.pl: from ../../include/pcp/defines.h:183
PCP_SIG_HEADER = "----- BEGIN ED25519 SIGNED MESSAGE -----"


# ./gencffi.pl: from ../../include/pcp/defines.h:183
PCP_ASYM_CIPHER_SIG = 24


# ./gencffi.pl: from ../../include/pcp/defines.h:183
EXP_PK_CIPHER_NAME = "CURVE25519-ED25519-POLY1305-SALSA20"


# ./gencffi.pl: from ../../include/pcp/defines.h:183
EXP_FORMAT_PBP = 2


# ./gencffi.pl: from ../../include/pcp/defines.h:183
EXP_SIG_SUB_KEYEXPIRE = 9


# ./gencffi.pl: from ../../include/pcp/defines.h:183
PCP_SIG_START = "----- BEGIN ED25519 SIGNATURE -----"
