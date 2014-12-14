PCP_RAW_CODE = '''

/*** bindings/py/gencffi.pl: from include/pcp/defines.h:187 */
typedef unsigned char   byte;

/*** bindings/py/gencffi.pl: from include/pcp/defines.h:187 */
typedef unsigned short  dbyte;

/*** bindings/py/gencffi.pl: from include/pcp/defines.h:187 */
typedef unsigned int    qbyte;

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
typedef struct _pcp_key_t pcp_key_t;

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
typedef struct _pcp_pubkey_t pcp_pubkey_t;

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
typedef struct _pbp_pubkey_t pbp_pubkey_t;

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
typedef struct _pcp_rec_t pcp_rec_t;

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
typedef struct _pcp_keysig_t pcp_keysig_t;

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
typedef struct _pcp_ctx_t PCPCTX;

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
typedef struct _vault_t vault_t;

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
typedef struct _vault_header_t vault_header_t;

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
typedef struct _vault_item_header_t vault_item_header_t;

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
typedef struct _pcp_buffer Buffer;

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
typedef struct _pcp_stream_t Pcpstream;

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
typedef struct _pcp_rfc_pubkey_header_t rfc_pub_h;

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
typedef struct _pcp_rfc_pubkey_0x21_t  rfc_pub_k;

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
typedef struct _pcp_rfc_pubkey_sigheader_0x21_t rfc_pub_sig_h;

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
typedef struct _pcp_rfc_pubkey_sigsub_0x21_t rfc_pub_sig_s;

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
typedef struct _pcp_ks_bundle_t pcp_ks_bundle_t;

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
struct _pcp_key_t {
  byte masterpub[32];    /**< ED25519 master public key signing key */
  byte mastersecret[64]; /**< ED25519 master secret key signing key */
  byte pub[32];          /**< Curve25519 encryption public key */
  byte secret[32];       /**< Curve25519 encryption secret key */
  byte edpub[32];        /**< ED25519 public signing key */
  byte edsecret[64];     /**< ED25519 secret signing key */
  byte nonce[24];        /**< random nonce used to encrypt secret keys */
  byte encrypted[176];   /**< concatenated and encrypted secret keys */
  char owner[255];       /**< the key owner, string */
  char mail[255];        /**< mail address of the owner, string */
  char id[17];           /**< key-id, used internally only, jenhash of public keys */
  uint8_t type;          /**< key type: MASTER_SECRET or SECRET */
  uint64_t ctime;        /**< creation time, epoch */
  uint32_t version;      /**< key version */
  uint32_t serial;       /**< serial number of the key, randomly generated */
  byte hh[56];
};

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
struct _pcp_pubkey_t {
  byte masterpub[32];    /**< ED25519 master public key signing key */
  byte sigpub[32];       /**< ED25519 public signing key */
  byte pub[32];          /**< Curve25519 encryption public key */
  byte edpub[32];        /**< ED25519 public signing key (FIXME: huh? 2 of them???) */
  char owner[255];       /**< the key owner, string */
  char mail[255];        /**< mail address of the owner, string */
  char id[17];           /**< key-id, used internally only, jenhash of public keys */
  uint8_t type;          /**< key type: MASTER_SECRET or SECRET */
  uint64_t ctime;        /**< creation time, epoch */
  uint32_t version;      /**< key version */
  uint32_t serial;       /**< serial number of the key, randomly generated */
  uint8_t valid;         /**< 1 if import signature verified, 0 if not */
  byte signature[128]; /**< raw binary blob of pubkey export signature */
  byte hh[56];
};

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
struct _pbp_pubkey_t {
  byte sigpub[32];
  byte edpub[32];
  byte pub[32];
  char iso_ctime[32];
  char iso_expire[32];
  char name[1024];
};

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
struct _pcp_rec_t {
  size_t ciphersize; /**< the size of the encrypted recipient list */
  byte *cipher;      /**< contains the whole encrypted recipient list */
  pcp_key_t *secret; /**< the secret key of the recipient for signing */
  pcp_pubkey_t *pub; /**< if verification were ok, contains the public key of the signer */
};

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
struct _pcp_keysig_t {
  uint8_t type;
  uint32_t size;
  char id[17];
  byte checksum[32];
  byte *blob;
  byte hh[56];
};

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
struct _pcp_ctx_t {
  char *pcp_err;    /**< last error message. retrieve with fatals_ifany() */
  byte pcp_errset;  /**< indicates if an error occurred. */
  int  pcp_exit;    /**< exit code for pcp commandline utility */
  int  verbose;     /**< enable verbose output */

  pcp_key_t *pcpkey_hash;       /**< hash containing for keys */
  pcp_pubkey_t *pcppubkey_hash; /**< hash for keys. */
  pcp_keysig_t *pcpkeysig_hash; /**< hash for key sigs */
};

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
struct _vault_t {
  char *filename;    /**< The filename of the vault (full path) */
  FILE *fd;          /**< Filehandle if opened */
  uint8_t unsafed;   /**< Flag to tell if the file needs to be written */
  uint8_t isnew;     /**< Flag to tell if the vault has been newly created */
  uint32_t size;     /**< Filesize */
  time_t modified;   /**< mtime */
  mode_t mode;       /**< File mode */
  uint32_t version;  /**< Vault version */
  byte checksum[32]; /**< SHA256 checksum over the whole vault */
};

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
struct _vault_header_t {
  uint8_t fileid;    /**< File id, proprietary. Marks the vault as a vault */
  uint32_t version;  /**< File version */
  byte checksum[32]; /**< SHA256 checksum over the whole vault */
};

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
struct _vault_item_header_t {
  uint8_t type;       /**< Item type (secret key, public, key, keysig, \see _PCP_KEY_TYPES */
  uint32_t size;      /**< Size of the item */
  uint32_t version;   /**< Version of the item */
  byte checksum[32];  /**< SHA256 checksum of the item */
};

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
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

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
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

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
struct _pcp_rfc_pubkey_header_t {
  uint8_t version;
  uint64_t ctime;
  uint8_t cipher;
};

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
struct _pcp_rfc_pubkey_0x21_t {
  byte sig_ed25519_pub[32];
  byte ed25519_pub[32];
  byte curve25519_pub[32];
};

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
struct _pcp_rfc_pubkey_sigheader_0x21_t {
  uint8_t version;
  uint8_t type;
  uint8_t pkcipher;
  uint8_t hashcipher;
  uint16_t numsubs;
};

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
struct _pcp_rfc_pubkey_sigsub_0x21_t {
  uint32_t size;
  uint8_t type;
};

/*** bindings/py/gencffi.pl: from include/pcp/structs.h:571 */
struct _pcp_ks_bundle_t {
  pcp_pubkey_t *p;
  pcp_keysig_t *s;
};

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
pcp_key_t *pcpkey_new ();

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
void pcp_keypairs(byte *msk, byte *mpk, byte *csk, byte *cpk, byte *esk, byte *epk);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
char *pcppubkey_get_art(pcp_pubkey_t *k);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
char *pcpkey_get_art(pcp_key_t *k);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
pcp_key_t *pcpkey_encrypt(PCPCTX *ptx, pcp_key_t *key, char *passphrase);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
pcp_key_t *pcpkey_decrypt(PCPCTX *ptx, pcp_key_t *key, char *passphrase);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
pcp_pubkey_t *pcpkey_pub_from_secret(pcp_key_t *key);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
char *pcp_getkeyid(pcp_key_t *k);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
char *pcp_getpubkeyid(pcp_pubkey_t *k);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
byte *pcppubkey_getchecksum(pcp_pubkey_t *k);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
byte *pcpkey_getchecksum(pcp_key_t *k);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
pcp_key_t * key2be(pcp_key_t *k);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
pcp_key_t *key2native(pcp_key_t *k);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
pcp_pubkey_t * pubkey2be(pcp_pubkey_t *k);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
pcp_pubkey_t *pubkey2native(pcp_pubkey_t *k);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
byte * pcp_gennonce();

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
byte *pcp_derivekey(PCPCTX *ptx, char *passphrase, byte *nonce);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
void pcp_seckeyblob(Buffer *b, pcp_key_t *k);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
void pcp_pubkeyblob(Buffer *b, pcp_pubkey_t *k);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
Buffer *pcp_keyblob(void *k, int type);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
int pcp_sanitycheck_pub(PCPCTX *ptx, pcp_pubkey_t *key);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
int pcp_sanitycheck_key(PCPCTX *ptx, pcp_key_t *key);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
void pcp_dumpkey(pcp_key_t *k);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
void pcp_dumppubkey(pcp_pubkey_t *k);

/*** bindings/py/gencffi.pl: from include/pcp/key.h:888 */
void pcpkey_setowner(pcp_key_t *key, char *owner, char *mail);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
Buffer *buffer_new(size_t blocksize, char *name);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
Buffer *buffer_new_str(char *name);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
Buffer *buffer_new_buf(char *name, void *data, size_t datasize);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
void buffer_init(Buffer *b, size_t blocksize, char *name);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
void buffer_free(Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
void buffer_clear(Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
void buffer_rewind(Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
void buffer_add(Buffer *b, const void *data, size_t len);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
void buffer_add_buf(Buffer *dst, Buffer *src);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
void buffer_add_str(Buffer *b, const char * fmt, ...);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
void buffer_add_hex(Buffer *b, void *data, size_t len);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
void buffer_resize(Buffer *b, size_t len);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
int buffer_done(Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
size_t buffer_get_chunk(Buffer *b, void *buf, size_t len);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
size_t buffer_get_chunk_tobuf(Buffer *b, Buffer *dst, size_t len);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
byte *buffer_get(Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
char *buffer_get_str(Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
byte *buffer_get_remainder(Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
size_t buffer_extract(Buffer *b, void *buf, size_t offset, size_t len);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
size_t buffer_fwd_offset(Buffer *b, size_t fwdby);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
void buffer_dump(const Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
void buffer_info(const Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
size_t buffer_size(const Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
size_t buffer_left(const Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
uint8_t buffer_get8(Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
uint16_t buffer_get16(Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
uint32_t buffer_get32(Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
uint64_t buffer_get64(Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
uint16_t buffer_get16na(Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
uint32_t buffer_get32na(Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
uint64_t buffer_get64na(Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
uint8_t  buffer_last8(Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
uint16_t buffer_last16(Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
uint32_t buffer_last32(Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
uint64_t buffer_last64(Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
size_t buffer_fd_read(Buffer *b, FILE *in, size_t len);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
void buffer_add8(Buffer *b, uint8_t v);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
void buffer_add16(Buffer *b, uint16_t v);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
void buffer_add32(Buffer *b, uint32_t v);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
void buffer_add64(Buffer *b, uint64_t v);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
void buffer_add16be(Buffer *b, uint16_t v);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
void buffer_add32be(Buffer *b, uint32_t v);

/*** bindings/py/gencffi.pl: from include/pcp/buffer.h:1543 */
void buffer_add64be(Buffer *b, uint64_t v);

/*** bindings/py/gencffi.pl: from include/pcp/context.h:1639 */
PCPCTX *ptx_new();

/*** bindings/py/gencffi.pl: from include/pcp/context.h:1639 */
void ptx_clean(PCPCTX *ptx);

/*** bindings/py/gencffi.pl: from include/pcp/context.h:1639 */
void fatal(PCPCTX *ptx, const char * fmt, ...);

/*** bindings/py/gencffi.pl: from include/pcp/context.h:1639 */
void fatals_ifany(PCPCTX *ptx);

/*** bindings/py/gencffi.pl: from include/pcp/context.h:1639 */
void fatals_reset(PCPCTX *ptx);

/*** bindings/py/gencffi.pl: from include/pcp/context.h:1639 */
void final(const char * fmt, ...);

/*** bindings/py/gencffi.pl: from include/pcp/context.h:1639 */
void ptx_dump(PCPCTX *ptx);

/*** bindings/py/gencffi.pl: from include/pcp/ed.h:1935 */
byte *pcp_ed_sign(byte *message, size_t messagesize, pcp_key_t *s);

/*** bindings/py/gencffi.pl: from include/pcp/ed.h:1935 */
byte *pcp_ed_verify(PCPCTX *ptx, byte *signature, size_t siglen, pcp_pubkey_t *p);

/*** bindings/py/gencffi.pl: from include/pcp/ed.h:1935 */
byte *pcp_ed_verify_key(PCPCTX *ptx, byte *signature, size_t siglen, pcp_pubkey_t *p);

/*** bindings/py/gencffi.pl: from include/pcp/ed.h:1935 */
size_t pcp_ed_sign_buffered(PCPCTX *ptx, Pcpstream *in, Pcpstream *out, pcp_key_t *s, int z85);

/*** bindings/py/gencffi.pl: from include/pcp/ed.h:1935 */
pcp_pubkey_t *pcp_ed_verify_buffered(PCPCTX *ptx, Pcpstream *in, pcp_pubkey_t *p);

/*** bindings/py/gencffi.pl: from include/pcp/ed.h:1935 */
size_t pcp_ed_detachsign_buffered(Pcpstream *in, Pcpstream *out, pcp_key_t *s);

/*** bindings/py/gencffi.pl: from include/pcp/ed.h:1935 */
pcp_pubkey_t *pcp_ed_detachverify_buffered(PCPCTX *ptx, Pcpstream *in, Pcpstream *sigfd, pcp_pubkey_t *p);

/*** bindings/py/gencffi.pl: from include/pcp/crypto.h:2223 */
size_t pcp_encrypt_stream(PCPCTX *ptx, Pcpstream *in, Pcpstream* out, pcp_key_t *s, pcp_pubkey_t *p, int signcrypt, int anon);

/*** bindings/py/gencffi.pl: from include/pcp/crypto.h:2223 */
size_t pcp_encrypt_stream_sym(PCPCTX *ptx, Pcpstream *in, Pcpstream* out, byte *symkey, int havehead, pcp_rec_t *recsign);

/*** bindings/py/gencffi.pl: from include/pcp/crypto.h:2223 */
size_t pcp_decrypt_stream(PCPCTX *ptx, Pcpstream *in, Pcpstream* out, pcp_key_t *s, byte *symkey, int verify, int anon);

/*** bindings/py/gencffi.pl: from include/pcp/crypto.h:2223 */
size_t pcp_decrypt_stream_sym(PCPCTX *ptx, Pcpstream *in, Pcpstream* out, byte *symkey, pcp_rec_t *recverify);

/*** bindings/py/gencffi.pl: from include/pcp/crypto.h:2223 */
pcp_rec_t *pcp_rec_new(byte *cipher, size_t clen, pcp_key_t *secret, pcp_pubkey_t *pub);

/*** bindings/py/gencffi.pl: from include/pcp/crypto.h:2223 */
void pcp_rec_free(pcp_rec_t *r);

/*** bindings/py/gencffi.pl: from include/pcp/vault.h:2453 */
vault_t *pcpvault_init(PCPCTX *ptx, char *filename);

/*** bindings/py/gencffi.pl: from include/pcp/vault.h:2453 */
vault_t *pcpvault_new(PCPCTX *ptx, char *filename, int is_tmp);

/*** bindings/py/gencffi.pl: from include/pcp/vault.h:2453 */
int pcpvault_create(PCPCTX *ptx, vault_t *vault);

/*** bindings/py/gencffi.pl: from include/pcp/vault.h:2453 */
int pcpvault_additem(PCPCTX *ptx, vault_t *vault, void *item, size_t itemsize, uint8_t type);

/*** bindings/py/gencffi.pl: from include/pcp/vault.h:2453 */
int pcpvault_addkey(PCPCTX *ptx, vault_t *vault, void *item, uint8_t type);

/*** bindings/py/gencffi.pl: from include/pcp/vault.h:2453 */
int pcpvault_close(PCPCTX *ptx, vault_t *vault);

/*** bindings/py/gencffi.pl: from include/pcp/vault.h:2453 */
void pcpvault_free(vault_t *vault);

/*** bindings/py/gencffi.pl: from include/pcp/vault.h:2453 */
int pcpvault_fetchall(PCPCTX *ptx, vault_t *vault);

/*** bindings/py/gencffi.pl: from include/pcp/vault.h:2453 */
int pcpvault_writeall(PCPCTX *ptx, vault_t *vault);

/*** bindings/py/gencffi.pl: from include/pcp/vault.h:2453 */
int pcpvault_copy(PCPCTX *ptx, vault_t *tmp, vault_t *vault);

/*** bindings/py/gencffi.pl: from include/pcp/vault.h:2453 */
void pcpvault_unlink(vault_t *tmp);

/*** bindings/py/gencffi.pl: from include/pcp/vault.h:2453 */
byte *pcpvault_create_checksum(PCPCTX *ptx);

/*** bindings/py/gencffi.pl: from include/pcp/vault.h:2453 */
void pcpvault_update_checksum(PCPCTX *ptx, vault_t *vault);

/*** bindings/py/gencffi.pl: from include/pcp/vault.h:2453 */
vault_header_t * vh2be(vault_header_t *h);

/*** bindings/py/gencffi.pl: from include/pcp/vault.h:2453 */
vault_header_t * vh2native(vault_header_t *h);

/*** bindings/py/gencffi.pl: from include/pcp/vault.h:2453 */
vault_item_header_t * ih2be(vault_item_header_t *h);

/*** bindings/py/gencffi.pl: from include/pcp/vault.h:2453 */
vault_item_header_t * ih2native(vault_item_header_t *h);

/*** bindings/py/gencffi.pl: from include/pcp/mgmt.h:2712 */
Buffer *pcp_export_rfc_pub (pcp_key_t *sk);

/*** bindings/py/gencffi.pl: from include/pcp/mgmt.h:2712 */
Buffer *pcp_export_pbp_pub(pcp_key_t *sk);

/*** bindings/py/gencffi.pl: from include/pcp/mgmt.h:2712 */
Buffer *pcp_export_yaml_pub(pcp_key_t *sk);

/*** bindings/py/gencffi.pl: from include/pcp/mgmt.h:2712 */
Buffer *pcp_export_perl_pub(pcp_key_t *sk);

/*** bindings/py/gencffi.pl: from include/pcp/mgmt.h:2712 */
Buffer *pcp_export_c_pub(pcp_key_t *sk);

/*** bindings/py/gencffi.pl: from include/pcp/mgmt.h:2712 */
Buffer *pcp_export_secret(PCPCTX *ptx, pcp_key_t *sk, char *passphrase);

/*** bindings/py/gencffi.pl: from include/pcp/mgmt.h:2712 */
pcp_ks_bundle_t *pcp_import_binpub(PCPCTX *ptx, byte *raw, size_t rawsize);

/*** bindings/py/gencffi.pl: from include/pcp/mgmt.h:2712 */
pcp_ks_bundle_t *pcp_import_pub(PCPCTX *ptx, byte *raw, size_t rawsize);

/*** bindings/py/gencffi.pl: from include/pcp/mgmt.h:2712 */
pcp_ks_bundle_t *pcp_import_pub_rfc(PCPCTX *ptx, Buffer *blob);

/*** bindings/py/gencffi.pl: from include/pcp/mgmt.h:2712 */
pcp_ks_bundle_t *pcp_import_pub_pbp(PCPCTX *ptx, Buffer *blob);

/*** bindings/py/gencffi.pl: from include/pcp/mgmt.h:2712 */
pcp_key_t *pcp_import_binsecret(PCPCTX *ptx, byte *raw, size_t rawsize, char *passphrase);

/*** bindings/py/gencffi.pl: from include/pcp/mgmt.h:2712 */
pcp_key_t *pcp_import_secret(PCPCTX *ptx, byte *raw, size_t rawsize, char *passphrase);

/*** bindings/py/gencffi.pl: from include/pcp/mgmt.h:2712 */
pcp_key_t *pcp_import_secret_native(PCPCTX *ptx, Buffer *cipher, char *passphrase);

/*** bindings/py/gencffi.pl: from include/pcp/mgmt.h:2712 */
int _check_keysig_h(PCPCTX *ptx, Buffer *blob, rfc_pub_sig_h *h);

/*** bindings/py/gencffi.pl: from include/pcp/mgmt.h:2712 */
int _check_hash_keysig(PCPCTX *ptx, Buffer *blob, pcp_pubkey_t *p, pcp_keysig_t *sk);

/*** bindings/py/gencffi.pl: from include/pcp/mgmt.h:2712 */
int _check_sigsubs(PCPCTX *ptx, Buffer *blob, pcp_pubkey_t *p, rfc_pub_sig_s *subheader);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
Pcpstream *ps_init(void);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
Pcpstream *ps_new_file(FILE *backendfd);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
Pcpstream *ps_new_inbuffer(Buffer *b);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
Pcpstream *ps_new_outbuffer();

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
size_t ps_read(Pcpstream *stream, void *buf, size_t readbytes);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
size_t ps_write(Pcpstream *stream, void *buf, size_t writebytes);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
size_t ps_finish(Pcpstream *stream);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
size_t ps_print(Pcpstream *stream, const char * fmt, ...);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
size_t ps_tell(Pcpstream *stream);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
Buffer *ps_buffer(Pcpstream *stream);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
void ps_close(Pcpstream *stream);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
int ps_end(Pcpstream *stream);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
int ps_err(Pcpstream *stream);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
void ps_setdetermine(Pcpstream *stream, size_t blocksize);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
void ps_armor(Pcpstream *stream, size_t blocksize);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
void ps_unarmor(Pcpstream *stream);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
size_t ps_read_decode(Pcpstream *stream);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
void ps_determine(Pcpstream *stream);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
size_t ps_read_next(Pcpstream *stream);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
size_t ps_read_cached(Pcpstream *stream, void *buf, size_t readbytes);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
size_t ps_read_raw(Pcpstream *stream, void *buf, size_t readbytes);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
void ps_write_encode(Pcpstream *stream, Buffer *dst);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
size_t ps_write_buf(Pcpstream *stream, Buffer *z);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
int ps_left(Pcpstream *stream);

/*** bindings/py/gencffi.pl: from include/pcp/pcpstream.h:3003 */
int ps_readline(Pcpstream *stream, Buffer *line);

/*** bindings/py/gencffi.pl: from include/pcp/z85.h:3181 */
byte *pcp_padfour(byte *src, size_t srclen, size_t *dstlen);

/*** bindings/py/gencffi.pl: from include/pcp/z85.h:3181 */
size_t pcp_unpadfour(byte *src, size_t srclen);

/*** bindings/py/gencffi.pl: from include/pcp/z85.h:3181 */
byte *pcp_z85_decode(PCPCTX *ptx, char *z85block, size_t *dstlen);

/*** bindings/py/gencffi.pl: from include/pcp/z85.h:3181 */
char *pcp_z85_encode(byte *raw, size_t srclen, size_t *dstlen, int doblock);

/*** bindings/py/gencffi.pl: from include/pcp/z85.h:3181 */
char *pcp_readz85file(PCPCTX *ptx, FILE *infile);

/*** bindings/py/gencffi.pl: from include/pcp/z85.h:3181 */
char *pcp_readz85string(PCPCTX *ptx, byte *input, size_t bufsize);

/*** bindings/py/gencffi.pl: from include/pcp/z85.h:3181 */
uint8_t is_utf8(const byte * bytes);

/*** bindings/py/gencffi.pl: from include/pcp/z85.h:3181 */
size_t _buffer_is_binary(byte *buf, size_t len);

/*** bindings/py/gencffi.pl: from include/pcp/z85.h:3181 */
uint8_t _parse_zchar(Buffer *z, uint8_t c, uint8_t is_comment);

/*** bindings/py/gencffi.pl: from include/pcp/z85.h:3181 */
long int z85_header_startswith(Buffer *buf, char *what);

/*** bindings/py/gencffi.pl: from include/pcp/z85.h:3181 */
int z85_isheader(Buffer *buf);

/*** bindings/py/gencffi.pl: from include/pcp/z85.h:3181 */
int z85_isend(Buffer *buf);

/*** bindings/py/gencffi.pl: from include/pcp/z85.h:3181 */
int z85_isbegin(Buffer *buf);

/*** bindings/py/gencffi.pl: from include/pcp/z85.h:3181 */
int z85_iscomment(Buffer *buf);

/*** bindings/py/gencffi.pl: from include/pcp/z85.h:3181 */
int z85_isempty(Buffer *line);

/*** bindings/py/gencffi.pl: from include/pcp/z85.h:3181 */
int z85_isencoded(Buffer *line);'''
