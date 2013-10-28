#ifndef _HAVE_PCP_VAULT
#define _HAVE_PCP_VAULT

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <sodium.h>
#include <unistd.h>

#include "defines.h"
#include "mem.h"
#include "key.h"
#include "uthash.h"


struct _vault_t {
  char *filename;
  FILE *fd;
  uint8_t unsafed;
  uint8_t isnew;
  uint32_t size;
  time_t modified;
  mode_t mode;
  uint32_t version;
  byte checksum[32];
};

struct _vault_header_t {
  byte fileid;
  uint32_t version;
  byte checksum[32];
};

struct _vault_item_header_t {
  byte type;
  uint32_t size;
  uint32_t version;
  byte checksum[32];
};

typedef struct _vault_t vault_t;
typedef struct _vault_header_t vault_header_t;
typedef struct _vault_item_header_t vault_item_header_t;

vault_t *pcpvault_init(char *filename);
vault_t *pcpvault_new(char *filename, int is_tmp);
int pcpvault_create(vault_t *vault);
int pcpvault_additem(vault_t *vault, void *item, size_t itemsize, uint8_t type, uint8_t do_hash);
int pcpvault_close(vault_t *vault);
int pcpvault_fetchall(vault_t *vault);
int pcpvault_writeall(vault_t *vault);
void pcpvault_copy(vault_t *tmp, vault_t *vault);
void pcpvault_unlink(vault_t *tmp);
unsigned char *pcpvault_create_checksum(vault_t *vault);
void pcpvault_update_checksum(vault_t *vault);

vault_header_t * vh2be(vault_header_t *h);
vault_header_t * vh2native(vault_header_t *h);
vault_item_header_t * ih2be(vault_item_header_t *h);
vault_item_header_t * ih2native(vault_item_header_t *h);

#endif // _HAVE_PCP_VAULT
