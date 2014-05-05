#include "invalidkeys.h"

int main() {
  char *pw =ucmalloc(8);
  char *pw2 =ucmalloc(8);
  char *o = ucmalloc(8);
  char *m = ucmalloc(8);
  strcpy(pw, "xxxx");
  strcpy(pw2, "xxxx");
  strcpy(o, "xxxx");
  strcpy(m, "xxxx");

  sodium_init();
  PCPCTX *ptx = ptx_new();
  pcp_key_t *k = pcpkey_new ();

  memcpy(k->owner, o, 8);
  memcpy(k->mail, m, 8);

  pcp_key_t *key = pcpkey_encrypt(ptx, k, pw);

  int i;
  for(i=0; i<3; i++)
    mkinvalid_secret(ptx, key, i);

  for(i=0; i<4; i++)
    mkinvalid_public(key, i);

  mkinvv(ptx, "testvault-invalidheader",  0);
  mkinvv(ptx, "testvault-invalidversion",  1);
  mkinvv(ptx, "testvault-invaliditemsize", 2);
  mkinvv(ptx, "testvault-invaliditemtype",  3);
  mkinvv(ptx, "testvault-invalidkeytype", 4);

  return 0;
}

void pr(char *t, unsigned char *b, size_t s) {
  size_t i;
  printf("%s:\n", t);
  for(i=0; i<s; ++i)
    printf("%02x", (unsigned int) b[i]);
  printf("\n");
}

void mkinvv(PCPCTX *ptx, const char *name, int type) {
  unlink(name);
  vault_t *v = pcpvault_new(ptx, (char *)name, 0);
  vault_item_header_t *item = ucmalloc(sizeof(vault_item_header_t));
  vault_header_t *header = ucmalloc(sizeof(vault_header_t));

  header->fileid = PCP_VAULT_ID;
  header->version = PCP_VAULT_VERSION;
  memset(header->checksum, 0, 32);

  item->version = PCP_KEY_VERSION;
  item->type = PCP_KEY_TYPE_SECRET;
  item->size = sizeof(pcp_key_t);

  unsigned char *blah = ucmalloc(30);
  unsigned char *blub = ucmalloc(sizeof(pcp_pubkey_t));

  fseek(v->fd, 0, SEEK_SET);

  switch (type) {
  case 0:
    header->fileid = 0;
    vh2be(header);
    fwrite(header, sizeof(vault_header_t), 1, v->fd);
    break;

  case 1:
    header->version = 0;
    vh2be(header);
    fwrite(header, sizeof(vault_header_t), 1, v->fd);
    break;

  case 2:
    vh2be(header);
    fwrite(header, sizeof(vault_header_t), 1, v->fd);
    item->size = 8;
    ih2be(item);
    fwrite(item, sizeof(vault_item_header_t), 1, v->fd);
    break;

  case 3:
    vh2be(header);
    fwrite(header, sizeof(vault_header_t), 1, v->fd);
    item->type = 0x08;
    ih2be(item);
    fwrite(item, sizeof(vault_item_header_t), 1, v->fd);
    fwrite(blub, sizeof(pcp_pubkey_t), 1, v->fd);
    break;

  case 4:
    vh2be(header);
    fwrite(header, sizeof(vault_header_t), 1, v->fd);
    fwrite(blah, 30, 1, v->fd);
    break;
  }

  fclose(v->fd);
}

void mkinvalid_public(pcp_key_t *k, int type) {
  pcp_key_t *key = ucmalloc(sizeof(pcp_key_t));
  memcpy(key, k, sizeof(pcp_key_t));
  FILE *fd = NULL;

  switch(type) {
  case 0:
    key->type = 0;
    fd = F("testpubkey-wrong-type");
    break;
  case 1:
    key->version = 0;
    fd = F("testpubkey-wrong-version");
    break;
  case 2:
    key->serial = 0;
    fd = F("testpubkey-wrong-serial");
    break;
  case 3:
    key->ctime = 0;
    fd = F("testpubkey-invalid-ctime");
    break;
  }

  if(fd != NULL) {
    Buffer *b = pcp_export_rfc_pub(key);
    fwrite(buffer_get(b), 1, buffer_size(b), fd);
    fclose(fd);
  }

  free(key);
}

void mkinvalid_secret(PCPCTX *ptx, pcp_key_t *k, int type) {
  pcp_key_t *key = ucmalloc(sizeof(pcp_key_t));
  memcpy(key, k, sizeof(pcp_key_t));
  FILE *fd = NULL;

    fprintf(stderr, "fd test %d\n", type);

  switch(type) {
  case 0:
    key->version = 0;
    fd = F("testkey-wrong-version");
    break;
  case 1:
    key->serial = 0;
    fd = F("testkey-wrong-serial");
    break;
  case 2:
    key->ctime = 0;
    fd = F("testkey-invalid-ctime");
    break;
  }

  if(fd != NULL) {
    pcp_dumpkey(key);
    Buffer *b = pcp_export_secret(ptx, key, "xxx");
    fwrite(buffer_get(b), 1, buffer_size(b), fd);
    fclose(fd);
  }
  else {
    fprintf(stderr, "fd not opened for test %d\n", type);
  }

  free(key);
}

FILE *F(char *filename) {
  FILE *f;
  if((f = fopen(filename, "wb+")) == NULL) {
    fprintf(stderr, "Could not open output file %s\n", filename);
    exit(1);
  }
  return f;
}
