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

  pcp_key_t *k = pcpkey_new ();

  memcpy(k->owner, o, 8);
  memcpy(k->mail, m, 8);

  pcp_key_t *key = pcpkey_encrypt(k, pw);

  int i;
  for(i=0; i<5; i++)
    mkinv(key, i);

  pcp_pubkey_t *pub = pcpkey_pub_from_secret(key);
  for(i=0; i<4; i++)
    mkinvp(pub, i);

  mkinvv("testvault-invalidheader",  0);
  mkinvv("testvault-invalidversion",  1);
  mkinvv("testvault-invaliditemsize", 2);
  mkinvv("testvault-invaliditemtype",  3);
  mkinvv("testvault-invalidkeytype", 4);

  return 0;
}

void pr(char *t, unsigned char *b, size_t s) {
  int i;
  printf("%s:\n", t);
  for(i=0; i<s; ++i)
    printf("%02x", (unsigned int) b[i]);
  printf("\n");
}

void mkinvv(const char *name, int type) {
  unlink(name);
  vault_t *v = pcpvault_new((char *)name, 0);
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

void mkinvp(pcp_pubkey_t *k, int type) {
  pcp_pubkey_t *key = ucmalloc(sizeof(pcp_pubkey_t));
  memcpy(key, k, sizeof(pcp_pubkey_t));

  switch(type) {
  case 0:
    key->type = 0;
    pcppubkey_print(key, F("testpubkey-wrong-type"), 0);
    break;
  case 1:
    key->version = 0;
    pcppubkey_print(key, F("testpubkey-wrong-version"), 0);
    break;
  case 2:
    key->serial = 0;
    pcppubkey_print(key, F("testpubkey-wrong-serial"), 0);
    break;
  case 3:
    key->id[16] = 0x3e;
    pcppubkey_print(key, F("testpubkey-invalid-id"), 0);
    break;
  case 4:
    key->ctime = 0;
    pcppubkey_print(key, F("testpubkey-invalid-ctime"), 0);
    break;
  }
}

void mkinv(pcp_key_t *k, int type) {
  pcp_key_t *key = ucmalloc(sizeof(pcp_key_t));
  memcpy(key, k, sizeof(pcp_key_t));

  switch(type) {
  case 0:
    key->encrypted[0] = 0;
    pcpkey_print(key, F("testkey-not-encrypted"));
    break;
  case 1:
    key->type = 0;
    pcpkey_print(key, F("testkey-wrong-type"));
    break;
  case 2:
    key->version = 0;
    pcpkey_print(key, F("testkey-wrong-version"));
    break;
  case 3:
    key->serial = 0;
    pcpkey_print(key, F("testkey-wrong-serial"));
    break;
  case 4:
    key->id[16] = 0x1;
    pcpkey_print(key, F("testkey-invalid-id"));
    break;
  case 5:
    key->ctime = 0;
    pcpkey_print(key, F("testkey-invalid-ctime"));
    break;
  }
}

FILE *F(char *filename) {
  FILE *f;
  if((f = fopen(filename, "wb+")) == NULL) {
    fprintf(stderr, "Could not open output file %s\n", filename);
    exit(1);
  }
  return f;
}
