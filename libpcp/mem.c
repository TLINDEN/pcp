#include "mem.h"
#include <stdio.h>


void *ucmalloc(size_t s) {
  size_t size = s * sizeof(unsigned char);
  void *value = malloc (size);

  if (value == NULL) {
    err(errno, "Cannot allocate memory");
    exit(-1);
  }

  memset (value, 0, size);

  //printf("allocated %d bytes at %p\n", (int)size, value);

  return value;
}

void *urmalloc(size_t s) {
  void *value = ucmalloc (s);

  arc4random_buf(value, s);

  return value;
}


void *ucfree(void *ptr) {
  free(ptr);
  ptr = NULL;
}
