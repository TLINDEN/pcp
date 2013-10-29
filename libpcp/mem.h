#ifndef _HAVE_PCP_MEM
#define _HAVE_PCP_MEM

#include <strings.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include "platform.h"

// simple malloc()  wrapper 
// behaves like calloc(), which
// I don't have here.
// 
// exits if there's no more memory
// available.
void *ucmalloc(size_t s);

// the same but it fills the pointer with random values
void *urmalloc(size_t s);

// dito.
void *ucfree(void *ptr);


#endif // _HAVE_PCP_MEM
