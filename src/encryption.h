#ifndef _HAVE_ENCRYPTION_H
#define _HAVE_ENCRYPTION_H

#include <stdio.h>
#include <string.h>

#include "defines.h"
#include "key.h"
#include "crypto.h"
#include "pcp.h"
#include "uthash.h"
#include "z85.h"
#include "keyprint.h"

int pcpdecrypt(char *id, int useid, char *infile, char *outfile, char *passwd);
int pcpencrypt(char *id, char *infile, char *outfile, char *passwd, char *recipient);

#endif // _HAVE_ENCRYPTION_H
