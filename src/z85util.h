#ifndef _HAVE_PCP_Z85
#define _HAVE_PCP_Z85

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "mem.h"
#include "z85.h"
#include "zmq_z85.h"
#include "defines.h"

int pcpz85_encode(char *infile, char *outfile);
int pcpz85_decode(char *infile, char *outfile);

#endif 
