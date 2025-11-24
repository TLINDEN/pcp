#ifndef _HAVE_PCP_GETPASS
#define _HAVE_PCP_GETPASS

/*
 * (unportable) functions to turn on/off terminal echo
 * using termios functions. might compile however on
 * most unices, tested on FreeBSD only.
 */


#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>


void pcp_echo_off();
void pcp_echo_on();
char *pcp_get_stdin();
char *pcp_get_passphrase(char *prompt);

#endif /*  _HAVE_PCP_GETPASS */
