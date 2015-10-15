/*-
 * Copyright 2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Modifications (c) 2013 - 2015 by T.v.Dein, same license as this file.
 */

#include "readpass.h"

/**
 * tarsnap_getpass(passwd, prompt, confirmprompt, devtty)
 * If ${devtty} is non-zero, read a password from /dev/tty if possible; if
 * not, read from stdin.  If reading from a tty (either /dev/tty or stdin),
 * disable echo and prompt the user by printing ${prompt} to stderr.  If
 * ${confirmprompt} is non-NULL, read a second password (prompting if a
 * terminal is being used) and repeat until the user enters the same password
 * twice.  Return the password as a malloced NUL-terminated string via
 * ${passwd}.  The obscure name is to avoid namespace collisions due to the
 * getpass / readpass / readpassphrase / etc. functions in various libraries.
 */
int
pcp_readpass(PCPCTX *ptx, char ** passwd, const char * prompt,
	     const char * confirmprompt, int devtty, char *readfromfile)
{
	FILE * readfrom;
	char passbuf[MAXPASSLEN];
	char confpassbuf[MAXPASSLEN];
	struct termios term, term_old;
	int usingtty;

	/*
	 * If devtty != 0, try to open /dev/tty; if that fails, or if devtty
	 * is zero, we'll read the password from stdin instead.
	 *
	 * Added by tlinden: however, if readfromfile is defined, we'll
	 * read the password from there, but if it is '-' we'll use stdin
	 * as well.
	 */
	if ((devtty == 0) || ((readfrom = fopen("/dev/tty", "r")) == NULL)) {
	  if(readfromfile != NULL) {
	    // FIXME: check if readfromfile is executable,
	    // if yes, call askextpass(tobewritten) and
	    // read from the returned fd somehow
	    if(readfromfile[0] == '-') {
	      readfrom = stdin;
	    }
	    else {
	      if((readfrom = fopen(readfromfile, "r")) == NULL) {
		fatal(ptx, "Could not open password file '%s'\n", readfromfile);
		goto err1;
	      }
	    }
	  }
	  else {
	    readfrom = stdin;
	  }
	}

	/* If we're reading from a terminal, try to disable echo. */
	if ((usingtty = isatty(fileno(readfrom))) != 0) {
		if (tcgetattr(fileno(readfrom), &term_old)) {
			fatal(ptx, "Cannot read terminal settings\n");
			goto err1;
		}
		memcpy(&term, &term_old, sizeof(struct termios));
		term.c_lflag = (term.c_lflag & ~ECHO) | ECHONL;
		if (tcsetattr(fileno(readfrom), TCSANOW, &term)) {
			fatal(ptx, "Cannot set terminal settings\n");
			goto err1;
		}
	}

retry:
	/* If we have a terminal, prompt the user to enter the password. */
	if (usingtty)
		fprintf(stderr, "%s: ", prompt);

	/* Read the password. */
	if (fgets(passbuf, MAXPASSLEN, readfrom) == NULL) {
		fatal(ptx, "Cannot read password\n");
		goto err2;
	}



	/* Confirm the password if necessary. */
	if (confirmprompt != NULL) {
		if (usingtty)
			fprintf(stderr, "%s: ", confirmprompt);
		if (fgets(confpassbuf, MAXPASSLEN, readfrom) == NULL) {
			fatal(ptx, "Cannot read password\n");
			goto err2;
		}
		if (strcmp(passbuf, confpassbuf)) {
			fprintf(stderr,
			    "Passwords mismatch, please try again\n");
			goto retry;
		}
	}

	/* Terminate the string at the first "\r" or "\n" (if any). */
	passbuf[strcspn(passbuf, "\r\n")] = '\0';

	/* enforce no empty passwords */
	if (strnlen(passbuf, MAXPASSLEN) == 0) {
	  fprintf(stderr,
		  "Empty password not allowed, please try again\n");
	  goto retry;
	}
	
	/* If we changed terminal settings, reset them. */
	if (usingtty)
		tcsetattr(fileno(readfrom), TCSANOW, &term_old);

	/* Close /dev/tty if we opened it.
	   if readfromfile is defined and set to -, disable stdin */
	if (readfrom != stdin) {
	  fclose(readfrom);
	}

	/* Copy the password out. */
	char *p = smalloc(strlen(passbuf) + 1);
	memcpy(p, passbuf, strlen(passbuf) + 1 );
	*passwd = p;

	/* Zero any stored passwords. */
	memset(passbuf, 0, MAXPASSLEN);
	memset(confpassbuf, 0, MAXPASSLEN);

	/* Success! */
	return (0);

err2:
	/* Reset terminal settings if necessary. */
	if (usingtty)
		tcsetattr(fileno(readfrom), TCSAFLUSH, &term_old);
err1:
	/* Close /dev/tty if we opened it. */
	if (readfrom != stdin)
		fclose(readfrom);

	/* Failure! */
	return (-1);
}


/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004, Valient Gough
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * modified by tlinden@cpan.org (c++ => c, pcp api)
 */

int pcp_readpass_fromprog(PCPCTX *ptx, char **passwd, const char *askpass) {
  // have a child process run the command and get the result back to us.
  int fds[2], pid;
  int res;
  char passbuf[MAXPASSLEN];
  
  res = socketpair(PF_UNIX, SOCK_STREAM, 0, fds);
  if (res == -1) {
    fatal(ptx, "Internal error: socketpair() failed");
    goto aerr1;
  }

  pid = fork();
  if (pid == -1) {
    fatal( ptx, "Internal error: fork() failed");
    close(fds[0]);
    close(fds[1]);
    goto aerr1;
  }

  if (pid == 0) {
    const char *argv[4];
    argv[0] = "/bin/sh";
    argv[1] = "-c";
    argv[2] = askpass;
    argv[3] = 0;

    // child process.. run the command and send output to fds[0]
    close(fds[1]);  // we don't use the other half..

    // make a copy of stdout and stderr descriptors, and set an environment
    // variable telling where to find them, in case a child wants it..
    int stdOutCopy = dup(STDOUT_FILENO);
    int stdErrCopy = dup(STDERR_FILENO);
    
    // replace STDOUT with our socket, which we'll used to receive the
    // password..
    dup2(fds[0], STDOUT_FILENO);

    // ensure that STDOUT_FILENO and stdout/stderr are not closed on exec..
    fcntl(STDOUT_FILENO, F_SETFD, 0);  // don't close on exec..
    fcntl(stdOutCopy, F_SETFD, 0);
    fcntl(stdErrCopy, F_SETFD, 0);

    char tmpBuf[8];

    snprintf(tmpBuf, sizeof(tmpBuf) - 1, "%i", stdOutCopy);
    setenv("PCP_ENV_STDOUT", tmpBuf, 1);

    snprintf(tmpBuf, sizeof(tmpBuf) - 1, "%i", stdErrCopy);
    setenv("PCP_ENV_STDERR", tmpBuf, 1);

    execvp(argv[0], (char *const *)argv);  // returns only on error..

    fatal(ptx, "Internal error: failed to exec program");
    goto aerr1;
  }

  close(fds[0]);

  memset(passbuf, 0, MAXPASSLEN);
  if ( recv(fds[1], passbuf, MAXPASSLEN, 0) <= 0) {
    fatal(ptx, "Cannot read password\n");
    goto aerr1;
  }


  close(fds[1]);

  waitpid(pid, NULL, 0);

  /* Terminate the string at the first "\r" or "\n" (if any). */
  passbuf[strcspn(passbuf, "\r\n")] = '\0';

  /* Copy the password out. */
  char *p = smalloc(strlen(passbuf) + 1);
  memcpy(p, passbuf, strlen(passbuf) + 1 );
  *passwd = p;

  /* Zero any stored passwords. */
  memset(passbuf, 0, MAXPASSLEN);
  
  return 0;

 aerr1:
  return -1;
}
