/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013-2015 T.Linden.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    You can contact me by mail: <tlinden AT cpan DOT org>.
*/


#include "pcp.h"
#include "defines.h"

void usage(int error) {
  fprintf(stderr, PCP_HELP_INTRO);
  if(error == 0)
    fprintf(stderr, PCP_HELP);
  version();
  exit(EXIT_FAILURE);
}


void version() {
  fprintf(stderr, "pcp version %d.%d.%d, use --help to learn how to use.\n",
	  PCP_VERSION_MAJOR, PCP_VERSION_MINOR, PCP_VERSION_PATCH);
  exit(0);
}


char *default_vault() {
  char *path = ucmalloc(1024);;
  snprintf(path, 1024, "%s/.pcpvault", getenv("HOME"));
  return path; 
}

char *altin(char *infile, int stdinused) {
  if(infile == NULL && stdinused == 1) {
    fprintf(stderr, "Error: cannot use <stdin> because -X had precedence!\n");
    exit(1);
  }
  return infile;
}

int main (int argc, char **argv)  {
  int opt, mode, usevault, useid, userec, lo, armor, detach, \
    signcrypt, exportformat, anon, xpf;
  char *vaultfile = default_vault();
  char *outfile = NULL;
  char *infile = NULL;
  char *sigfile = NULL;
  char *keyid = NULL;
  char *id = NULL;
  char *xpass = NULL;
  char *xpassfile = NULL;
  char *extra = NULL;
  plist_t *recipient = NULL;
  FILE *in;

  errno = 0;
  debug = 0;
  mode = 0;
  usevault = 0;
  useid = 0;
  userec = 0;
  lo = 0;
  armor = 0;
  detach = 0;
  signcrypt = 0;
  anon = 0;
  xpf = 0;
  exportformat = EXP_FORMAT_NATIVE;

  ptx = ptx_new();

  static struct option longopts[] = {
    /*  generics */
    { "vault",           required_argument, NULL,           'V' },
    { "outfile",         required_argument, NULL,           'O' },
    { "infile",          required_argument, NULL,           'I' },
    { "keyid",           required_argument, NULL,           'i' },
    { "text",            required_argument, NULL,           't' },
    { "xpass",           required_argument, NULL,           'x' },
    { "password-file",   required_argument, NULL,           'X' },
    { "recipient",       required_argument, NULL,           'r' },

    /*  key management */
    { "keygen",          no_argument,       NULL,           'k' },
    { "listkeys",        no_argument,       NULL,           'l' },
    { "listkeys-verbose",no_argument,       NULL,           'L' }, /* alias for -l -v */
    { "export-secret",   no_argument,       NULL,           's' },
    { "export-public",   no_argument,       NULL,           'p' },
    { "export",          no_argument,       NULL,           'p' }, /* alias -p */
    { "import",          no_argument,       NULL,           'K' }, /* alias -P */
    { "import-key",      no_argument,       NULL,           'K' }, /* alias -K */
    { "remove-key",      no_argument,       NULL,           'R' },
    { "edit-key",        no_argument,       NULL,           'E' },    
    { "export-format",   required_argument, NULL,           'F' },

    /*  crypto */
    { "encrypt",         no_argument,       NULL,           'e' },
    { "encrypt-sym",     no_argument,       NULL,           'm' },
    { "decrypt",         no_argument,       NULL,           'd' },
    { "anonymous",       no_argument,       NULL,           'A' },
    { "add-myself",      no_argument,       NULL,           'M' },
    { "checksum",        no_argument,       NULL,           'C' },

    /*  encoding */
    { "z85-encode",      no_argument,       NULL,           'z' },
    { "armor",           no_argument,       NULL,           'a' }, /* alias -z */
    { "textmode",        no_argument,       NULL,           'a' }, /* alias -z */
    { "z85-decode",      no_argument,       NULL,           'Z' },
    { "json-io",         no_argument,       NULL,           'j' },

    /*  globals */
    { "help",            no_argument,       NULL,           'h' },
    { "version",         no_argument,       NULL,           '0' }, /* no short opt, FIXME: how to avoid? */
    { "verbose",         no_argument,       NULL,           'v' },
    { "debug",           no_argument,       NULL,           'D' },

    /*  signing */
    { "sign",            no_argument,       NULL,           'g' }, 
    { "check-signature", no_argument,       NULL,           'c' },
    { "sigfile",         required_argument, NULL,           'f' },
    { NULL,              0,                 NULL,            0 }
  };

  while ((opt = getopt_long(argc, argv, "klLV:vdehsO:i:I:pSPRtEx:DzaZr:gcmf:b1F:0KAMX:jC",
			    longopts, NULL)) != -1) {
  
    switch (opt)  {
      case 0:
	switch(lo) {
	case 's':
	  printf("sign\n");
	  break;
	}
	break;

      case 'k':
        mode += PCP_MODE_KEYGEN;
	usevault = 1;
        break;
      case  'L':
        ptx->verbose = 1; /* no break by purpose, turn on -l */
      case 'l':
	mode += PCP_MODE_LISTKEYS;
	usevault = 1;
	break;

      case 's':
	mode += PCP_MODE_EXPORT_SECRET;
	usevault = 1;
	break;
      case 'p':
	mode += PCP_MODE_EXPORT_PUBLIC;
	usevault = 1;
	break;
      case 'K':
	mode += PCP_MODE_IMPORT;
	usevault = 1;
	break;
      case 'R':
	mode += PCP_MODE_DELETE_KEY;
	usevault = 1;
	break;
      case 't':
	mode += PCP_MODE_TEXT;
	usevault = 0;
	break;
      case 'E':
	mode += PCP_MODE_EDIT;
	usevault = 1;
	break;
      case 'e':
	mode += PCP_MODE_ENCRYPT;
	usevault = 1;
	break;
      case 'm':
	mode += PCP_MODE_ENCRYPT_ME;
	break;
      case 'd':
	mode += PCP_MODE_DECRYPT;
	usevault = 1;
	break;
      case 'z':
      case 'a':
	armor = 1;
	break;
      case 'Z':
	armor = 2;
	break;
      case 'A':
	anon = 1;
	break;
      case 'F':
	if(strncmp(optarg, "pbp", 3) == 0) {
	  exportformat = EXP_FORMAT_PBP;
	}
	else if(strncmp(optarg, "pcp", 3) == 0) {
	  exportformat = EXP_FORMAT_NATIVE;
	}
	else {
	  warn("Unknown export format specified, using native\n");
	  exportformat = EXP_FORMAT_NATIVE;
	}
	break;
      case 'j':
#ifdef HAVE_JSON
	ptx->json = 1;
#else
	fprintf(stderr, "WARN: -j set, but no JSON support compiled in. Recompile with --with-json\n");
#endif
	break;
      case 'g':
	mode += PCP_MODE_SIGN;
	usevault = 1;
	break;
      case 'c':
	mode += PCP_MODE_VERIFY;
	usevault = 1;
	break;
      case 'C':
	mode += PCP_MODE_CHECKSUM;
	break;	
      case 'f':
	sigfile = ucmalloc(strlen(optarg)+1);
	strncpy(sigfile, optarg, strlen(optarg)+1);
	detach = 1;
	break;

      case 'V':
	strncpy(vaultfile, optarg, 1024);
	break;
      case 'O':
	if(strncmp(optarg, "-", 2) > 0) {
	  outfile = ucmalloc(strlen(optarg)+1);
	  strncpy(outfile, optarg, strlen(optarg)+1);
	}
	break;
      case 'I':
	if(strncmp(optarg, "-", 2) > 0) {
	  infile = ucmalloc(strlen(optarg)+1);
	  strncpy(infile, optarg, strlen(optarg)+1);
	}
	break;
      case 'X':
	xpassfile = ucmalloc(strlen(optarg)+1);
	strncpy(xpassfile, optarg, strlen(optarg)+1);
	xpf = 1;
	break;
      case 'i':
	keyid = ucmalloc(19);
	strncpy(keyid, optarg, 19);
	useid = 1;
	break;
      case 'x':
	xpass = smalloc(strlen(optarg)+1);
	strncpy(xpass, optarg, strlen(optarg)+1);
	if(strncmp(xpass, "n/a", 3) == 0)
	  xpass[0] = '\0';
	break;
      case 'r':
	p_add(&recipient, optarg);
	userec = 1;
	break;
      case 'M':
	p_add_me(&recipient);
	userec = 1;
	break;

      case 'D':
	debug = 1;
	break;
      case '0':
	version();
      case 'v':
	ptx->verbose = 1;
	break;
      case 'h':
	usage(0);
      default:
	usage(1);
    }
  }

  argc -= optind;
  argv += optind;

  if(mode == 0) {
    /* turn -z|-Z into a mode if there's nothing else specified */
    if(armor == 1) {
      mode = PCP_MODE_ZENCODE;
    }
    else if(armor == 2) {
      mode = PCP_MODE_ZDECODE;
    }
    else {
      version();
      return 1;
    }
  }

  if(mode == PCP_MODE_ENCRYPT + PCP_MODE_SIGN) {
    mode = PCP_MODE_ENCRYPT;
    signcrypt = 1;
  }
  if(mode == PCP_MODE_DECRYPT + PCP_MODE_VERIFY) {
    mode = PCP_MODE_DECRYPT;
    signcrypt = 1;
  }


  sodium_init(); /*  FIXME: better called from the lib? */

#ifndef DEBUG
#  ifdef HAVE_SETRLIMIT
     setrlimit(RLIMIT_CORE, &(struct rlimit) {0, 0});
#  endif
#endif  

  errno = 0; /* FIXME: workaround for https://github.com/jedisct1/libsodium/issues/114 */

  if(mode == PCP_MODE_ENCRYPT && useid == 0 && userec == 0) {
    usevault = 0;
    mode = PCP_MODE_ENCRYPT_ME;
  }

  if(argc >= 1) {
    /* ok, there are arguments left on the commandline.
       treat it as filename or recipient, depending on
       current mode and other given parameters */
    extra = ucmalloc(strlen(argv[0])+1);
    strncpy(extra, argv[0], strlen(argv[0])+1);
    int useex = 0;

    switch (mode) {
    case PCP_MODE_DECRYPT:
      if(infile == NULL) {
	infile = extra;
	useex = 1;
      }
      break;

    case PCP_MODE_ENCRYPT:
      if(infile == NULL) {
	infile = extra;
	useex = 1;
      }
      else if(userec == 0 && useid == 0) {
	userec = 1;
	int i;
	for (i=0; i<argc; i++) {
	  p_add(&recipient, argv[i]);
	}
      }
      break;

    case PCP_MODE_IMPORT: 
      if(infile == NULL) {
	infile = extra;
	useex = 1;
      }
      break;

    case PCP_MODE_EXPORT_SECRET:
    case PCP_MODE_EXPORT_PUBLIC:
      if(outfile == NULL) {
	outfile = extra;
	useex = 1;
      }
      else if(useid == 0 && userec == 0) {
	p_add(&recipient, extra);
	useex = 1;
	userec = 1;
      }
      break;

    case PCP_MODE_VERIFY:
      if(infile == NULL) {
	infile = extra;
	useex = 1;
      }
      else if (useid == 0) {
	id = extra;
	useid = 1;
	useex = 1;
      }
      break;

    case PCP_MODE_SIGN:
      if(infile == NULL) {
	infile = extra;
	useex = 1;
      }
      else if(outfile == NULL && detach == 0) {
	outfile = extra;
	useex = 1;
      }
      break;
    }
    if(useex)
      free(extra);
  }

  if(xpassfile != NULL) {
    pcp_readpass(&xpass, "passphrase", NULL, 0, xpassfile);
    if(xpassfile[0] != '-')
      xpf = 0; 
    free(xpassfile);
  }

  /* check if there's some enviroment we could use */
  if(usevault == 1) {
    char *_vaultfile = getenv("PCP_VAULT");
    if(_vaultfile != NULL) {
      strncpy(vaultfile, _vaultfile, strlen(_vaultfile)+1);
    }
  }
  if(debug == 0) {
    char *_debug = getenv("PCP_DEBUG");
    if(_debug != NULL) {
      debug = 1;
    }
  }

  if(usevault == 1) {
    vault = pcpvault_init(ptx, vaultfile);
    /* special case: ignore vault error in decrypt mode. sym decrypt doesn't
       need it and asym will just fail without keys. */
    if(vault == NULL && mode == PCP_MODE_DECRYPT) {
      /* use an empty one */
      vault = pcpvault_init(ptx, "/dev/null");
      fatals_reset(ptx);
    }
    
    if(vault != NULL) {
      switch (mode) {
      case  PCP_MODE_KEYGEN:
	pcp_keygen(xpass);
	break;

      case PCP_MODE_LISTKEYS:
	pcp_listkeys();
	break;

      case PCP_MODE_EXPORT_SECRET:
	if(useid) {
	  id = pcp_normalize_id(keyid);
	  if(id != NULL) {
	    pcp_exportsecret(id, useid, outfile, armor, xpass);
	  }
	}
	else {
	  pcp_exportsecret(NULL, useid, outfile, armor, xpass);
	}
	break;

      case PCP_MODE_EXPORT_PUBLIC:
	if(useid) {
	  id = pcp_normalize_id(keyid);
	  if(id == NULL)
	    break;
	}
	pcp_exportpublic(id, xpass, outfile, exportformat, armor);
	break;

      case PCP_MODE_IMPORT:
	if(infile == NULL) {
	  altin(NULL, xpf);
	  in = stdin;
	}
	else {
	  if((in = fopen(infile, "rb")) == NULL) {
	    fatal(ptx, "Could not open input file %s\n", infile);
	    break;
	  }
	}
	pcp_import(vault, in, xpass);
	break;

      case PCP_MODE_DELETE_KEY:
	if(useid) {
	  id = pcp_normalize_id(keyid);
	  if(id != NULL) {
	    pcpdelete_key(id);
	  }
	}
	else {
	  fatal(ptx, "You need to specify a key id (--keyid)!\n");
	}
	break;

      case PCP_MODE_EDIT:
	if(useid) {
	  id = pcp_normalize_id(keyid);
	  if(id != NULL) {
	    pcpedit_key(id);
	  }
	}
	else {
	  fatal(ptx, "You need to specify a key id (--keyid)!\n");
	}
	break;

      case PCP_MODE_ENCRYPT:
	if(useid == 1 && userec == 0) {
	  /*  one dst, FIXME: make id a list as well */
	  id = pcp_normalize_id(keyid);
	  pcpencrypt(id, altin(infile, xpf), outfile, xpass, NULL, signcrypt, armor, anon);
	}
	else if(useid == 0 && userec == 1) {
	  /*  multiple dst */
	  pcpencrypt(NULL, altin(infile, xpf), outfile, xpass, recipient, signcrypt, armor, anon);
	}
	else {
	  /*  -i and -r specified */
	  fatal(ptx, "You can't specify both -i and -r, use either -i or -r!\n");
	}

	break;

      case PCP_MODE_DECRYPT:
	if(useid) {
	  id = pcp_normalize_id(keyid);
	  if(id != NULL) {
	    pcpdecrypt(id, useid, altin(infile, xpf), outfile, xpass, signcrypt);
	  }
	}
	else {
	  pcpdecrypt(NULL, useid, altin(infile, xpf), outfile, xpass, signcrypt);
	}
	break;	

      case PCP_MODE_SIGN:
	if(detach) {
	  if(outfile != NULL && sigfile != NULL)
	    fatal(ptx, "You can't both specify -O and -f, use -O for std signatures and -f for detached ones\n");
	  else
	    pcpsign(altin(infile, xpf), sigfile, xpass, armor, detach);
	}
	else
	  pcpsign(altin(infile, xpf), outfile, xpass, armor, detach);
	break;

      case PCP_MODE_VERIFY:
	if(useid) {
	  id = pcp_normalize_id(keyid);
	  if(id != NULL) {
	    pcpverify(altin(infile, xpf), sigfile, id, detach);
	  }
	}
	else {
	  pcpverify(altin(infile, xpf), sigfile, NULL, detach);
	}
	break;

      default:
 	/*   */
	goto ELSEMODE;
	break;
      }
      pcpvault_close(ptx, vault);
    }
  }
  else {
  ELSEMODE:
    switch (mode) {
    case PCP_MODE_ZENCODE:
      pcpz85_encode(infile, outfile);
      break;
    
    case PCP_MODE_ZDECODE:
      pcpz85_decode(infile, outfile);
      break;

    case PCP_MODE_ENCRYPT_ME:
      pcpencrypt(NULL, altin(infile, xpf), outfile, xpass, NULL, 0, armor, 0);
      break;

    case PCP_MODE_TEXT:
      if(infile != NULL) {
	pcptext_infile(infile);
      }
      else {
	vault = pcpvault_init(ptx, vaultfile);
	if(! useid && infile == NULL) {
	  pcptext_vault(vault);
	}
	else {
	  id = pcp_normalize_id(keyid);
	  if(id != NULL) {
	    pcptext_key(id);
	  }
	}
	pcpvault_close(ptx, vault);
      }
      break;
    case PCP_MODE_CHECKSUM:
      if(infile == NULL) {
	if(argc == 0) {
	  char *list[1];
	  list[0] = NULL;
	  pcpchecksum(list, 1, xpass);
	}
	else {
	  pcpchecksum(argv, argc, xpass);
	}
      }
      else {
	char *list[1];
	list[0] = infile;
	pcpchecksum(list, 1, xpass);
      }
      break;
      
    default:
      /*  mode params mixed */
      fatal(ptx, "Sorry, invalid combination of commandline parameters (0x%04X)!\n", mode);
      break;  
    }
  }
  
  fatals_ifany(ptx);
  int e = ptx->pcp_exit;
  ptx_clean(ptx);

  if(infile != NULL)
    free(infile);
  if(outfile != NULL)
    free(outfile);
  if(vaultfile != NULL)
    free(vaultfile);
  if(sigfile != NULL)
    free(sigfile);
  if(xpass != NULL)
    sfree(xpass);
  if(recipient != NULL)
    p_clean(recipient);
  if(id != NULL)
    free(id);
  if(keyid != NULL)
    free(keyid);
  return e;
}
