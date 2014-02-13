/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013 T.Linden.

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

int main (int argc, char **argv)  {
  int opt, mode, usevault, useid, userec, lo, armor, detach, signcrypt, exportformat;
  char *vaultfile = default_vault();
  char *outfile = NULL;
  char *infile = NULL;
  char *sigfile = NULL;
  char *keyid = NULL;
  char *id = NULL;
  char *xpass = NULL;
  char *extra = NULL;
  plist_t *recipient = NULL;
  FILE *in;

  PCP_EXIT = 0;
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
  exportformat = EXP_FORMAT_NATIVE;

  static struct option longopts[] = {
    /*  generics */
    { "vault",           required_argument, NULL,           'V' },
    { "outfile",         required_argument, NULL,           'O' },
    { "infile",          required_argument, NULL,           'I' },
    { "keyid",           required_argument, NULL,           'i' },
    { "text",            required_argument, NULL,           't' },
    { "xpass",           required_argument, NULL,           'x' },
    { "recipient",       required_argument, NULL,           'r' },

    /*  key management */
    { "keygen",          no_argument,       NULL,           'k' },
    { "listkeys",        no_argument,       NULL,           'l' },
    { "export-secret",   no_argument,       NULL,           's' },
    { "export-public",   no_argument,       NULL,           'p' },
    { "import-secret",   no_argument,       NULL,           'S' },
    { "import-public",   no_argument,       NULL,           'P' },
    { "remove-key",      no_argument,       NULL,           'R' },
    { "edit-key",        no_argument,       NULL,           'E' },    
    { "export-yaml",     no_argument,       NULL,           'y' },
    { "export-format",   required_argument, NULL,           'F' },

    /*  crypto */
    {  "encrypt",        no_argument,       NULL,           'e' },
    {  "encrypt-me",     no_argument,       NULL,           'm' },
    {  "decrypt",        no_argument,       NULL,           'd' },

    /*  encoding */
    {  "z85-encode",     no_argument,       NULL,           'z' },
    {  "z85-decode",     no_argument,       NULL,           'Z' },

    /*  globals */
    { "help",            no_argument,       NULL,           'h' },
    { "version",         no_argument,       NULL,           'v' },
    { "debug",           no_argument,       NULL,           'D' },

    /*  signing */
    { "sign",            no_argument,       NULL,           'g' }, 
    { "check-signature", no_argument,       NULL,           'c' },
    { "sigfile",         required_argument, NULL,           'f' },
    { NULL,              0,                 NULL,            0 }
  };

  while ((opt = getopt_long(argc, argv, "klV:vdehsO:i:I:pSPRtEx:DzZr:gcymf:b1F:",
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
      case 'P':
	mode += PCP_MODE_IMPORT_PUBLIC;
	usevault = 1;
	break;
      case 'S':
	mode += PCP_MODE_IMPORT_SECRET;
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
	armor = 1;
	break;
      case 'Z':
	armor = 2;
	break;
      case 'F':
	if(strncmp(optarg, "pbp", 3) == 0) {
	  exportformat = EXP_FORMAT_PBP;
	}
	else if(strncmp(optarg, "pcp", 3) == 0) {
	  exportformat = EXP_FORMAT_NATIVE;
	}
	else if(strncmp(optarg, "yaml", 3) == 0) {
	  exportformat = EXP_FORMAT_YAML;
	}
	else if(strncmp(optarg, "c", 3) == 0) {
	  exportformat = EXP_FORMAT_C;
	}
	else if(strncmp(optarg, "py", 3) == 0) {
	  exportformat = EXP_FORMAT_PY;
	}
	else if(strncmp(optarg, "perl", 3) == 0) {
	  exportformat = EXP_FORMAT_PERL;
	}
	else if(strncmp(optarg, "c", 3) == 0) {
	  exportformat = EXP_FORMAT_C;
	}
	else {
	  warn("Unknown export format specified, using native\n");
	  exportformat = EXP_FORMAT_NATIVE;
	}
	break;
      case 'g':
	mode += PCP_MODE_SIGN;
	usevault = 1;
	break;
      case 'c':
	mode += PCP_MODE_VERIFY;
	usevault = 1;
	break;
      case 'f':
	sigfile = ucmalloc(strlen(optarg)+1);
	strncpy(sigfile, optarg, strlen(optarg)+1);
	detach = 1;
	break;
      case 'y':
	mode += PCP_MODE_YAML;
	usevault = 1;
	break;

      case 'V':
	strncpy(vaultfile, optarg, 1024);
	break;
      case 'O':
	outfile = ucmalloc(strlen(optarg)+1);
	strncpy(outfile, optarg, strlen(optarg)+1);
	break;
      case 'I':
	infile = ucmalloc(strlen(optarg)+1);
	strncpy(infile, optarg, strlen(optarg)+1); 
	break;
      case 'i':
	keyid = ucmalloc(19);
	strncpy(keyid, optarg, 19);
	useid = 1;
	break;
      case 'x':
	xpass = ucmalloc(strlen(optarg)+1);
	strncpy(xpass, optarg, strlen(optarg)+1);
	break;
      case 'r':
	p_add(&recipient, optarg);
	userec = 1;
	break;

      case 'D':
	debug = 1;
	break;
      case 'v':
	version();
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

    switch (mode) {
    case PCP_MODE_DECRYPT:
      if(infile == NULL)
	infile = extra;
      break;

    case PCP_MODE_ENCRYPT:
      if(infile == NULL)
	infile = extra;
      else if(userec == 0 && useid == 0) {
	userec = 1;
	int i;
	for (i=0; i<argc; i++) {
	  p_add(&recipient, argv[i]);
	}
	free(extra);
      }
      break;

    case PCP_MODE_IMPORT_PUBLIC:
    case PCP_MODE_IMPORT_SECRET:
      if(infile == NULL)
	infile = extra;
      break;

    case PCP_MODE_EXPORT_SECRET:
    case PCP_MODE_EXPORT_PUBLIC:
      if(outfile == NULL)
	outfile = extra;
      else if(useid == 0 && userec == 0) {
	p_add(&recipient, extra);
	userec = 1;
      }
      break;

    case PCP_MODE_VERIFY:
      if(infile == NULL)
	infile = extra;
      else if (useid == 0) {
	id = extra;
	useid = 1;
      }
      break;

    case PCP_MODE_SIGN:
      if(infile == NULL)
	infile = extra;
      else if(outfile == NULL && detach == 0)
	outfile = extra;
      break;

    default:
      free(extra); /* not used */
    }
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
    pcphash_init();
    vault = pcpvault_init(vaultfile);
    if(vault != NULL) {
      switch (mode) {
      case  PCP_MODE_KEYGEN:
	pcp_keygen(xpass);
	if(xpass != NULL)
	  free(xpass);
	break;

      case PCP_MODE_LISTKEYS:
	pcp_listkeys();
	break;

      case PCP_MODE_EXPORT_SECRET:
	if(useid) {
	  id = pcp_normalize_id(keyid);
	  if(id != NULL) {
	    pcp_exportsecret(id, useid, outfile, armor, xpass);
	    free(id);
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
	if(xpass != NULL)
	  free(xpass);
	if(recipient != NULL)
	  free(recipient);
	break;

      case PCP_MODE_IMPORT_PUBLIC:
	if(infile == NULL)
	  in = stdin;
	else {
	  if((in = fopen(infile, "rb")) == NULL) {
	    fatal("Could not open input file %s\n", infile);
	    free(infile);
	    break;
	  }
	}
	pcp_importpublic(vault, in);
	break;

      case PCP_MODE_IMPORT_SECRET:
	if(infile == NULL)
	  in = stdin;
	else {
	  if((in = fopen(infile, "rb")) == NULL) {
	    fatal("Could not open input file %s\n", infile);
	    free(infile);
	    break;
	  }
	}
	pcp_importsecret(vault, in, xpass);
	break;

      case PCP_MODE_DELETE_KEY:
	if(useid) {
	  id = pcp_normalize_id(keyid);
	  if(id != NULL) {
	    pcpdelete_key(id);
	    free(id);
	  }
	}
	else {
	  fatal("You need to specify a key id (--keyid)!\n");
	}
	break;

      case PCP_MODE_EDIT:
	if(useid) {
	  id = pcp_normalize_id(keyid);
	  if(id != NULL) {
	    pcpedit_key(id);
	    free(id);
	  }
	}
	else {
	  fatal("You need to specify a key id (--keyid)!\n");
	}
	break;

      case PCP_MODE_ENCRYPT:
	if(useid == 1 && userec == 0) {
	  /*  one dst, FIXME: make id a list as well */
	  id = pcp_normalize_id(keyid);
	  pcpencrypt(id, infile, outfile, xpass, NULL, signcrypt);
	}
	else if(useid == 0 && userec == 1) {
	  /*  multiple dst */
	  pcpencrypt(NULL, infile, outfile, xpass, recipient, signcrypt);
	}
	else {
	  /*  -i and -r specified */
	  fatal("You can't specify both -i and -r, use either -i or -r!\n");
	}
	if(id != NULL)
	  free(id);
	if(xpass != NULL)
	    free(xpass);
	if(recipient != NULL)
	  p_clean(recipient);

	break;

      case PCP_MODE_DECRYPT:
	if(useid) {
	  id = pcp_normalize_id(keyid);
	  if(id != NULL) {
	    pcpdecrypt(id, useid, infile, outfile, xpass, signcrypt);
	    free(id);
	  }
	}
	else {
	  pcpdecrypt(NULL, useid, infile, outfile, xpass, signcrypt);
	}
	if(xpass != NULL)
	  free(xpass);
	break;	

      case PCP_MODE_SIGN:
	if(detach) {
	  if(outfile != NULL && sigfile != NULL)
	    fatal("You can't both specify -O and -f, use -O for std signatures and -f for detached ones\n");
	  else
	    pcpsign(infile, sigfile, xpass, armor, detach);
	}
	else
	  pcpsign(infile, outfile, xpass, armor, detach);
	break;

      case PCP_MODE_VERIFY:
	if(useid) {
	  id = pcp_normalize_id(keyid);
	  if(id != NULL) {
	    pcpverify(infile, sigfile, id, detach);
	    free(id);
	  }
	}
	else {
	  pcpverify(infile, sigfile, NULL, detach);
	}
	break;

      case PCP_MODE_YAML:
	pcpexport_yaml(outfile);
	break;

      default:
 	/*   */
	goto ELSEMODE;
	break;
      }
      pcpvault_close(vault);
      pcphash_clean();
      free(vaultfile);
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
      pcpencrypt(NULL, infile, outfile, xpass, NULL, 0);
      break;

    case PCP_MODE_TEXT:
      if(infile != NULL) {
	pcptext_infile(infile);
      }
      else {
	pcphash_init();
	vault = pcpvault_init(vaultfile);
	if(! useid && infile == NULL) {
	  pcptext_vault(vault);
	}
	else {
	  id = pcp_normalize_id(keyid);
	  if(id != NULL) {
	    pcptext_key(id);
	    free(id);
	  }
	}
	pcpvault_close(vault);
	pcphash_clean();
	free(vaultfile);
      }
      break;

    default:
      /*  mode params mixed */
      fatal("Sorry, invalid combination of commandline parameters (0x%04X)!\n", mode);
      break;  
    }
  }
  
  fatals_ifany();
  fatals_done();
  return PCP_EXIT;

}
