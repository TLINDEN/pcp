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

void usage() {
  fprintf(stderr, PCP_HELP_INTRO);
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
  int opt, mode, usevault, useid, userec, lo;
  char *vaultfile = default_vault();
  char *outfile = NULL;
  char *infile = NULL;
  char *sigfile = NULL;
  char *keyid = NULL;
  char *id = NULL;
  char *xpass = NULL;
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

  static struct option longopts[] = {
    // generics
    { "vault",           required_argument, NULL,           'V' },
    { "outfile",         required_argument, NULL,           'O' },
    { "infile",          required_argument, NULL,           'I' },
    { "keyid",           required_argument, NULL,           'i' },
    { "text",            required_argument, NULL,           't' },
    { "xpass",           required_argument, NULL,           'x' },
    { "recipient",       required_argument, NULL,           'r' },

    // key management
    { "keygen",          no_argument,       NULL,           'k' },
    { "listkeys",        no_argument,       NULL,           'l' },
    { "export-secret",   no_argument,       NULL,           's' },
    { "export-public",   no_argument,       NULL,           'p' },
    { "import-secret",   no_argument,       NULL,           'S' },
    { "import-public",   no_argument,       NULL,           'P' },
    { "remove-key",      no_argument,       NULL,           'R' },
    { "edit-key",        no_argument,       NULL,           'E' },    
    { "export-yaml",     no_argument,       NULL,           'y' },

    // crypto
    {  "encrypt",        no_argument,       NULL,           'e' },
    {  "decrypt",        no_argument,       NULL,           'd' },

    // encoding
    {  "z85-encode",     no_argument,       NULL,           'z' },
    {  "z85-decode",     no_argument,       NULL,           'Z' },

    // globals
    { "help",            no_argument,       NULL,           'h' },
    { "version",         no_argument,       NULL,           'f' },
    { "debug",           no_argument,       NULL,           'D' },

    // signing
    { "sign",            no_argument,       NULL,           'g' }, 
    { "check-signature", required_argument, NULL,           'c' }, 
    { NULL,              0,                 NULL,            0 }
  };

  while ((opt = getopt_long(argc, argv, "klV:vdehsO:i:I:pSPRtEx:DzZr:gc:y",
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
      case 'd':
	mode += PCP_MODE_DECRYPT;
	usevault = 1;
	break;
      case 'z':
	mode += PCP_MODE_ZENCODE;
	break;
      case 'Z':
	mode += PCP_MODE_ZDECODE;
	break;
      case 'g':
	mode += PCP_MODE_SIGN;
	usevault = 1;
	break;
      case 'c':
	mode += PCP_MODE_VERIFY;
	sigfile = ucmalloc(strlen(optarg)+1);
	strncpy(sigfile, optarg, strlen(optarg)+1);
	usevault = 1;
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
	usage();
      default:
	usage();
    }
  }

  argc -= optind;
  argv += optind;


  if(mode == 0) {
    version();
    return 1;
  }

  sodium_init(); // FIXME: better called from the lib?

  if(usevault == 1) {
    pcphash_init();
    vault = pcpvault_init(vaultfile);
    if(vault != NULL) {
      switch (mode) {
      case  PCP_MODE_KEYGEN:
	pcp_keygen(xpass, outfile);
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
	    pcp_exportsecret(id, useid, outfile);
	    free(id);
	  }
	}
	else {
	  pcp_exportsecret(NULL, useid, outfile);
	}
	break;

      case PCP_MODE_EXPORT_PUBLIC:
	if(useid) {
	  id = pcp_normalize_id(keyid);
	  if(id == NULL)
	    break;
	}
	if (recipient != NULL)
	  pcp_exportpublic(id, recipient->value, xpass, outfile);
	else
	  pcp_exportpublic(id, NULL, xpass, outfile);
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
	pcp_importsecret(vault, in);
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
	  // one dst, FIXME: make id a list as well
	  id = pcp_normalize_id(keyid);
	  pcpencrypt(id, infile, outfile, xpass, NULL);
	}
	else if(useid == 0 && userec == 1) {
	  // multiple dst
	  pcpencrypt(id, infile, outfile, xpass, recipient);
	}
        else if(useid == 0 && userec == 0) {
	  // self mode
          pcp_key_t *k = pcp_find_primary_secret();
	  id = ucmalloc(17);
          memcpy(id, k->id, 17);
	  pcpencrypt(id, infile, outfile, xpass, NULL);
        }
	else {
	  // -i and -r specified
	  fatal("You can't specify both -i and -r, use either -i or -r!\n");
	}
	if(id != NULL)
	  free(id);
	if(xpass != NULL)
	    free(xpass);
	if(recipient != NULL)
	  free(recipient);

	break;

      case PCP_MODE_DECRYPT:
	if(useid) {
	  id = pcp_normalize_id(keyid);
	  if(id != NULL) {
	    pcpdecrypt(id, useid, infile, outfile, xpass);
	    free(id);
	  }
	}
	else {
	  pcpdecrypt(NULL, useid, infile, outfile, xpass);
	}
	if(xpass != NULL)
	  free(xpass);
	break;	

      case PCP_MODE_SIGN:
	pcpsign(infile, outfile, xpass);
	break;

      case PCP_MODE_VERIFY:
	pcpverify(infile, sigfile);
	break;

      case PCP_MODE_YAML:
	pcpexport_yaml(outfile);
	break;

      default:
 	// 
	goto ELSEMODE;
	break;
      }
    }
    pcpvault_close(vault);
    pcphash_clean();
    ucfree(vaultfile);
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
	  ucfree(vaultfile);
	}
	break;

    default:
      // mode params mixed
      fatal("Sorry, invalid combination of commandline parameters!\n");
      break;  
    }
  }
  

  fatals_ifany();
  return PCP_EXIT;

}
