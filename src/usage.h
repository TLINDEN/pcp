#ifndef _HAVE_USAGE_H
#define _HAVE_USAGE_H
#define PCP_HELP "\n" \
"Usage: pcp1 [options]\n" \
"\n" \
"General Options:\n" \
"-V --vault <vaultfile>    Specify an alternate vault file.\n" \
"                          The deault vault is ~/.pcpvault.\n" \
"-O --outfile <file>       Output file. If not specified, stdout\n" \
"                          will be used.\n" \
"-I --infile <file>        Input file. If not specified, stdin\n" \
"                          will be used.\n" \
"-i --keyid <id>           Specify a key id to import/export.\n" \
"-r --recipient <string>   Specify a recpipient, used for public\n" \
"                          key export and encryption.\n" \
"-t --text                 Print textual representation of some\n" \
"                          item. Specify -V to get info about a\n" \
"			  vault, -i to get info about a key id\n" \
"			  installed in the vault or -I in which\n" \
"			  case it determines itself what kind of\n" \
"			  file it is.\n" \
"-h --help                 Print this help message.\n" \
"-v --version              Print program version.\n" \
"-D --debug                Enable debug output.\n" \
"\n" \
"Keymanagement Options:\n" \
"-k --keygen               Generate a CURVE25519 secret key. If\n" \
"                          the generated key is the first one in\n" \
"                          your vault, it will become the primary\n" \
"                          secret key. If an output file (-O) has\n" \
"			  been specified, don't store the generated\n" \
"			  key to the vault but export it to the\n" \
"			  file instead. You will be asked for\n" \
"			  an owner, mail and a passphrase. If you\n" \
"			  leave the passphrase empty, the key will\n" \
"			  be stored unencrypted.\n" \
"-l --listkeys             List all keys currently stored in your\n" \
"                          vault. Only the key id's and some info\n" \
"                          about the keys will be printed, not the\n" \
"                          actual keys.\n" \
"-R --remove-key           Remove a key from the vault. Requires\n" \
"                          option -i <keyid>.\n" \
"-s --export-secret        Export a secret key. If your vault only\n" \
"                          contains one secret key, this one will\n" \
"                          be exported. If a key id have been\n" \
"                          specified (-i), this one will be used.\n" \
"                          If there are more than one secret keys\n" \
"                          in the vault and no key id has been\n" \
"                          given, export the primary secret key.\n" \
"                          Use -O to export to a file.\n" \
"-p --export-public        Export a public key. If no key id have\n" \
"                          been specified, the public part of your\n" \
"                          primary secret key will be exported.\n" \
"                          Use -O to export to a file.\n" \
"-S --import-secret        Import a secret key. Use -I to import\n" \
"                          from a file.\n" \
"-P --import-public        Import a public key. Use -I to import\n" \
"                          from a file.\n" \
"-y --export-yaml          Export all keys stored in your vault\n" \
"                          as YAML formatted text. Use -O to put\n" \
"                          the export into a file.\n" \
"Encryption Options:\n" \
"-e --encrypt              Asym-Encrypt a message. Read from stdin or\n" \
"                          specified via -I. Output will be written\n" \
"                          to stdout or the file given with -O.\n" \
"                          If a keyid (-i) has been\n" \
"                          given, use that public key for encryption.\n" \
"                          If one or more recipient (-r) has been given,\n" \
"                          encrypt the message for all recipients\n" \
"                          asymetrically, given there are matching\n" \
"                          public keys installed in the vault for them.\n" \
"                          If none of -i or -r has been given, encrypt\n" \
"                          the message symetrically. This is the same\n" \
"                          as -m (self-encryption mode).\n" \
"-m --encrypt-me           Sym-Encrypt a message. Specify -I and/or\n" \
"                          -O for input/output file. You will be asked\n" \
"                          for a passphrase. No key material will\n" \
"                          be used. Same as -e without -r and -i.\n" \
"-d --decrypt              Decrypt a message. Read from stdin or\n" \
"                          specified via -I. Output to stdout or\n" \
"                          written to the file specified via -O.\n" \
"                          The primary secret key will be used for\n" \
"                          decryption, if there is no primary and\n" \
"                          just one secret key in the vault, this\n" \
"                          one will be used. Otherwise you'll have\n" \
"                          to specify the keyid (-i) of the key.\n" \
"                          You need to have the public key of the\n" \
"                          sender installed in your vault.\n" \
"                          If the input is self-encrypted (symetrically)\n" \
"                          a passphrase will be requested.\n" \
"\n" \
"Signature Options:\n" \
"-g --sign                 Create a signature of file specified with\n" \
"                          -I (or from stdin) using your primary\n" \
"                          secret key. If -r has been given, a derived\n" \
"                          secret key will be used for signing.\n" \
"-c --check-signature <file> Verify a signature in file <file> against\n" \
"                          the file specified with -I (or stdin).\n" \
"                          The public key required for this must\n" \
"                          exist in your vault file.\n" \
"-f --sigfile <file>       Write a detached signature file, which doesn't\n" \
"                          contain the original content. Output will be\n" \
"                          z85 encoded always. To verify, you need to\n" \
"                          specify the original file to be verified\n" \
"                          against using -I as well (plus -f <sigfile>).\n" \
"\n" \
"Encoding Options:\n" \
"-z --z85-encode           Encode something to Z85 encoding. Use\n" \
"                          -I and -O respectively, otherwise it\n" \
"                          stdin/stdout.\n" \
"-Z --z85-decode           Decode something from Z85 encoding. Use\n" \
"                          -I and -O respectively, otherwise it\n" \
"                          stdin/stdout\n" \
"\n" \
"\n" \
"\n"
#endif
