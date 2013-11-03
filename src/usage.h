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
"                          item. Either -V or -i must be specified\n" \
"                          as well.\n" \
"-h --help                 Print this help message.\n" \
"-v --version              Print program version.\n" \
"-D --debug                Enable debug output.\n" \
"\n" \
"Keymanagement Options:\n" \
"-k --keygen               Generate a CURVE25519 secret key. If\n" \
"                          the generated key is the first one in\n" \
"                          your vault, it will become the primary\n" \
"                          secret key.\n" \
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
"\n" \
"Encryption Options:\n" \
"-e --encrypt              Encrypt a message. Read from stdin or\n" \
"                          specified via -I. A keyid (-i) of the\n" \
"                          public key of the receipient must be\n" \
"                          specified. Output to stdout or written\n" \
"                          to the file specified via -O.\n" \
"-d --decrypt              Decrypt a message. Read from stdin or\n" \
"                          specified via -I. Output to stdout or\n" \
"                          written to the file specified via -O.\n" \
"                          The primary secret key will be used for\n" \
"                          decryption, if there is no primary and\n" \
"                          just one secret key in the vault, this\n" \
"                          one will be used. Otherwise you'll have\n" \
"                          to specify the keyid (-i) of the key.\n" \
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
