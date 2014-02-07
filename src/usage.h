#ifndef _HAVE_USAGE_H
#define _HAVE_USAGE_H
#define PCP_HELP "\n" \
"Usage: pcp1 [ --help          | --version ]\n" \
"            [ --keygen        | --listkeys      | --remove-key    | --edit-key      ]\n" \
"            [ --export-public | --export-secret | --import-public | --import-secret ]\n" \
"            [ --encrypt       | --decrypt ]\n" \
"            [ --sign          | --check-signature ]\n" \
"            [ arguments ]\n" \
"\n" \
"General Options:\n" \
"-h --help                 Print this help message.\n" \
"-v --version              Print program version.\n" \
"-D --debug                Enable debug output.\n" \
"-V --vault <vaultfile>    Specify an alternate vault file.\n" \
"-O --outfile <file>       Output file. STDOUT if unspecified.\n" \
"-I --infile <file>        Input file. STDIN if unspecified.\n" \
"-i --keyid <id>           Specify a key id for various operations.\n" \
"-r --recipient <string>   Specify a recpipient, multiple allowed.\n" \
"-t --text                 Print textual representation of ojects.\n" \
"\n" \
"Keymanagement Options:\n" \
"-k --keygen               Generate new key pair.\n" \
"-l --listkeys             List all keys stored in your vault.\n" \
"-R --remove-key           Remove a key from the vault.\n" \
"-s --export-secret        Export a secret key.\n" \
"-p --export-public        Export a public key.\n" \
"-S --import-secret        Import a secret key.\n" \
"-P --import-public        Import a public key.\n" \
"-y --export-yaml          Export all keys as YAML formatted text.\n" \
"-b --pbpcompat            Enable PBP compatibility for public key\n" \
"                          exports and imports.\n" \
"Encryption Options:\n" \
"-e --encrypt              Asym-Encrypt a message. If none of -i or -r\n" \
"                          has been given, encrypt the message symetrically.\n" \
"-m --encrypt-me           Symetrically encrypt a message.\n" \
"-d --decrypt              Decrypt a message.\n" \
"\n" \
"Signature Options:\n" \
"-g --sign                 Create a signature of a file.\n" \
"-c --check-signature      Verify a signature of a file.\n" \
"-f --sigfile <file>       Write or check a detached signature file.\n" \
"\n" \
"Encoding Options:\n" \
"-z --z85-encode           Armor with Z85 encoding.\n" \
"\n" \
"Arguments:\n" \
"Extra arguments after options are treated as filenames or\n" \
"recipients, depending on operation mode.\n" \
"\n" \
"\n"
#endif
