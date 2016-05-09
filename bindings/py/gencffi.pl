#!/usr/bin/perl
use Data::Dumper;

my %sobytes = (
               'crypto_box_NONCEBYTES' => 24,
               'crypto_box_PUBLICKEYBYTES' => 32,
               'crypto_box_SECRETKEYBYTES' => 32,
               'crypto_box_ZEROBYTES' => 32,
               'crypto_box_BOXZEROBYTES' => 16,
               'crypto_box_MACBYTES' => 16,
               'crypto_secretbox_KEYBYTES' => 32,
               'crypto_secretbox_NONCEBYTES' => 24,
               'crypto_secretbox_ZEROBYTES' => 32,
               'crypto_secretbox_BOXZEROBYTES' => 16,
               'crypto_secretbox_MACBYTES' => 16,
               'crypto_sign_PUBLICKEYBYTES' => 32,
               'crypto_sign_SECRETKEYBYTES' => 64,
               'crypto_sign_SEEDBYTES' => 32,
               'crypto_sign_BYTES' => 64,
               'crypto_stream_KEYBYTES' => 32,
               'crypto_stream_NONCEBYTES' => 24,
               'crypto_generichash_BYTES' => 32,
               'crypto_scalarmult_curve25519_BYTES' => 32,
               'crypto_scalarmult_BYTES' => 32,
               'crypto_generichash_BYTES_MAX' => 64,
              );

my @ignore = qw(uthash.h);

my @code;
my @structs;
my @typedefs;
my %defs;

foreach my $head (@ARGV) {
  next if grep { $head =~ $_} @ignore;
  open HEAD, "<$head" or die "Could not open $head: $!\n";
  my $raw = join '', <HEAD>;

  # resolve sodium constants
  foreach my $sobyte (sort { length($b) <=> length($a) } keys %sobytes) {
    $raw =~ s/$sobyte/$sobytes{$sobyte}/g;
  }

  # some sizes are calculated, cffi doesn't so do we
  $raw =~ s/(\d+) \+ (\d+)/$1 + $2/ge;

  # 1line type
  while ($raw =~ /^(typedef .*;)/gm) {
    push @typedefs, ('', "/*** $0: from $head:$. */");
    push @typedefs, $1;
  }

  # a struct
  # the uthash handle doesn't resolve, so we
  # use a placeholder
  while ($raw =~ /(struct [^\s]* \{[^\}]*\};)/gs) {
    my $code = $1;
    $code =~ s/UT_hash_handle hh/byte hh[56]/g;
    push @structs, ('', "/*** $0: from $head:$. */");
    push @structs, $code;
  }

  # a function
  while ($raw =~ /^([a-zA-Z].*\(.*\);)/gm) {
    my $c = $1;
    push @code, ('', "/*** $0: from $head:$. */");
    push @code, $c;
  }

  # a definition
  while ($raw =~ /^\s*#define ((EXP|PCP|PBP).*)$/gm) {
    my ($name, $def) = split /\s\s*/, $1, 2;
    $def =~ s/\/\*.*//;
    next if ($name =~ /_VERSION/);
    if (!exists $defs{$name} && $def !~ /(sizeof| \+ )/) {
      $defs{$name} = "\n# $0: from $head:$.\n$name = $def\n";
    }
  }

  close $head;
  $. = 0;
}



print "PCP_RAW_CODE = '''\n";
print qq(
typedef enum {
JSON_OBJECT,
JSON_ARRAY,
JSON_STRING,
JSON_INTEGER,
JSON_REAL,
JSON_TRUE,
JSON_FALSE,
JSON_NULL
} json_type;

typedef struct json_t {
json_type type;
size_t refcount;
} json_t;
);
print join "\n", @typedefs;
print join "\n", @structs;
print join "\n", @code;
print "'''\n";


print join "\n", values %defs;
