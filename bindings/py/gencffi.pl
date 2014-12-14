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

my @code;

foreach my $head (@ARGV) {
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
    push @code, ('', "/*** $0: from $head:$. */");
    push @code, $1;
  }

  # a struct
  # the uthash handle doesn't resolve, so we
  # use a placeholder
  while ($raw =~ /(struct [^\s]* \{[^\}]*\};)/gs) {
    my $code = $1;
    $code =~ s/UT_hash_handle hh/byte hh[56]/g;
    push @code, ('', "/*** $0: from $head:$. */");
    push @code, $code;
  }

  # a function
  while ($raw =~ /^([a-zA-Z].*\(.*\);)/gm) {
    my $c = $1;
    push @code, ('', "/*** $0: from $head:$. */");
    push @code, $c;
  }

  close $head;
}



print "PCP_RAW_CODE = '''\n";
print join "\n", @code;
print "'''\n";

