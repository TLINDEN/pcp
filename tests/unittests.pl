#!/usr/bin/perl
#
#    This file is part of Pretty Curved Privacy (pcp1).
#
#    Copyright (C) 2013 T.Linden.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    You can contact me by mail: <tlinden AT cpan DOT org>.
#
use lib qw(lib);

BEGIN {
  eval {
    use IPC::Run qw( run timeout);
  };
};

use Test::More;
use IPC::Open3;
use IO::Select;
use FileHandle;
use Config::General qw(ParseConfig);
use Tie::IxHash;
use Data::Dumper;

sub run3;
sub execute;
sub final;

my $output;

my ($config, $check) = @ARGV;
if (! $config) {
  die "usage: $0 <config>\n";
}

my %cfg = ParseConfig(-ConfigFile => $config,
		      -InterPolateVars => 1,
		      -UseApacheInclude => 1,
		      -Tie => "Tie::IxHash" );
my $verbose = $cfg{verbose};

if (exists $cfg{confirm}) {
  print "$cfg{confirm} [CTRL-C to abort, <ENTER> to continue] ";
  my $cont = <STDIN>;
}

if ($check) {
  if (exists $cfg{test}->{$check}) {
    &runtest($cfg{test}->{$check}, $check);
  }
}
else {
  my $continue = 1;
  foreach my $test (keys %{$cfg{test}}) {
    if ($continue) {
      $continue = &runtest($cfg{test}->{$test}, $test);
      if (!$continue) {
	print "Last failed check: $test\n";
	break;
      }
    }
  }
}


sub runtest {
  my($cfg, $name) = @_;
  my($in, $out, $error, $timeout);

  if (exists $cfg->{loop}) {
    my $loop = delete $cfg->{loop};
    foreach my $n (0 .. $loop) {
      if (&runtest($cfg, "${name}-loop-${n}") == 0) {
	return 0;
      }
    }
    return 1;
  }

  foreach my $key (keys %{$cfg}) {
    $cfg->{$key}   =~ s/\`([^\`]*)\`/my $result = `$1`; chomp $result; $result/ge;
  }

  if (exists $cfg->{prepare}) {
    print STDERR "  executing prepare command: $cfg->{prepare}\n" if ($verbose);
    if ($cfg->{prepare} =~ />/) {
      system("$cfg->{prepare}");
    }
    else {
      system("$cfg->{prepare} > /dev/null 2>&1");
    }
  }

  if (exists $cfg->{test}) {
    foreach my $test (keys %{$cfg->{test}}) {
      my $name = "$test ($cfg->{test}->{$test}->{cmd})";
      if (&runtest($cfg->{test}->{$test}, $name) == 0) {
	return 0;
      }
    }
    return 1;
  }

  $cfg->{cmd} =~ s/%\{([^\}]*)\}/
    my $N = $1; my $o;
    if (exists $cfg->{$N}) {
      $o = `$cfg->{$N}`;
      chomp $o;
    }
    $o;
  /gex;

  print STDERR "\n$cfg->{cmd}\n      ";

  my $ret = run3($cfg->{cmd},
		$cfg->{input},
		\$out, \$error, 10, 0, undef);

  $output = $out . $error;
  
  $output =~ s/^\s*//;
  $output =~ s/\s*$//;

  printf "$output\n" if $verbose > 1;

  if (exists $cfg->{expect}) {
    if ($cfg->{expect} =~ /^!(\/.*)/) {
      unlike($output, $1, "$name") or return final 0;
    }
    elsif ($cfg->{expect} =~ /^\//) {
      like($output, $cfg->{expect}, "$name") or return final 0;
    }
    else {
      is($output, $cfg->{expect}, "$name") or return final 0;
    }
  }

  elsif (exists $cfg->{"expect-file"}) {
    my $e = 0;
    if (-s $cfg->{"expect-file"}) {
      $e = 1;
    }
    is($e, 1, "$name") or return final 0;
  }

  elsif (exists $cfg->{"expect-file-contains"}) {
    my($file, $expext) = split /\s\s*/, $cfg->{"expect-file-contains"};
    my $e = 0;
    if (-s $file) {
      $e = 1;
    }
    is($e, 1, "$name") or return final 0;
    if (open F, "<$file") {
      my $content = join '', <F>;
      close F;
      like($content, qr/$expect/s, "$name") or return final 0;
    }
    else {
      fail($test);
      return final 0;
    }
  }

  elsif (exists $cfg->{exit}) {
    is($ret, $cfg->{exit}, "$name") or return final 0;
  }

  else {
    diag("invalid test spec for $test");
    fail($test);
    return final 0;
  }

  

  return final 1;
}

done_testing;


sub final {
  my $ret = shift;
  system("stty echo"); # turn echo on, just in case a prompt timed out
  if ($output =~ /(segmentation fault|bus error)/i || -s "pcp1.core") {
    # override $ret
    $ret = 0;
    diag("Abnormal program termination");
    # if there is a coredump, extract a backtrace
    if (-s "pcp1.core") {
      # print a backtrace
      system("gdb -x .gdb -batch $cfg{pcp} pcp1.core");
      unlink "pcp1.core";
    }
  }
  return $ret;
}

sub run3 {
  # open3 wrapper. catch stderr, stdout, errno; add timeout and kill
  my($cmd, $input, $output, $error, $timeout, $debug, $monitorfile) = @_;

  if ($^O =~ /win/i) {
    my ($o, $e, @c);
    if ($cmd =~ /\|/) {
      @c = ("sh", "-c", $cmd);
    }
    else {
      @c = split /\s\s*/, $cmd;
    }
    my $ret = run \@c, \$input, \$o, \$e, timeout( $timeout );
    $$output = $o;
    $$error = $e;
    return ret;
  }

  my ($stdin, $stderr, $stdout) = ('', '', '');

  my $child = 0;
  my $cmdline = join " ", @{$cmd};
  $timeout = $timeout ? $timeout : 10;
  $SIG{CHLD} = &reaper;

 REENTRY:
  eval {
    local $SIG{ALRM} = sub { die "timeout" };
    alarm $timeout;

    if ($child && kill 0, $child) {
      ;
    }
    else {
      $child = open3($stdin, $stdout, $stderr, $cmd);
      $childs++;
      
      if ($input) {
	print $stdin $input;
      }
      $stdin->close();
    }
    
    my $sel = new IO::Select;
    $sel->add($stdout, $stderr);
    
    while(my @ready = $sel->can_read) {
      foreach my $fh (@ready) {
	my $line;
	my $len = sysread $fh, $line, 4096;
	if(not defined $len){
	  die "Error from child: $!\n";
	}
	elsif ($len == 0){
	  $sel->remove($fh);
	  next;
	}
	else {
	  if(fileno($fh) == fileno($stdout)) {
	    $$output .= $line;
	  }
	  elsif(fileno($fh) == fileno($stderr)) {
	    $$error .= $line;
	  }
	  else {
	    die "Unknown filehandle returned!\n";
	  }
	}
      }
    }
    alarm 0;
    close $stderr;
    close $stdout;
  };
  
 TRY:
  my($exitcode, $killsignal, $coredumped);
  
  if ($@ !~ /timeout at/) {
    my ($alert);
    while ($childs > 0 || kill(0, $child)) {
      if ((time - $alert) >= 60) {
	$alert = time;
      }
    }
    
    $childs        = 0;
    $CHILD_ERROR   = $childerror{$child};
    $killsignal = $CHILD_ERROR & 127;
    $coredumped = $CHILD_ERROR & 127;
  }

  $exitcode   = $CHILD_ERROR >> 8;

  if ($@ || ($exitcode != 0)) {
    chomp $@;
    if ($@ =~ /timeout/) {
      if (kill 0, $child) {
	# whoe it's still running
	if ($monitorfile) {
	  my $size = -s $monitorfile;
	  sleep $timeout;
	  my $nsize = -s $monitorfile;
	  if ($size != $nsize and kill 0, $child) {
	    # well, file still growing, so the process seems still to work
	    # go back to the eval{} block and enter select() again
	    goto REENTRY;
					}
	  else {
	    # process no more running
	    # reset $@ and go back to returncode check
	    $@ = "";
	    goto TRY;
	  }
	}
	else {
	  # get rid of it
	  $$error .= "Timed out after $timeout seconds!\n";
	  kill TERM => $child;
	}
      }
    }
    else {
      $$error .= $@;
    }
    return $exitcode;
  }
  else {
    return $exitcode;
  }
}

sub runipc  {
  my($cmd, $input, $output, $error, $timeout, $debug, $monitorfile) = @_;

  print STDERR Dumper(\@_);

  if (run $cmd, $input, $output, $error, timeout( $timeout )) {
    return 0;
  }
  else {
    return 1;
  }

}

sub reaper {
  my $pid;
  while (1) {
    my $pid =  waitpid(-1,WNOHANG);
    if ($pid) {
      $childs-- if $pid > 0;
      $childerror{$pid} = $CHILD_ERROR;
      last;
    }
  }
  $SIG{CHLD} = \&reaper;
}

