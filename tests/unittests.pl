#!/usr/bin/perl
use Test::More;
use IPC::Open3;
use IO::Select;
use FileHandle;
use Config::General qw(ParseConfig);
use Tie::IxHash;
use Data::Dumper;

sub run;
sub execute;

my ($config, $check) = @ARGV;
if (! $config) {
  die "usage: $0 <config>\n";
}

my %cfg = ParseConfig(-ConfigFile => $config,
		      -InterPolateVars => 1,
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
      }
    }
  }
}


sub runtest {
  my($cfg, $name) = @_;
  my($in, $out, $error, $timeout);

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

  my $ret = run($cfg->{cmd},
		$cfg->{input},
		\$out, \$error, 5, 0, undef);

  my $output = $out . $error;
  

  $output =~ s/^\s*//;
  $output =~ s/\s*$//;

  if (exists $cfg->{expect}) {
    if ($cfg->{expect} =~ /^\//) {
      like($output, $cfg->{expect}, "$name") or return 0;
    }
    else {
      is($output, $cfg->{expect}, "$name") or return 0;
    }
  }

  elsif (exists $cfg->{"expect-file"}) {
    my $e = 0;
    if (-s $cfg->{"expect-file"}) {
      $e = 1;
    }
    is($e, 1, "$name") or return 0;
  }

  elsif (exists $cfg->{"expect-file-contains"}) {
    my($file, $expext) = split /\s\s*/, $cfg->{"expect-file-contains"};
    my $e = 0;
    if (-s $file) {
      $e = 1;
    }
    is($e, 1, "$name") or return 0;
    if (open F, "<$file") {
      my $content = join '', <F>;
      close F;
      like($content, qr/$expect/s, "$name") or return 0;
    }
    else {
      fail($test);
      return 0;
    }
  }

  elsif (exists $cfg->{exit}) {
    is($ret, $cfg->{exit}, "$name") or return 0;
  }

  else {
    diag("invalid test spec for $test");
    fail($test);
    return 0;
  }

  return 1;
}

done_testing;

sub run {
  # open3 wrapper. catch stderr, stdout, errno; add timeout and kill
  my($cmd, $input, $output, $error, $timeout, $debug, $monitorfile) = @_;

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

