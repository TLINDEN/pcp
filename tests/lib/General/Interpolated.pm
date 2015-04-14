#
# Config::General::Interpolated - special Class based on Config::General
#
# Copyright (c) 2001 by Wei-Hon Chen <plasmaball@pchome.com.tw>.
# Copyright (c) 2000-2014 by Thomas Linden <tlinden |AT| cpan.org>.
# All Rights Reserved. Std. disclaimer applies.
# Artistic License, same as perl itself. Have fun.
#

package Config::General::Interpolated;
$Config::General::Interpolated::VERSION = "2.15";

use strict;
use Carp;
use Config::General;
use Exporter ();


# Import stuff from Config::General
use vars qw(@ISA @EXPORT);
@ISA = qw(Config::General Exporter);


sub new {
  #
  # overwrite new() with our own version
  # and call the parent class new()
  #

  croak "Deprecated method Config::General::Interpolated::new() called.\n"
       ."Use Config::General::new() instead and set the -InterPolateVars flag.\n";
}



sub _set_regex {
  #
  # set the regex for finding vars
  #

  # the following regex is provided by Autrijus Tang
  # <autrijus@autrijus.org>, and I made some modifications.
  # thanx, autrijus. :)
  my $regex = qr{
		 (^|\G|[^\\])   # $1: can be the beginning of the line
		                #     or the beginning of next match
		                #     but can't begin with a '\'
		 \$		# dollar sign
		 (\{)?		# $2: optional opening curly
		 ([a-zA-Z0-9_\-\.:\+,]+) # $3: capturing variable name (fix of #33447)
		 (?(2)		# $4: if there's the opening curly...
		 \}		#     ... match closing curly
		)
	       }x;
  return $regex;
}


sub _interpolate  {
  #
  # interpolate a scalar value and keep the result
  # on the varstack.
  #
  # called directly by Config::General::_parse_value()
  #
  my ($this, $config, $key, $value) = @_;
  my $quote_counter = 100;

  # some dirty trick to circumvent single quoted vars to be interpolated
  # we remove all quotes and replace them with unique random literals,
  # which will be replaced after interpolation with the original quotes
  # fixes bug rt#35766
  my %quotes;

  if(! $this->{AllowSingleQuoteInterpolation} ) {
    $value =~ s/(\'[^\']+?\')/
      my $key = "QUOTE" . ($quote_counter++) . "QUOTE";
      $quotes{ $key } = $1;
      $key;
    /gex;
  }

  $value =~ s{$this->{regex}}{
    my $con = $1;
    my $var = $3;
    my $var_lc = $this->{LowerCaseNames} ? lc($var) : $var;

    if (exists $config->{__stack}->{$var_lc}) {
      $con . $config->{__stack}->{$var_lc};
    }
    elsif ($this->{InterPolateEnv}) {
      # may lead to vulnerabilities, by default flag turned off
      if (defined($ENV{$var})) {
	$con . $ENV{$var};
      }
      else {
	$con;
      }
    }
    elsif ($this->{StrictVars}) {
      croak "Use of uninitialized variable (\$$var) while loading config entry: $key = $value\n";
    }
    else {
      # be cool
      $con;
    }
  }egx;

  # re-insert unaltered quotes
  # fixes bug rt#35766
  foreach my $quote (keys %quotes) {
    $value =~ s/$quote/$quotes{$quote}/;
  }

  return $value;
};


sub _interpolate_hash {
  #
  # interpolate a complete hash and keep the results
  # on the varstack.
  #
  # called directly by Config::General::new()
  #
  my ($this, $config) = @_;

  # bugfix rt.cpan.org#46184, moved code from _interpolate() to here.
  if ($this->{InterPolateEnv}) {
    # may lead to vulnerabilities, by default flag turned off
    for my $key (keys %ENV){
      $config->{__stack}->{$key}=$ENV{$key};
    }
  }

  $config = $this->_var_hash_stacker($config);

  return $config;
}

sub _var_hash_stacker {
  #
  # build a varstack of a given hash ref
  #
  my ($this, $config) = @_;

  foreach my $key (keys %{$config}) {
    next if($key eq "__stack");
    if (ref($config->{$key}) eq "ARRAY" ) {
      $config->{$key} = $this->_var_array_stacker($config->{$key}, $key);
    }
    elsif (ref($config->{$key}) eq "HASH") {
      my $tmphash = $config->{$key};
      $tmphash->{__stack} = $config->{__stack};
      $config->{$key} = $this->_var_hash_stacker($tmphash);
    }
    else {
      # SCALAR
      $config->{__stack}->{$key} = $config->{$key};
    }
  }

  return $config;
}


sub _var_array_stacker {
  #
  # same as _var_hash_stacker but for arrayrefs
  #
  my ($this, $config, $key) = @_;

  my @new;

  foreach my $entry (@{$config}) {
    if (ref($entry) eq "HASH") {
      $entry = $this->_var_hash_stacker($entry);
    }
    elsif (ref($entry) eq "ARRAY") {
      # ignore this. Arrays of Arrays cannot be created/supported
      # with Config::General, because they are not accessible by
      # any key (anonymous array-ref)
      next;
    }
    else {
      #### $config->{__stack}->{$key} = $config->{$key};
      # removed. a array of scalars (eg: option = [1,2,3]) cannot
      # be used for interpolation (which one shall we use?!), so
      # we ignore those types of lists.
      # found by fbicknel, fixes rt.cpan.org#41570
    }
    push @new, $entry;
  }

  return  \@new;
}

sub _clean_stack {
  #
  # recursively empty the variable stack
  #
  my ($this, $config) = @_;
  #return $config; # DEBUG
  foreach my $key (keys %{$config}) {
    if ($key eq "__stack") {
      delete $config->{__stack};
      next;
    }
    if (ref($config->{$key}) eq "ARRAY" ) {
      $config->{$key} = $this->_clean_array_stack($config->{$key});
    }
    elsif (ref($config->{$key}) eq "HASH") {
      $config->{$key} = $this->_clean_stack($config->{$key});
    }
  }
  return $config;
}


sub _clean_array_stack {
  #
  # same as _var_hash_stacker but for arrayrefs
  #
  my ($this, $config) = @_;

  my @new;

  foreach my $entry (@{$config}) {
    if (ref($entry) eq "HASH") {
      $entry = $this->_clean_stack($entry);
    }
    elsif (ref($entry) eq "ARRAY") {
      # ignore this. Arrays of Arrays cannot be created/supported
      # with Config::General, because they are not accessible by
      # any key (anonymous array-ref)
      next;
    }
    push @new, $entry;
  }

  return  \@new;
}

1;

__END__


=head1 NAME

Config::General::Interpolated - Parse variables within Config files


=head1 SYNOPSIS

 use Config::General;
 $conf = Config::General->new(
    -ConfigFile      => 'configfile',
    -InterPolateVars => 1
 );

=head1 DESCRIPTION

This is an internal module which makes it possible to interpolate
Perl style variables in your config file (i.e. C<$variable>
or C<${variable}>).

Normally you don't call it directly.


=head1 VARIABLES

Variables can be defined everywhere in the config and can be used
afterwards as the value of an option. Variables cannot be used as
keys or as part of keys.

If you define a variable inside
a block or a named block then it is only visible within this block or
within blocks which are defined inside this block. Well - let's take a
look to an example:

 # sample config which uses variables
 basedir   = /opt/ora
 user      = t_space
 sys       = unix
 <table intern>
     instance  = INTERN
     owner     = $user                 # "t_space"
     logdir    = $basedir/log          # "/opt/ora/log"
     sys       = macos
     <procs>
         misc1   = ${sys}_${instance}  # macos_INTERN
         misc2   = $user               # "t_space"
     </procs>
 </table>

This will result in the following structure:

 {
     'basedir' => '/opt/ora',
     'user'    => 't_space'
     'sys'     => 'unix',
     'table'   => {
	  'intern' => {
	        'sys'      => 'macos',
	        'logdir'   => '/opt/ora/log',
	        'instance' => 'INTERN',
	        'owner' => 't_space',
	        'procs' => {
		     'misc1' => 'macos_INTERN',
		     'misc2' => 't_space'
            }
	 }
     }

As you can see, the variable B<sys> has been defined twice. Inside
the <procs> block a variable ${sys} has been used, which then were
interpolated into the value of B<sys> defined inside the <table>
block, not the sys variable one level above. If sys were not defined
inside the <table> block then the "global" variable B<sys> would have
been used instead with the value of "unix".

Variables inside double quotes will be interpolated, but variables
inside single quotes will B<not> interpolated. This is the same
behavior as you know of Perl itself.

In addition you can surround variable names with curly braces to
avoid misinterpretation by the parser.

=head1 SEE ALSO

L<Config::General>

=head1 AUTHORS

 Thomas Linden <tlinden |AT| cpan.org>
 Autrijus Tang <autrijus@autrijus.org>
 Wei-Hon Chen <plasmaball@pchome.com.tw>

=head1 COPYRIGHT

Copyright 2001 by Wei-Hon Chen E<lt>plasmaball@pchome.com.twE<gt>.
Copyright 2002-2014 by Thomas Linden <tlinden |AT| cpan.org>.

This program is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

See L<http://www.perl.com/perl/misc/Artistic.html>

=head1 VERSION

2.15

=cut

