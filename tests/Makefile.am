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

AM_CFLAGS = -I../include/pcp -Wall -g
check_PROGRAMS = col invalidkeys pwhashes

col_LDADD = ../libpcp/.libs/libpcp1.a
col_SOURCES = collisions.c

invalidkeys_LDADD = ../libpcp/.libs/libpcp1.a ../src/keyprint.o
invalidkeys_SOURCES = invalidkeys.c

pwhashes_LDADD = ../libpcp/.libs/libpcp1.a
pwhashes_SOURCES = pwhashes.c

AM_CPPFLAGS = -I$(top_builddir)/src


#
# Note: some of these unit tests run only on freebsd.
# required sudo settings:
# %wheel ALL = NOPASSWD: /sbin/umount
# %wheel ALL = NOPASSWD: /sbin/mdmfs 

test: check
	rm -f test* v* stresstest/*
	./unittests.pl unittests.cfg $(CHECK)
	@echo "To run a single test only, type: 'make test CHECK=testname'"
	sudo umount -f env

stresstest: check
	./unittests.pl stresstests.cfg
