#
#    This file is part of Pretty Curved Privacy (pcp1).
#
#    Copyright (C) 2013-2015 T. von Dein.
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

AM_CFLAGS = -I../include/pcp -I../src -I../libpcp/scrypt/crypto -Wall -g
check_PROGRAMS = col invalidkeys gencheader statictest cpptest \
		 buffertest sample streamtest pipetest decodertest mangle

gencheader_LDADD = ../libpcp/.libs/libpcp1.a
gencheader_SOURCES = gencheader.c

statictest_LDADD = ../libpcp/.libs/libpcp1.a
statictest_SOURCES = statictest.c

buffertest_LDADD = ../libpcp/.libs/libpcp1.a
buffertest_SOURCES = buffertest.c

sample_LDADD = ../libpcp/.libs/libpcp1.a
sample_SOURCES = sample.c

streamtest_LDADD = ../libpcp/.libs/libpcp1.a
streamtest_SOURCES = streamtest.c

pipetest_LDADD = ../libpcp/.libs/libpcp1.a
pipetest_SOURCES = pipetest.c

decodertest_LDADD = ../libpcp/.libs/libpcp1.a
decodertest_SOURCES = decodertest.c

col_LDADD = ../libpcp/.libs/libpcp1.a
col_SOURCES = collisions.c ../src/compat_getopt.c

mangle_LDADD = 
mangle_SOURCES = mangle.c

invalidkeys_LDADD = ../libpcp/.libs/libpcp1.a \
		    ../src/keyprint.o ../src/keymgmt.o ../src/readpass.o
invalidkeys_SOURCES = invalidkeys.c

AM_CXXFLAGS = -I../include -I../bindings/cpp -I../libpcp/scrypt/crypto -Wall -g
cpptest_LDADD = ../bindings/cpp/.libs/libpcp1++.a ../libpcp/.libs/libpcp1.a
cpptest_SOURCES = cpptest.cpp

#
# Note: some of these unit tests run only on freebsd.
# required sudo settings:
# %wheel ALL = NOPASSWD: /sbin/umount
# %wheel ALL = NOPASSWD: /sbin/mdmfs 

if BUILDPY
  MAYPY=pytest
endif

test: check $(MAYPY)

ctest:
	rm -f test* v* stresstest/*
	./unittests.pl unittests.cfg $(CHECK)
	@echo "To run a single test only, type: 'make test CHECK=testname'"

pytest:
	./unittests.pl pyunittests.cfg $(CHECK)

stresstest: check
	./unittests.pl stresstests.cfg

iotest: check
	./unittests.pl iotests.cfg
	sudo umount -f env
