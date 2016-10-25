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

if BUILDCPP
  MAYCPP=docpptest
  CPPTEST=cpptest
endif

if BUILDJSON
  MAYJSON=jsontest
endif

AM_CFLAGS = -I../include/pcp -I../src
check_PROGRAMS = invalidkeys gencheader statictest $(CPPTEST) \
		 buffertest sample streamtest pipetest decodertest mangle

EXTRA_DIST = Makefile.am Makefile.in *.c *.h *.sh *.pl *.py *.cfg *.cpp \
	     jot key-* unkn* README bart* env/* md5

LINK = $(LIBTOOL) --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) \
        --mode=link $(CCLD) $(AM_LDFLAGS) \
        $(LDFLAGS) -o $@

CXXLINK = $(LIBTOOL) --tag=CXX $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) \
        --mode=link $(CXXLD) $(AM_LDFLAGS) \
        $(LDFLAGS) -o $@

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

mangle_LDADD = 
mangle_SOURCES = mangle.c

invalidkeys_LDADD = ../libpcp/.libs/libpcp1.a \
		    ../src/keyprint.o ../src/keymgmt.o
invalidkeys_SOURCES = invalidkeys.c

if BUILDCPP
AM_CXXFLAGS = -I../include -I../bindings/cpp -I../libpcp/scrypt/crypto
cpptest_LDADD = ../bindings/cpp/.libs/libpcp1++.a ../libpcp/.libs/libpcp1.a
cpptest_SOURCES = cpptest.cpp
endif

#
# Note: some of these unit tests run only on freebsd.
# required sudo settings:
# %wheel ALL = NOPASSWD: /sbin/umount
# %wheel ALL = NOPASSWD: /sbin/mdmfs 

if BUILDPY
  MAYPY=pytest
endif

et:
	@echo check ctest $(MAYPY) $(MAYCPP) $(MAYJSON)

test: check ctest $(MAYPY) $(MAYCPP) $(MAYJSON)

ctest:
	rm -f test* v* stresstest/*
	./unittests.sh unittests.cfg $(CHECK)
	@echo "To run a single test only, type: 'make test CHECK=testname'"

pytest:
	./unittests.sh pyunittests.cfg $(CHECK)

docpptest:
	./unittests.sh cppunittests.cfg $(CHECK)

jsontest:
	./unittests.sh jsonunittests.cfg $(CHECK)

stresstest: check
	./unittests.pl stresstests.cfg

iotest: check
	./unittests.pl iotests.cfg
	sudo umount -f env
