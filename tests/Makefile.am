
AM_CFLAGS = -I../libpcp -Wall -g
check_PROGRAMS = col invalidkeys pwhashes

col_LDADD = ../libpcp/.libs/libpcp1.a
col_SOURCES = collisions.c

invalidkeys_LDADD = ../libpcp/.libs/libpcp1.a ../src/keyprint.o
invalidkeys_SOURCES = invalidkeys.c

pwhashes_LDADD = ../libpcp/.libs/libpcp1.a
pwhashes_SOURCES = pwhashes.c

AM_CPPFLAGS = -I$(top_builddir)/src


test: check
	rm -f test* v* stresstest/*
	./unittests.pl unittests.cfg $(CHECK)
	@echo "To run a single test only, type: 'make test CHECK=testname'"

stresstest: check
	./unittests.pl stresstests.cfg
