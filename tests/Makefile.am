
AM_CFLAGS = -I../libpcp -Wall -g
check_PROGRAMS = col invalidkeys

col_LDADD = ../libpcp/.libs/libpcp1.a
col_SOURCES = collisions.c

invalidkeys_LDADD = ../libpcp/.libs/libpcp1.a ../src/keyprint.o
invalidkeys_SOURCES = invalidkeys.c
AM_CPPFLAGS = -I$(top_builddir)/src


test: check
	./unittests.pl unittests.cfg

stresstest: check
	./unittests.pl stresstests.cfg
