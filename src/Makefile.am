EXTRA_DIST = z85util.c 

AM_CFLAGS = -I../libpcp -Wall -g

bin_PROGRAMS = pcp1

pcp1_LDADD = ../libpcp/.libs/libpcp1.a
pcp1_SOURCES = pcp.c keymgmt.c keyprint.c readpass.c encryption.c z85util.c

