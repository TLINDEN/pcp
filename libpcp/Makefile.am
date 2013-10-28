AM_CFLAGS = -I../libpcp -Wall -g

lib_LTLIBRARIES      = libpcp1.la

libpcp1_la_SOURCES = mac.c mem.c pad.c version.c warn.c \
		    z85.c zmq_z85.c key.c randomart.c \
		    vault.c fatal.c jenhash.c digital_crc32.c \
                    crypto.c

include_HEADERS      = ../include/pcp.h
