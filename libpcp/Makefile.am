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
AM_CFLAGS =  -I../include/pcp -Iscrypt/util

lib_LTLIBRARIES      = libpcp1.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libpcp1.pc

libpcp1_la_SOURCES = platform.c  mem.c version.c \
		    context.c z85.c zmq_z85.c key.c randomart.c \
		    vault.c jenhash.c  \
                    crypto.c ed.c keyhash.c scrypt.c \
		    util.c buffer.c mgmt.c keysig.c pcpstream.c

include_HEADERS      = ../include/pcp.h

libpcp1_la_LINK = $(LIBTOOL) --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) \
                  --mode=link $(CCLD) $(AM_LDFLAGS) \
	          $(LDFLAGS) -o $@
