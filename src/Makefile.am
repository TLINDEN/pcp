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


AM_CFLAGS = -I../include/pcp -I../libpcp/scrypt/crypto -Wall -g

bin_PROGRAMS = pcp1

pcp1_LDADD = ../libpcp/.libs/libpcp1.a
pcp1_SOURCES = pcp.c keymgmt.c keyprint.c readpass.c \
               encryption.c z85util.c signature.c \
               compat_getopt.c

