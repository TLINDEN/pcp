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
dist_man_MANS = pcp1.1
DATAROOTDIR = /usr
DOXDIR = $(prefix)/share/doc/libpcp-$(VERSION)

DOC_FILES = html/* ../README.txt ../COPYING ../AUTHORS ../INSTALL ../ChangeLog ../config.log

# FIXME: make doc install optional...
install-data-local:
	$(INSTALL) -m 755 -d $(DOXDIR)
	$(INSTALL) -m 644 $(DOC_FILES) $(DOXDIR)/

