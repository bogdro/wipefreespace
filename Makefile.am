#
# WipeFreeSpace - A program for secure cleaning of free space on filesystems.
#	-- Makefile.am, part of the build system.
#
# Copyright (C) 2007-2024 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
# License: GNU General Public License, v3+
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

SUBDIRS = doc src po test

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = config.rpath mkinstalldirs m4/ChangeLog wipefreespace.spec.in \
	m4/ax_c_check_flag.m4 THANKS patches INSTALL-WFS.txt m4/ax_check_link_flag.m4

x-pack:	doc/wipefreespace.info
	make dist-gzip
	tar zxf wipefreespace-@VERSION@.tar.gz
	echo '\input texinfo'			 > wipefreespace-@VERSION@/doc/wipefreespace.texi
	echo '@setfilename wipefreespace.info'	>> wipefreespace-@VERSION@/doc/wipefreespace.texi
	echo '@settitle wipefreespace manual'	>> wipefreespace-@VERSION@/doc/wipefreespace.texi
	echo '@bye'				>> wipefreespace-@VERSION@/doc/wipefreespace.texi
	tar zcf wipefreespace-@VERSION@.tar.gz wipefreespace-@VERSION@
	rm -fr wipefreespace-@VERSION@

.PHONY: x-pack
