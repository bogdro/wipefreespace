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
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

bin_PROGRAMS = wipefreespace
datadir = @datadir@
wipefreespace_SOURCES = wipefreespace.c wipefreespace.h wfs_wrappers.c wfs_wrappers.h	\
	wfs_secure.c wfs_secure.h wfs_signal.c wfs_signal.h wfs_util.c wfs_util.h	\
	wfs_wiping.c wfs_wiping.h

wipefreespace_LDADD = $(INTLLIBS)
localedir = $(datadir)/locale
#INCLUDES = -I../intl -DLOCALEDIR=\"$(localedir)\"
AM_CPPFLAGS = -I../intl -DLOCALEDIR=\"$(localedir)\"
EXTRA_DIST = wfs_cfg.h.in

if EXT234FS
wipefreespace_SOURCES += wfs_ext234.h wfs_ext234.c
endif

if NTFS
wipefreespace_SOURCES += wfs_ntfs.h wfs_ntfs.c
endif

if XFS
wipefreespace_SOURCES += wfs_xfs.h wfs_xfs.c
endif

if REISERFS
wipefreespace_SOURCES += wfs_reiser.h wfs_reiser.c
endif

if REISER4
wipefreespace_SOURCES += wfs_reiser4.h wfs_reiser4.c
endif

if FATFS
wipefreespace_SOURCES += wfs_fat.h wfs_fat.c
endif

if MINIXFS
wipefreespace_SOURCES += wfs_minixfs.h wfs_minixfs.c
endif

if JFS
wipefreespace_SOURCES += wfs_jfs.h wfs_jfs.c
endif

if HFSP
wipefreespace_SOURCES += wfs_hfsp.h wfs_hfsp.c
endif

if OCFS
wipefreespace_SOURCES += wfs_ocfs.h wfs_ocfs.c
endif

