#
# WipeFreeSpace - A program for secure cleaning of free space on filesystems.
#	-- Makefile.am, part of the test build system.
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

if WFS_TESTS_ENABLED

TESTS = test_wfs_mount_check test_wfs_wiping test_wfs_wrappers
check_PROGRAMS = test_wfs_mount_check test_wfs_wiping test_wfs_wrappers
WFSTEST_COMMON_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
WFSTEST_COMMON_LDADD = @CHECK_LIBS@ @LIBS@
WFSTEST_FS_COMMON_LDADD = \
	$(top_builddir)/src/wfs_util.o \
	$(top_builddir)/src/wfs_subprocess.o \
	$(top_builddir)/src/wfs_wiping.o \
	$(WFSTEST_COMMON_LDADD)

test_wfs_mount_check_SOURCES = test_wfs_mount_check.c
test_wfs_mount_check_CFLAGS = $(WFSTEST_COMMON_CFLAGS)
test_wfs_mount_check_LDADD = $(top_builddir)/src/wfs_mount_check.o \
	$(WFSTEST_FS_COMMON_LDADD)

test_wfs_wiping_SOURCES = test_wfs_wiping.c
test_wfs_wiping_CFLAGS = $(WFSTEST_COMMON_CFLAGS)
test_wfs_wiping_LDADD = $(top_builddir)/src/wfs_wiping.o $(WFSTEST_COMMON_LDADD)

test_wfs_wrappers_SOURCES = test_wfs_wrappers.c test_stubs.c
test_wfs_wrappers_CFLAGS = $(WFSTEST_COMMON_CFLAGS)
test_wfs_wrappers_LDADD = $(top_builddir)/src/wfs_wrappers.o \
	$(top_builddir)/src/wfs_mount_check.o \
	$(WFSTEST_FS_COMMON_LDADD)

if EXT234FS
test_wfs_mount_check_LDADD += $(top_builddir)/src/wfs_ext234.o
test_wfs_wrappers_LDADD += $(top_builddir)/src/wfs_ext234.o

TESTS += test_wfs_ext234
check_PROGRAMS += test_wfs_ext234

test_wfs_ext234_SOURCES = test_wfs_ext234.c test_stubs.c
test_wfs_ext234_CFLAGS = $(WFSTEST_COMMON_CFLAGS)
test_wfs_ext234_LDADD = $(top_builddir)/src/wfs_ext234.o \
	$(WFSTEST_FS_COMMON_LDADD)
endif

if NTFS
test_wfs_mount_check_LDADD += $(top_builddir)/src/wfs_ntfs.o
test_wfs_wrappers_LDADD += $(top_builddir)/src/wfs_ntfs.o

TESTS += test_wfs_ntfs
check_PROGRAMS += test_wfs_ntfs

test_wfs_ntfs_SOURCES = test_wfs_ntfs.c test_stubs.c
test_wfs_ntfs_CFLAGS = $(WFSTEST_COMMON_CFLAGS)
test_wfs_ntfs_LDADD = $(top_builddir)/src/wfs_ntfs.o \
	$(WFSTEST_FS_COMMON_LDADD)
endif

if XFS
test_wfs_mount_check_LDADD += $(top_builddir)/src/wfs_xfs.o
test_wfs_wrappers_LDADD += $(top_builddir)/src/wfs_xfs.o

TESTS += test_wfs_xfs
check_PROGRAMS += test_wfs_xfs

test_wfs_xfs_SOURCES = test_wfs_xfs.c test_stubs.c
test_wfs_xfs_CFLAGS = $(WFSTEST_COMMON_CFLAGS)
test_wfs_xfs_LDADD = $(top_builddir)/src/wfs_xfs.o \
	$(WFSTEST_FS_COMMON_LDADD)
endif

if REISERFS
test_wfs_mount_check_LDADD += $(top_builddir)/src/wfs_reiser.o
test_wfs_wrappers_LDADD += $(top_builddir)/src/wfs_reiser.o

TESTS += test_wfs_reiser
check_PROGRAMS += test_wfs_reiser

test_wfs_reiser_SOURCES = test_wfs_reiser.c test_stubs.c
test_wfs_reiser_CFLAGS = $(WFSTEST_COMMON_CFLAGS)
test_wfs_reiser_LDADD = $(top_builddir)/src/wfs_reiser.o \
	$(WFSTEST_FS_COMMON_LDADD)
endif

if REISER4
test_wfs_mount_check_LDADD += $(top_builddir)/src/wfs_reiser4.o
test_wfs_wrappers_LDADD += $(top_builddir)/src/wfs_reiser4.o

TESTS += test_wfs_reiser4
check_PROGRAMS += test_wfs_reiser4

test_wfs_reiser4_SOURCES = test_wfs_reiser4.c test_stubs.c
test_wfs_reiser4_CFLAGS = $(WFSTEST_COMMON_CFLAGS)
test_wfs_reiser4_LDADD = $(top_builddir)/src/wfs_reiser4.o \
	$(WFSTEST_FS_COMMON_LDADD)
endif

if FATFS
test_wfs_mount_check_LDADD += $(top_builddir)/src/wfs_fat.o
test_wfs_wrappers_LDADD += $(top_builddir)/src/wfs_fat.o

TESTS += test_wfs_fat
check_PROGRAMS += test_wfs_fat

test_wfs_fat_SOURCES = test_wfs_fat.c test_stubs.c
test_wfs_fat_CFLAGS = $(WFSTEST_COMMON_CFLAGS)
test_wfs_fat_LDADD = $(top_builddir)/src/wfs_fat.o \
	$(WFSTEST_FS_COMMON_LDADD)
endif

if MINIXFS
test_wfs_mount_check_LDADD += $(top_builddir)/src/wfs_minixfs.o
test_wfs_wrappers_LDADD += $(top_builddir)/src/wfs_minixfs.o

TESTS += test_wfs_minixfs
check_PROGRAMS += test_wfs_minixfs

test_wfs_minixfs_SOURCES = test_wfs_minixfs.c test_stubs.c
test_wfs_minixfs_CFLAGS = $(WFSTEST_COMMON_CFLAGS)
test_wfs_minixfs_LDADD = $(top_builddir)/src/wfs_minixfs.o \
	$(WFSTEST_FS_COMMON_LDADD)
endif

if JFS
test_wfs_mount_check_LDADD += $(top_builddir)/src/wfs_jfs.o
test_wfs_wrappers_LDADD += $(top_builddir)/src/wfs_jfs.o

TESTS += test_wfs_jfs
check_PROGRAMS += test_wfs_jfs

test_wfs_jfs_SOURCES = test_wfs_jfs.c test_stubs.c
test_wfs_jfs_CFLAGS = $(WFSTEST_COMMON_CFLAGS)
test_wfs_jfs_LDADD = $(top_builddir)/src/wfs_jfs.o \
	$(WFSTEST_FS_COMMON_LDADD)
endif

if HFSP
test_wfs_mount_check_LDADD += $(top_builddir)/src/wfs_hfsp.o
test_wfs_wrappers_LDADD += $(top_builddir)/src/wfs_hfsp.o

TESTS += test_wfs_hfsp
check_PROGRAMS += test_wfs_hfsp

test_wfs_hfsp_SOURCES = test_wfs_hfsp.c test_stubs.c
test_wfs_hfsp_CFLAGS = $(WFSTEST_COMMON_CFLAGS)
test_wfs_hfsp_LDADD = $(top_builddir)/src/wfs_hfsp.o \
	$(WFSTEST_FS_COMMON_LDADD)
endif

if OCFS
test_wfs_mount_check_LDADD += $(top_builddir)/src/wfs_ocfs.o
test_wfs_wrappers_LDADD += $(top_builddir)/src/wfs_ocfs.o

TESTS += test_wfs_ocfs
check_PROGRAMS += test_wfs_ocfs

test_wfs_ocfs_SOURCES = test_wfs_ocfs.c test_stubs.c
test_wfs_ocfs_CFLAGS = $(WFSTEST_COMMON_CFLAGS)
test_wfs_ocfs_LDADD = $(top_builddir)/src/wfs_ocfs.o \
	$(WFSTEST_FS_COMMON_LDADD)
endif

x-compile: $(TESTS)
.PHONY: x-compile

endif
