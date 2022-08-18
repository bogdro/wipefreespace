if WFS_TESTS_ENABLED

TESTS = test_wfs_util test_wfs_wiping
check_PROGRAMS = test_wfs_util test_wfs_wiping
WFSTEST_COMMON_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src

test_wfs_util_SOURCES = test_wfs_util.c
test_wfs_util_CFLAGS = $(WFSTEST_COMMON_CFLAGS)
test_wfs_util_LDADD = $(top_builddir)/src/wfs_util.o @CHECK_LIBS@ @LIBS@

if EXT234FS
test_wfs_util_LDADD += $(top_builddir)/src/wfs_ext234.o
endif

if NTFS
test_wfs_util_LDADD += $(top_builddir)/src/wfs_ntfs.o
endif

if XFS
test_wfs_util_LDADD += $(top_builddir)/src/wfs_xfs.o
endif

if REISERFS
test_wfs_util_LDADD += $(top_builddir)/src/wfs_reiser.o
endif

if REISER4
test_wfs_util_LDADD += $(top_builddir)/src/wfs_reiser4.o
endif

if FATFS
test_wfs_util_LDADD += $(top_builddir)/src/wfs_fat.o
endif

if MINIXFS
test_wfs_util_LDADD += $(top_builddir)/src/wfs_minixfs.o
endif

if JFS
test_wfs_util_LDADD += $(top_builddir)/src/wfs_jfs.o
endif

if HFSP
test_wfs_util_LDADD += $(top_builddir)/src/wfs_hfsp.o
endif

if OCFS
test_wfs_util_LDADD += $(top_builddir)/src/wfs_ocfs.o
endif

test_wfs_wiping_SOURCES = test_wfs_wiping.c
test_wfs_wiping_CFLAGS = $(WFSTEST_COMMON_CFLAGS)
test_wfs_wiping_LDADD = $(top_builddir)/src/wfs_wiping.o @CHECK_LIBS@ @LIBS@

zcompile: $(TESTS)
.PHONY: zcompile

endif
