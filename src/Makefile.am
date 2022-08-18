bin_PROGRAMS = wipefreespace
datadir = @datadir@
wipefreespace_SOURCES = wipefreespace.c wipefreespace.h wfs_wrappers.c wfs_wrappers.h	\
	wfs_secure.c wfs_secure.h wfs_signal.c wfs_signal.h wfs_util.c wfs_util.h

wipefreespace_LDADD = $(INTLLIBS)
localedir = $(datadir)/locale
INCLUDES = -I../intl -DLOCALEDIR=\"$(localedir)\"
EXTRA_DIST = wfs_cfg.h.in

if EXT234FS
wipefreespace_SOURCES += wfs_ext23.h wfs_ext23.c
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

