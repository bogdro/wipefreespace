bin_PROGRAMS = wipefreespace
datadir = @datadir@
wipefreespace_SOURCES = wipefreespace.c wrappers.c wipefreespace.h wrappers.h wfs_cfg.h ../config.h \
	secure.c secure.h wfs_signal.c wfs_signal.h
wipefreespace_LDADD = $(INTLLIBS)
localedir = $(datadir)/locale
INCLUDES = -I../intl -DLOCALEDIR=\"$(localedir)\"

if ISGCC
AM_CFLAGS = 	-Wall -Wextra -Wfloat-equal -Wbad-function-cast		\
		-Wsign-compare -Wunreachable-code -Wpointer-arith	\
		-Wcast-qual -Wcast-align -Wstrict-prototypes 		\
		-Wformat-security -Wformat-nonliteral -Wnested-externs	\
		-Wshadow -Wconversion -Wdeclaration-after-statement	\
		-Wundef -Wpadded -Wredundant-decls -Wfatal-errors	\
  		-pedantic -g
endif

if EXT2FS
wipefreespace_SOURCES += ext23.h ext23.c
#wipefreespace_LDADD += -lext2fs
endif

if NTFS
wipefreespace_LDADD += libwfsntfs.a
noinst_LIBRARIES = libwfsntfs.a
libwfsntfs_a_SOURCES = wfs_ntfs.h wfs_ntfs.c
if ISGCC
libwfsntfs_a_CFLAGS = -std=gnu99 $(AM_CFLAGS)
endif
#wipefreespace_LDADD += -lntfs
endif

if XFS
wipefreespace_LDADD += libwfsxfs.a
noinst_LIBRARIES = libwfsxfs.a
libwfsxfs_a_SOURCES = wfs_xfs.h wfs_xfs.c
if ISGCC
AM_CFLAGS	+= -std=gnu99
libwfsxfs_a_CFLAGS = -std=gnu99 $(AM_CFLAGS)
endif
#####wipefreespace_SOURCES += wfs_xfs.h wfs_xfs.c
#####wipefreespace_LDADD += -lxfs
endif

#if REISERFS
#wipefreespace_SOURCES += wfs_reiser.h wfs_reiser.c
#wipefreespace_LDADD += -lcore -lmisc -luuid
#endif

#if COMERR
#wipefreespace_LDADD += -lcom_err
#endif

#if SYSCAP
#wipefreespace_LDADD += -lcap
#endif
