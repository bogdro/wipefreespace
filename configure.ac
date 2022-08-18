#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(wipefreespace, 1.0, bogdandr@op.pl)
AM_INIT_AUTOMAKE
AC_CONFIG_FILES([Makefile src/Makefile doc/wipefreespace.texi wipefreespace.spec\
	src/wfs_cfg.h doc/Makefile po/Makefile.in po/Makefile])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])

# ==================== configure arguments

AC_ARG_ENABLE(EXT234,[[  --enable-EXT234	Ext2/3/4 support (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_ext234=no
	 else
		feat_ext234=yes
	 fi
	]
	,feat_ext234=yes)

AC_ARG_ENABLE(NTFS,[[  --enable-NTFS		NTFS support (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_ntfs=no
	 else
		feat_ntfs=yes
	 fi
	]
	,feat_ntfs=yes)

AC_ARG_ENABLE(XFS,[[  --enable-XFS		XFS support (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_xfs=no
	 else
		feat_xfs=yes
	 fi
	]
	,feat_xfs=yes)

AC_ARG_ENABLE(REISERFS,[[  --enable-REISERFS	ReiserFSv3+ support (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_reiser=no
	 else
		feat_reiser=yes
	 fi
	]
	,feat_reiser=yes)

AC_ARG_ENABLE(REISER4,[[  --enable-REISER4	ReiserFSv4 support (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_reiser4=no
	 else
		feat_reiser4=yes
	 fi
	]
	,feat_reiser4=yes)

AC_ARG_ENABLE(LSR_WANT_RANDOM,[[  --enable-random-method	Random pattern method (like shred) instead of full Gutmann.]],
	[if (test "x$enableval" = "xyes"); then
		want_rand=yes
	 else
		want_rand=no
	 fi
	]
	,want_rand=no)

if (test "x$want_rand" = "xyes"); then
	AC_DEFINE(LSR_WANT_RANDOM, [1], [If shred-like wiping method was chosen instead of full Gutmann method.])
fi

# ==================== Set of available languages (deprecated).
#ALL_LINGUAS="pl"

# ==================== Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB
AM_CONDITIONAL(ISGCC, [test "x$GCC" = "xyes"])

# ==================== Checks for libraries.
# OpenBSD needs libssl and libcrypto for libcom_err, which is part of
#	krb5-devel in that world. Autoconf cache makes the second test
#	(with the libraries) negative, so this is disabled.
#AC_CHECK_LIB(com_err,com_err,,
#
#	AC_CHECK_LIB(ssl,ssl_cert_new,,, -lcrypto)
#	AC_CHECK_LIB(crypto,RAND_add,,, -lssl)
#	AC_CHECK_LIB(com_err,com_err,,,-lssl -lcrypto)
#)

libcomm=yes
AC_CHECK_LIB([com_err],[com_err],,[libcomm=no])

libext234=no
if ( test "x$feat_ext234" = "xyes" ); then

	libext234=yes
	AC_CHECK_LIB([ext2fs],[ext2fs_open],,[libext234=no])
fi

libcap=yes
AC_CHECK_LIB([cap],[cap_init],,[libcap=no])

libntfs=no
if ( test "x$feat_ntfs" = "xyes" ); then

	libntfs=yes
	AC_CHECK_LIB([ntfs],[ntfs_pwrite],,[libntfs=no])
fi

#AC_CHECK_LIB(pthread,pthread_create)

libuuid=no
if ( test "x$feat_reiser" = "xyes" || test "x$feat_reiser4" = "xyes" ); then
	libuuid=yes
	AC_CHECK_LIB([uuid],[uuid_unparse],,[libuuid=no])
fi

libmisc=no
libcore=no
if ( test "x$feat_reiser" = "xyes" ); then

	if (test "x$libuuid" = "xyes"); then

		libmisc=yes
		libcore=yes
		AC_CHECK_LIB([misc],[misc_test_bit],,[libmisc=no],[-luuid])
		AC_CHECK_LIB([core],[reiserfs_open],,[libcore=no],[-lmisc -luuid])
	else
		AC_MSG_WARN([[ReiserFS support impossible without the uuid library.]])
	fi
fi

libaal=no
if ( test "x$feat_reiser4" = "xyes" ); then

	libaal=yes
	AC_CHECK_LIB([aal],[aal_device_open],,[libaal=no])
	if (test "x$libaal" = "xyes" && test "x$libuuid" = "xyes"); then

		libreiser4=yes
		AC_CHECK_LIB([reiser4misc],[misc_str2long],,,[-laal -luuid -lreiser4])
		AC_CHECK_LIB([reiser4],[reiser4_fs_open],,[libreiser4=no],[-laal -luuid -lreiser4misc])
	else
		AC_MSG_WARN([[Reiser4 support impossible without the aal and uuid libraries.
			Libmisc.a from reiser4progs has to be installed under a new name:
			libreiser4misc.a]])
	fi
fi

# ==================== Checks for header files.
AC_HEADER_STDC

AC_CHECK_HEADER([getopt.h],AC_DEFINE([HAVE_GETOPT_H],[1],[Whether you have the getopt.h header.]),
	[AC_MSG_ERROR([[I need getopt.h to work.]])]
	)

AC_CHECK_HEADERS([sys/time.h time.h sys/stat.h])
AC_HEADER_TIME()
AC_HEADER_STAT()
AC_HEADER_SYS_WAIT()
AC_HEADER_MAJOR()

has_uni_h=yes
AC_CHECK_HEADER([unistd.h],AC_DEFINE([HAVE_UNISTD_H],[1],
	[Whether you have the unistd.h header.]),[has_uni_h=no])

AC_CHECK_HEADERS([sys/param.h mntent.h stdarg.h sys/types.h])

has_sys_wait_h=yes
AC_CHECK_HEADER([sys/wait.h],AC_DEFINE([HAVE_SYS_WAIT_H],[1],
	[Whether you have the sys/wait.h header.]),[AC_CHECK_HEADER([wait.h],
		AC_DEFINE([HAVE_WAIT_H],[1],
		[Whether you have the wait.h header.]),[has_wait_h=no])])

AC_CHECK_HEADERS([sys/mount.h],,,
		[[#ifdef HAVE_SYS_PARAM_H
	  	  # include <sys/param.h>
		  #endif
		  ]]
		  )

has_ext234_h=no
if ( test "x$feat_ext234" = "xyes" ); then

	if (test "x$libext234" = "xyes"); then

		has_ext234_h=yes
		AC_CHECK_HEADER([ext2fs/ext2fs.h],
			AC_DEFINE([HAVE_EXT2FS_EXT2FS_H],[1],[Whether you have the ext2fs/ext2fs.h header.]),
			[AC_CHECK_HEADER([ext2fs.h],
				AC_DEFINE([HAVE_EXT2FS_H],[1],[Whether you have the ext2fs.h header.]),
				has_ext234_h=no)]
			)
	fi
fi

if ( test "x$feat_xfs" = "xyes" ); then

	AC_CHECK_PROG([XFS_DB], [xfs_db], [yes], [no])
fi

have_ll=yes
AC_CHECK_TYPE([long long],AC_DEFINE([HAVE_LONG_LONG],[1],[Whether you have the long long type.]),
	[have_ll=no])

if ( test "x$feat_xfs" = "xyes" ); then

	if (test "x$have_ll" != "xyes" && test "x$XFS_DB" = "xyes" ); then

		AC_MSG_WARN([[XFS support impossible without the long long type.]])
	fi
fi

has_ntfs_h=no
if ( test "x$feat_ntfs" = "xyes" ); then

	if (test "x$have_ll" != "xyes" && test "x$libntfs" = "xyes"); then

		AC_MSG_WARN([[NTFS support impossible without the long long type.]])

	elif (test "x$have_ll" = "xyes" && test "x$libntfs" = "xyes"); then

		has_ntfs_h=yes
		AC_CHECK_HEADER([ntfs/ntfs_volume.h],
				AC_DEFINE([HAVE_NTFS_NTFS_VOLUME_H],[1],
					[Whether you have the ntfs/ntfs_volume.h header.]),
				[AC_CHECK_HEADER([ntfs/volume.h],
					AC_DEFINE([HAVE_NTFS_VOLUME_H],[1],
						[Whether you have the ntfs/volume.h header.]),
					[AC_CHECK_HEADER([volume.h],
						AC_DEFINE([HAVE_VOLUME_H],[1],
							[Whether you have the volume.h header.]),
						has_ntfs_h=no,
					[[#ifdef HAVE_STDARG_H
			  		  # include <stdarg.h>
					  #endif
					  ]]
					  )],
				[[#ifdef HAVE_STDARG_H
			  	  # include <stdarg.h>
				  #endif
				  ]]
				  )],
			[[#ifdef HAVE_STDARG_H
		  	  # include <stdarg.h>
			  #endif
			  ]]
			 )
	fi
fi

has_reiser_h=no
if ( test "x$feat_reiser" = "xyes" ); then

	if (test "x$have_ll" != "xyes" && test "x$libcore" = "xyes"); then

		AC_MSG_WARN([[ReiserFS support impossible without the long long type.]])

	elif (	   test "x$have_ll" = "xyes" 	\
		&& test "x$libcore" = "xyes"	\
		); then

		has_reiser_h=yes
		AC_CHECK_HEADER([reiserfs_lib.h],
			AC_DEFINE([HAVE_REISERFS_LIB_H],[1],
				[Whether you have the reiserfs_lib.h header.]),
			[has_reiser_h=no],[[#include <misc.h>]])
	fi
fi

has_libreiser4_h=no
if ( test "x$feat_reiser4" = "xyes" ); then

	if (test "x$have_ll" != "xyes" && test "x$libreiser4" = "xyes"); then

		AC_MSG_WARN([[Reiser4 support impossible without the long long type.]])

	elif (	   test "x$have_ll" = "xyes" 	\
		&& test "x$libreiser4" = "xyes"	\
		); then

		has_libreiser4_h=yes
		AC_CHECK_HEADER([reiser4/libreiser4.h],
			AC_DEFINE([HAVE_REISER4_LIBREISER4_H],[1],
				[Whether you have the libreiser4.h header.]),
			[has_libreiser4_h=no])
	fi
fi

wfs_have_reiser4=no
if (	   test "x$has_libreiser4_h"	= "xyes"	\
	&& test "x$libreiser4"		= "xyes"	\
	&& test "x$feat_reiser4"	= "xyes"	\
	&& test "x$have_ll"		= "xyes" ); then

	wfs_have_reiser4=yes
fi

AM_CONDITIONAL(REISER4, [test "x$wfs_have_reiser4" = "xyes"] )


AM_CONDITIONAL(EXT234FS, \
	[  test "x$has_ext234_h" = "xyes"	\
	&& test "x$libext234"	= "xyes"	\
	&& test "x$feat_ext234"	= "xyes"] )

AM_CONDITIONAL(NTFS, \
	[  test "x$has_ntfs_h"	= "xyes"	\
	&& test "x$libntfs"	= "xyes"	\
	&& test "x$feat_ntfs"	= "xyes"] )

has_com_h=yes
AC_CHECK_HEADER([et/com_err.h],
	AC_DEFINE([HAVE_ET_COM_ERR_H],[1],[Whether you have the et/com_err.h header.]),
	[AC_CHECK_HEADER([com_err.h],
		AC_DEFINE([HAVE_COM_ERR_H],[1],[Whether you have the com_err.h header.]),
		[has_com_h=no])]
)

AM_CONDITIONAL(COMERR, \
	[  test "x$has_com_h"	= "xyes"	\
	&& test "x$libcomm"	= "xyes"])

AC_CHECK_HEADERS([locale.h stdlib.h string.h errno.h signal.h malloc.h \
	libgen.h limits.h paths.h sys/select.h sched.h asm/types.h \
	sys/sysmacros.h sys/mkdev.h hdreg.h linux/hdreg.h])

if ( test "x$feat_xfs" = "xyes" ); then

	if (       test "x$have_ll"	 = "xyes"	\
		&& test "x$has_uni_h"	!= "xyes"	\
		&& test "x$XFS_DB"	 = "xyes"
		 ); then

		AC_MSG_WARN([[XFS support impossible without the unistd.h header with its functions.]])
	fi
fi

has_cap_h=yes
AC_CHECK_HEADER([sys/capability.h],
	AC_DEFINE([HAVE_SYS_CAPABILITY_H],[1],[Whether you have the sys/capability.h header.]),
	[has_cap_h=no])

has_fcntl_h=yes
AC_CHECK_HEADER([fcntl.h],
	AC_DEFINE([HAVE_FCNTL_H],[1],[Whether you have the fcntl.h header.]),
	[has_fcntl_h=no])

AM_CONDITIONAL(SYSCAP, \
	[  test "x$has_cap_h"	= "xyes"	\
	&& test "x$libcap"	= "xyes"] )

AC_CHECK_DECLS([environ],,,
	[
	#ifndef _GNU_SOURCE
	# define _GNU_SOURCE	1
	#endif
	#ifdef HAVE_UNISTD_H
	# include <unistd.h>
	#endif
	])

AC_CHECK_DECLS([__environ],,,
	[
	#ifdef HAVE_UNISTD_H
	# include <unistd.h>
	#endif
	])

# ===================== Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_C_VOLATILE
AC_CHECK_TYPES([size_t, ssize_t])
AC_CHECK_TYPES([off64_t],,,
	[
	#define _FILE_OFFSET_BITS 64
	#define _LARGEFILE64_SOURCE
	#ifdef HAVE_SYS_TYPES_H
	# include <sys/types.h>
	#endif
	])
AC_CHECK_TYPES([sig_atomic_t],,,
	[
	#ifdef HAVE_SIGNAL_H
	# include <signal.h>
	#endif
	])

# Checks for library functions.
AC_FUNC_MALLOC
AC_TYPE_SIGNAL

AC_CHECK_FUNCS([memset memcpy setlocale strtoul random srandom clearenv \
	getuid geteuid snprintf daemon sigaction access sleep getpid \
	hasmntopt getmntent getmntent_r sched_yield sync fsync select ioctl])

has_execvp=no
has_kill=no
if ( test "x$feat_xfs" = "xyes" ); then

	has_execvp=yes
	has_kill=yes
	AC_CHECK_FUNC([execvp],
		AC_DEFINE([HAVE_EXECVP],[1],[Whether you have the execvp function.]),
		[has_execvp=no])
	AC_CHECK_FUNC([kill],
		AC_DEFINE([HAVE_KILL],[1],[Whether you have the kill function.]),
		[has_kill=no])
fi

has_getopt=yes
AC_CHECK_FUNC([getopt_long],
	AC_DEFINE([HAVE_GETOPT_LONG],[1],[Whether you have the getopt_long function.]),
	[has_getopt=no
	AC_MSG_ERROR([[I need the getopt_long() function.]])])

has_malloc=yes
AC_CHECK_FUNC([malloc],
	AC_DEFINE([HAVE_MALLOC],[1],[Whether you have the malloc function.]),
	[has_malloc=no])

has_fork=yes
AC_CHECK_FUNC([fork],
	AC_DEFINE([HAVE_FORK],[1],[Whether you have the fork function.]),
	[has_fork=no])

has_dup2=yes
AC_CHECK_FUNC([dup2],
	AC_DEFINE([HAVE_DUP2],[1],[Whether you have the dup2 function.]),
	[has_dup2=no])

has_close=yes
AC_CHECK_FUNC([close],
	AC_DEFINE([HAVE_CLOSE],[1],[Whether you have the close function.]),
	[has_close=no])

has_pipe=yes
AC_CHECK_FUNC([pipe],
	AC_DEFINE([HAVE_PIPE],[1],[Whether you have the pipe function.]),
	[has_pipe=no])

has_wait=yes
AC_CHECK_FUNC([wait],
	AC_DEFINE([HAVE_WAIT],[1],[Whether you have the wait function.]),
	[has_wait=no])

has_waitpid=yes
AC_CHECK_FUNC([waitpid],
	AC_DEFINE([HAVE_WAITPID],[1],[Whether you have the waitpid function.]),
	[has_waitpid=no])



if (test "x$has_malloc" != "xyes"); then

	AC_MSG_ERROR([[I need the malloc() function.]])
fi

if ( \
	   test "x$have_ll"  = "xyes"	\
	&& test "x$has_uni_h" = "xyes"	\
	&& test "x$has_fcntl_h"  = "xyes"	\
	&& test "x$has_fork"       = "xyes"	\
	&& test "x$has_execvp"     = "xyes"	\
	&& test "x$has_dup2"       = "xyes"	\
	&& test "x$has_close"      = "xyes"	\
	&& test "x$has_pipe"       = "xyes"	\
	&& (  test "x$has_waitpid" = "xyes"	\
	   || test "x$has_wait"    = "xyes" )	\
	&& test "x$has_kill"       = "xyes"	\
	&& test "x$XFS_DB" = "xyes"		\
	); then

	wfs_have_xfs=yes;
else
	wfs_have_xfs=no;
fi

AM_CONDITIONAL(XFS, [test "x$wfs_have_xfs"  = "xyes" && test "x$feat_xfs" = "xyes"])

wfs_have_reiserfs=no
if (	   test "x$have_ll"		= "xyes"	\
	&& test "x$has_reiser_h"	= "xyes"	\
	&& test "x$has_uni_h"		= "xyes"	\
	&& test "x$has_fork"		= "xyes"	\
	&& test "x$libcore"		= "xyes"	\
	&& (  test "x$has_waitpid"	= "xyes"	\
	   || test "x$has_wait"		= "xyes"	\
	   )						\
	&& test "x$has_sys_wait_h"	= "xyes"	\
	&& test "x$feat_reiser"		= "xyes"); then

	wfs_have_reiserfs=yes
fi

AM_CONDITIONAL(REISERFS, [ test "x$wfs_have_reiserfs" = "xyes" ])

if  (  test "x$has_ext234_h"		!= "xyes"	\
    && test "x$has_ntfs_h"		!= "xyes"	\
    && test "x$wfs_have_xfs"		!= "xyes"	\
    && test "x$has_reiser_h"		!= "xyes"	\
    && test "x$has_libreiser4_h"	!= "xyes"
    ); then
	AC_MSG_ERROR([[I need at least one of the filesystem headers with its required data types (if any).]])
fi

AM_GNU_GETTEXT_VERSION([0.14.3])
AM_GNU_GETTEXT([external])

# Can be /usr/local/include/libintl.h. Use --with-libintl-prefix=DIR then.
# The macros above set the correct CFLAGS if this option is given.

AC_CHECK_HEADERS([libintl.h])

if (test "x$GCC" = "xyes" ); then

	AX_C_CHECK_FLAG([-Wall], [CFLAGS="$CFLAGS -Wall"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wextra], [CFLAGS="$CFLAGS -Wextra"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-W], [CFLAGS="$CFLAGS -W"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wfloat-equal], [CFLAGS="$CFLAGS -Wfloat-equal"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wbad-function-cast], [CFLAGS="$CFLAGS -Wbad-function-cast"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wsign-compare], [CFLAGS="$CFLAGS -Wsign-compare"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wunreachable-code], [CFLAGS="$CFLAGS -Wunreachable-code"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wpointer-arith], [CFLAGS="$CFLAGS -Wpointer-arith"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wcast-qual], [CFLAGS="$CFLAGS -Wcast-qual"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wcast-align], [CFLAGS="$CFLAGS -Wcast-align"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wstrict-prototypes], [CFLAGS="$CFLAGS -Wstrict-prototypes"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wformat -Wformat-security], [CFLAGS="$CFLAGS -Wformat -Wformat-security"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wformat -Wformat-nonliteral], [CFLAGS="$CFLAGS -Wformat -Wformat-nonliteral"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wnested-externs], [CFLAGS="$CFLAGS -Wnested-externs"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wshadow], [CFLAGS="$CFLAGS -Wshadow"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wconversion], [CFLAGS="$CFLAGS -Wconversion"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wdeclaration-after-statement], [CFLAGS="$CFLAGS -Wdeclaration-after-statement"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wundef], [CFLAGS="$CFLAGS -Wundef"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wpadded], [CFLAGS="$CFLAGS -Wpadded"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wredundant-decls], [CFLAGS="$CFLAGS -Wredundant-decls"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wfatal-errors], [CFLAGS="$CFLAGS -Wfatal-errors"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-pedantic], [CFLAGS="$CFLAGS -pedantic"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wno-strict-aliasing], [CFLAGS="$CFLAGS -Wno-strict-aliasing"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wmissing-prototypes], [CFLAGS="$CFLAGS -Wmissing-prototypes"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wmissing-declarations], [CFLAGS="$CFLAGS -Wmissing-declarations"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-O1 -Wuninitialized], [CFLAGS="$CFLAGS -O1 -Wuninitialized"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Winit-self], [CFLAGS="$CFLAGS -Winit-self"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wlogical-op], [CFLAGS="$CFLAGS -Wlogical-op"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-fstack-protector-all], [CFLAGS="$CFLAGS -fstack-protector-all"], [CFLAGS="$CFLAGS"])

	if (test "x$have_ll" = "xyes"); then

		AX_C_CHECK_FLAG([-std=gnu99], [CFLAGS="$CFLAGS -std=gnu99"], [CFLAGS="$CFLAGS"])
		AX_C_CHECK_FLAG([-Wno-long-long], [CFLAGS="$CFLAGS -Wno-long-long"], [CFLAGS="$CFLAGS"])
	fi
fi

# Required if both ReiserFSv3+ and REiserFSv4 are enabled, because the same symbols
# appear in multiple places.
if ( test "x$wfs_have_reiserfs" = "xyes" && test "x$wfs_have_reiser4" = "xyes"); then

	AX_C_CHECK_FLAG([-Wl,-z -Wl,muldefs], [CFLAGS="$CFLAGS -Wl,-z -Wl,muldefs"], [CFLAGS="$CFLAGS"])
fi

AC_SUBST(AM_CFLAGS,$CFLAGS)

# =====================

AC_OUTPUT

# ===================== Print summary

echo "***********************************"
if (       test "x$has_ext234_h"	= "xyes"	\
	&& test "x$libext234"		= "xyes"); then

	echo " *	Ext2/3/4: yes"
else
	if (test "x$feat_ext234" != "xyes"); then
		echo " *	Ext2/3/4: no (disabled by command line)"
	elif (test "x$libext234" != "xyes"); then
		echo " *	Ext2/3/4: no (library missing or unusable)"
	else
		echo " *	Ext2/3/4: no (headers missing)"
	fi
fi

if (       test "x$has_ntfs_h"	= "xyes"	\
	&& test "x$libntfs"	= "xyes"); then

		echo " *	NTFS: yes"
else
	if (test "x$feat_ntfs" != "xyes"); then
		echo " *	NTFS: no (disabled by command line)"
	elif (test "x$libntfs" != "xyes"); then
		echo " *	NTFS: no (library missing or unusable)"
	else
		echo " *	NTFS: no (headers missing)"
	fi
fi

if ( test "x$wfs_have_xfs"  = "xyes" ); then

	echo " *	XFS: yes"
else
	if (test "x$feat_xfs" != "xyes"); then
		echo " *	XFS: no (disabled by command line)"

	elif (test "x$have_ll" != "xyes"); then
		echo " *	XFS: no (long long type missing)"

	elif (test "x$has_uni_h" != "xyes"); then
		echo " *	XFS: no (unistd.h missing)"

	elif (test "x$has_fcntl_h" != "xyes"); then
		echo " *	XFS: no (fcntl.h missing)"

	elif (test "x$has_fork" != "xyes"); then
		echo " *	XFS: no (fork() missing)"

	elif (test "x$has_execvp" != "xyes"); then
		echo " *	XFS: no (execvp() missing)"

	elif (test "x$has_dup2" != "xyes"); then
		echo " *	XFS: no (dup2() missing)"

	elif (test "x$has_close" != "xyes"); then
		echo " *	XFS: no (close() missing)"

	elif (test "x$has_pipe" != "xyes"); then
		echo " *	XFS: no (pipe() missing)"

	elif (test "x$XFS_DB" != "xyes"	); then
		echo " *	XFS: no (xfs_db program missing)"

	elif (test "x$has_kill" != "xyes"); then
		echo " *	XFS: no (kill() missing)"

	else
		echo " *	XFS: no (waitpid() and wait() both missing)"
	fi
fi

if (	   test "x$have_ll"		= "xyes"	\
	&& test "x$has_reiser_h"	= "xyes"	\
	&& test "x$libcore"		= "xyes"); then

	echo " *	ReiserFS: yes"
else
	if (test "x$feat_reiser" != "xyes"); then
		echo " *	ReiserFS: no (disabled by command line)"

	elif (test "x$have_ll" != "xyes"); then
		echo " *	ReiserFS: no (long long type missing)"

	elif ( test "x$has_reiser_h"  != "xyes" ); then
		echo " *	ReiserFS: no (reiserfs_lib.h header missing)"

	elif (test "x$has_uni_h" != "xyes"); then
		echo " *	ReiserFS: no (unistd.h missing)"

	elif (test "x$has_sys_wait_h" != "xyes"); then
		echo " *	ReiserFS: no (wait.h & sys/wait.h missing)"

	elif (test "x$has_fork" != "xyes"); then
		echo " *	ReiserFS: no (fork() missing)"

	elif (test "x$libcore" != "xyes"); then
		echo " *	ReiserFS: no (library missing or unusable)"
	else
		echo " *	ReiserFS: no (waitpid() and wait() missing)"
	fi
fi

if (	   test "x$has_libreiser4_h"	= "xyes"	\
	&& test "x$libreiser4"		= "xyes"	\
	&& test "x$feat_reiser4"	= "xyes"	\
	&& test "x$have_ll"		= "xyes"); then

	echo " *	Reiser4: yes"
else
	if (test "x$feat_reiser4" != "xyes"); then
		echo " *	Reiser4: no (disabled by command line)"

	elif (test "x$have_ll" != "xyes"); then
		echo " *	Reiser4: no (long long type missing)"

	elif ( test "x$has_libreiser4_h"  != "xyes" ); then
		echo " *	Reiser4: no (libreiser4.h header missing)"

	else	#if (test "x$libreiser4" != "xyes"); then
		echo " *	Reiser4: no (library missing or unusable)"
	fi
fi

echo "***********************************"

