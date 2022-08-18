#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(wipefreespace, 0.8, bogdandr@op.pl)
AM_INIT_AUTOMAKE
AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile po/Makefile.in po/Makefile])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])

# ==================== configure arguments

AC_ARG_ENABLE(EXT23,[[  --enable-EXT23	Ext2/3 support (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_ext23=no
	 else
		feat_ext23=yes
	 fi
	]
	,feat_ext23=yes)
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
AC_ARG_ENABLE(REISERFS,[[  --enable-REISERFS	ReiserFSv3 support (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_reiser=no
	 else
		feat_reiser=yes
	 fi
	]
	,feat_reiser=yes)

# ==================== Set of available languages (deprecated).
#ALL_LINGUAS="pl"

# ==================== Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB
AM_CONDITIONAL(ISGCC, test "x$GCC" = "xyes")

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

AC_CHECK_LIB(com_err,com_err)

if ( test "x$feat_ext23" = "xyes" ); then

	AC_CHECK_LIB(ext2fs,ext2fs_open)
fi

AC_CHECK_LIB(cap,cap_init)

if ( test "x$feat_ntfs" = "xyes" ); then

	AC_CHECK_LIB(ntfs,ntfs_pwrite)
fi

#AC_CHECK_LIB(pthread,pthread_create)

if ( test "x$feat_reiser" = "xyes" ); then

	AC_CHECK_LIB(uuid,uuid_unparse)
	if test "x$ac_cv_lib_uuid_uuid_unparse" = xyes; then

		AC_CHECK_LIB(misc,misc_test_bit,,,-luuid)
		AC_CHECK_LIB(core,reiserfs_open,,,-lmisc -luuid)
	else
		AC_MSG_WARN([[ReiserFS support impossible without the uuid library.]])
	fi
fi

# ==================== Checks for header files.
AC_HEADER_STDC
#AC_CHECK_HEADER(getopt.h, [AC_DEFINE(HAVE_GETOPT_H)], [AC_MSG_ERROR([[I need getopt.h to work!]])])

AC_CHECK_HEADERS([getopt.h])

if (test "x$ac_cv_header_getopt_h" != "xyes"); then

	AC_MSG_ERROR([[I need getopt.h to work.]])
fi

AC_HEADER_TIME()
AC_HEADER_STAT()
AC_HEADER_SYS_WAIT()
AC_HEADER_MAJOR()

AC_CHECK_HEADERS([sys/param.h mntent.h stdarg.h sys/types.h unistd.h sys/wait.h wait.h])

AC_CHECK_HEADERS([sys/mount.h],,,
		[[#ifdef HAVE_SYS_PARAM_H
	  	  # include <sys/param.h>
		  #endif]])


if ( test "x$feat_ext23" = "xyes" ); then

	if (test "x$ac_cv_lib_ext2fs_ext2fs_open" = "xyes"); then

		AC_CHECK_HEADERS([ext2fs/ext2fs.h])
		if (test "x$ac_cv_header_ext2fs_ext2fs_h" != "xyes"); then
			AC_CHECK_HEADERS([ext2fs.h])
		fi
	fi
fi

if ( test "x$feat_xfs" = "xyes" ); then

	AC_CHECK_PROG([XFS_DB], [xfs_db], [yes], [no])
fi

AC_CHECK_TYPES([long long])

if ( test "x$feat_xfs" = "xyes" ); then

	if (test "x$ac_cv_type_long_long" != "xyes" && test "x$XFS_DB" = "xyes" ); then

		AC_MSG_WARN([[XFS support impossible without the long long type.]])
	fi
fi

if ( test "x$feat_ntfs" = "xyes" ); then

	if (test "x$ac_cv_type_long_long" != "xyes" && test "x$ac_cv_lib_ntfs_ntfs_pwrite" = "xyes"); then

		AC_MSG_WARN([[NTFS support impossible without the long long type.]])

	elif (test "x$ac_cv_type_long_long" = "xyes" && test "x$ac_cv_lib_ntfs_ntfs_pwrite" = "xyes"); then

		AC_CHECK_HEADERS([ntfs/ntfs_volume.h],,,
			[[#ifdef HAVE_STDARG_H
		  	  # include <stdarg.h>
			  #endif]])

		if (test "x$ac_cv_header_ntfs_ntfs_volume_h" != "xyes"); then

			AC_CHECK_HEADERS([ntfs/volume.h],,,
				[[#ifdef HAVE_STDARG_H
			  	  # include <stdarg.h>
				  #endif]])

			if (test "x$ac_cv_header_ntfs_volume_h" != "xyes"); then

				AC_CHECK_HEADERS([volume.h],,,
					[[#ifdef HAVE_STDARG_H
			  		  # include <stdarg.h>
					  #endif]])
			fi
		fi
	fi
fi

if ( test "x$feat_reiser" = "xyes" ); then

	if (test "x$ac_cv_type_long_long" != "xyes" && test "x$ac_cv_lib_core_reiserfs_open" = "xyes"); then

		AC_MSG_WARN([[ReiserFS support impossible without the long long type.]])

	elif (test "x$ac_cv_type_long_long" = "xyes" 			\
		&& test "x$ac_cv_lib_core_reiserfs_open" = "xyes"	\
		); then

		AC_CHECK_HEADERS([reiserfs_lib.h],,,[[#include <misc.h>]])
	fi
fi

AM_CONDITIONAL(EXT2FS, \
	(  test "x$ac_cv_header_ext2fs_ext2fs_h" = "xyes"	\
	|| test "x$ac_cv_header_ext2fs_h"	 = "xyes")	\
	&& test "x$ac_cv_lib_ext2fs_ext2fs_open" = "xyes"	\
	&& test "x$feat_ext23"			 = "xyes" )

AM_CONDITIONAL(NTFS, \
	(  test "x$ac_cv_header_ntfs_volume_h"	= "xyes"	\
	|| test "x$ac_cv_header_volume_h"	= "xyes")	\
	&& test "x$ac_cv_lib_ntfs_ntfs_pwrite"	= "xyes"	\
	&& test "x$feat_ntfs"			= "xyes")

AC_CHECK_HEADERS([et/com_err.h])
if (test "x$ac_cv_header_et_com_err_h" != "xyes"); then
	AC_CHECK_HEADERS([com_err.h])
fi

AM_CONDITIONAL(COMERR, \
	(  test "x$ac_cv_header_et_com_err_h" = "xyes"	\
	|| test "x$ac_cv_header_com_err_h"    = "xyes")	\
	&& test "x$ac_cv_lib_com_err_com_err" = "xyes")

AC_CHECK_HEADERS([locale.h stdlib.h string.h errno.h signal.h malloc.h \
	sys/time.h sys/stat.h sys/capability.h libgen.h limits.h fcntl.h paths.h \
	sched.h asm/types.h sys/sysmacros.h sys/mkdev.h])

if ( test "x$feat_xfs" = "xyes" ); then

	if (       test "x$ac_cv_type_long_long"   = "xyes"	\
		&& test "x$ac_cv_header_unistd_h" != "xyes"	\
		&& test "x$XFS_DB" = "xyes"
		 ); then

		AC_MSG_WARN([[XFS support impossible without the unistd.h header with its functions.]])
	fi
fi

AM_CONDITIONAL(SYSCAP, \
	   test "x$ac_cv_header_sys_capability_h" = "xyes"	\
	&& test "x$ac_cv_lib_cap_cap_init"        = "xyes")

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

if (test "x$ac_cv_type_signal" != "xvoid"); then

	AC_DEFINE([RETSIG_ISINT],[1], [Is return type of signal equal to int])
fi

AC_CHECK_FUNCS([memset memcpy malloc setlocale strtoul getopt_long random srandom \
	clearenv getuid geteuid snprintf daemon sigaction access fork dup2 \
	pipe memmove close waitpid wait sleep getpid hasmntopt getmntent_r   \
	sched_yield sync])

if ( test "x$feat_xfs" = "xyes" ); then

	AC_CHECK_FUNCS([execvp kill])
fi

if (test "x$ac_cv_func_getopt_long" != "xyes"); then

	AC_MSG_ERROR([[I need the getopt_long() function.]])
fi

if (test "x$ac_cv_func_malloc" != "xyes"); then

	AC_MSG_ERROR([[I need the malloc() function.]])
fi

if ( \
	   test "x$ac_cv_type_long_long"  = "xyes"	\
	&& test "x$ac_cv_header_unistd_h" = "xyes"	\
	&& test "x$ac_cv_header_fcntl_h"  = "xyes"	\
	&& test "x$ac_cv_func_fork"       = "xyes"	\
	&& test "x$ac_cv_func_execvp"     = "xyes"	\
	&& test "x$ac_cv_func_dup2"       = "xyes"	\
	&& test "x$ac_cv_func_close"      = "xyes"	\
	&& test "x$ac_cv_func_pipe"       = "xyes"	\
	&& (  test "x$ac_cv_func_waitpid" = "xyes"	\
	   || test "x$ac_cv_func_wait"    = "xyes"	\
	   || test "x$ac_cv_func_kill"    = "xyes" )	\
	&& test "x$XFS_DB" = "xyes"			\
	); then

	wfs_have_xfs=yes;
else
	wfs_have_xfs=no;
fi

AM_CONDITIONAL(XFS, test "x$wfs_have_xfs"  = "xyes" && test "x$feat_xfs" = "xyes")

AM_CONDITIONAL(REISERFS, \
	   test "x$ac_cv_type_long_long"         = "xyes"	\
	&& test "x$ac_cv_header_reiserfs_lib_h"  = "xyes"	\
	&& test "x$ac_cv_header_unistd_h"	 = "xyes"	\
	&& test "x$ac_cv_func_fork"		 = "xyes"	\
	&& test "x$ac_cv_lib_core_reiserfs_open" = "xyes"	\
	&& (  test "x$ac_cv_func_waitpid"	 = "xyes"	\
	   || test "x$ac_cv_func_wait"		 = "xyes"	\
	   )							\
	&& (  test "x$ac_cv_header_sys_wait_h"	 = "xyes"	\
	   || test "x$ac_cv_header_wait_h"	 = "xyes"	\
	   )							\
	&& test "x$feat_reiser"			 = "xyes"	\
	)

if (   test "x$ac_cv_header_ext2fs_ext2fs_h" != "xyes"	\
    && test "x$ac_cv_header_ext2fs_h"        != "xyes"	\
    && test "x$ac_cv_header_ntfs_volume_h"   != "xyes"	\
    && test "x$ac_cv_header_volume_h"        != "xyes"	\
    && test "x$wfs_have_xfs"                 != "xyes"	\
#    && test "x$ac_cv_header_reiserfs_lib_h" != "xyes"
    ); then
	AC_MSG_ERROR([[I need at least one of the filesystem headers with its required data types (if any).]])
fi

AM_GNU_GETTEXT_VERSION([0.14.3])
AM_GNU_GETTEXT([external])

# Can be /usr/local/include/libintl.h. Use --with-libintl-prefix=DIR then.
# The macros above set the correct CFLAGS if this option is given.

AC_CHECK_HEADERS([libintl.h])

if (test "x$ac_cv_c_compiler_gnu" = "xyes"); then

	AX_GCC_OPTION(CFLAGS, [[-Wall]], "$CFLAGS -Wall", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wextra]], "$CFLAGS -Wextra", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-W]], "$CFLAGS -W", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wfloat-equal]], "$CFLAGS -Wfloat-equal", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wbad-function-cast]], "$CFLAGS -Wbad-function-cast", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wsign-compare]], "$CFLAGS -Wsign-compare", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wunreachable-code]], "$CFLAGS -Wunreachable-code", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wpointer-arith]], "$CFLAGS -Wpointer-arith", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wcast-qual]], "$CFLAGS -Wcast-qual", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wcast-align]], "$CFLAGS -Wcast-align", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wstrict-prototypes]], "$CFLAGS -Wstrict-prototypes", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wformat -Wformat-security]], "$CFLAGS -Wformat -Wformat-security", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wformat -Wformat-nonliteral]], "$CFLAGS -Wformat -Wformat-nonliteral", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wnested-externs]], "$CFLAGS -Wnested-externs", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wshadow]], "$CFLAGS -Wshadow", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wconversion]], "$CFLAGS -Wconversion", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wdeclaration-after-statement]], "$CFLAGS -Wdeclaration-after-statement", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wundef]], "$CFLAGS -Wundef", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wpadded]], "$CFLAGS -Wpadded", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wredundant-decls]], "$CFLAGS -Wredundant-decls", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wfatal-errors]], "$CFLAGS -Wfatal-errors", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-pedantic]], "$CFLAGS -pedantic", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wno-strict-aliasing]], "$CFLAGS -Wno-strict-aliasing", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wmissing-prototypes]], "$CFLAGS -Wmissing-prototypes", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wmissing-declarations]], "$CFLAGS -Wmissing-declarations", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-ffortify-source]], "$CFLAGS -ffortify-source", "$CFLAGS")

	if (test "x$ac_cv_type_long_long" = "xyes"); then

		AX_GCC_OPTION(CFLAGS, [[-std=gnu99]], "$CFLAGS -std=gnu99", "$CFLAGS")
	fi
fi

AC_SUBST(AM_CFLAGS,$CFLAGS)

# =====================

AC_OUTPUT

# ===================== Print summary

echo "***********************************"
if (    (  test "x$ac_cv_header_ext2fs_ext2fs_h" = "xyes"	\
	|| test "x$ac_cv_header_ext2fs_h"        = "xyes")	\
	&& test "x$ac_cv_lib_ext2fs_ext2fs_open" = "xyes"); then

	echo " *	Ext2/3: yes"
else
	if (test "x$feat_ext23" != "xyes"); then
		echo " *	Ext2/3: no (disabled by command line)"
	elif (test "x$ac_cv_lib_ext2fs_ext2fs_open" != "xyes"); then
		echo " *	Ext2/3: no (libext2fs missing)"
	else
		echo " *	Ext2/3: no (headers missing)"
	fi
fi

if (   (   test "x$ac_cv_header_ntfs_volume_h" = "xyes"		\
	|| test "x$ac_cv_header_volume_h"      = "xyes")	\
	&& test "x$ac_cv_lib_ntfs_ntfs_pwrite" = "xyes"); then

		echo " *	NTFS: yes"
else
	if (test "x$feat_ntfs" != "xyes"); then
		echo " *	NTFS: no (disabled by command line)"
	elif (test "x$ac_cv_lib_ntfs_ntfs_pwrite" != "xyes"); then
		echo " *	NTFS: no (library missing)"
	else
		echo " *	NTFS: no (headers missing)"
	fi
fi

if ( test "x$wfs_have_xfs"  = "xyes" ); then

	echo " *	XFS: yes"
else
	if (test "x$feat_xfs" != "xyes"); then
		echo " *	XFS: no (disabled by command line)"

	elif (test "x$ac_cv_type_long_long" != "xyes"); then
		echo " *	XFS: no (long long type missing)"

	elif (test "x$ac_cv_header_unistd_h" != "xyes"); then
		echo " *	XFS: no (unistd.h missing)"

	elif (test "x$ac_cv_header_fcntl_h" != "xyes"); then
		echo " *	XFS: no (fcntl.h missing)"

	elif (test "x$ac_cv_func_fork" != "xyes"); then
		echo " *	XFS: no (fork() missing)"

	elif (test "x$ac_cv_func_execvp" != "xyes"); then
		echo " *	XFS: no (execvp() missing)"

	elif (test "x$ac_cv_func_dup2" != "xyes"); then
		echo " *	XFS: no (dup2() missing)"

	elif (test "x$ac_cv_func_close" != "xyes"); then
		echo " *	XFS: no (close() missing)"

	elif (test "x$ac_cv_func_pipe" != "xyes"); then
		echo " *	XFS: no (pipe() missing)"

	elif (test "x$XFS_DB" != "xyes"	); then
		echo " *	XFS: no (xfs_db program missing)"

	else
		echo " *	XFS: no (waitpid(), wait() and kill() all missing)"
	fi
fi

if (	   test "x$ac_cv_type_long_long"         = "xyes"	\
	&& test "x$ac_cv_header_reiserfs_lib_h"  = "xyes"	\
	&& test "x$ac_cv_lib_core_reiserfs_open" = "xyes"); then

	echo " *	ReiserFS: yes"
else
	if (test "x$feat_reiser" != "xyes"); then
		echo " *	ReiserFS: no (disabled by command line)"

	elif (test "x$ac_cv_type_long_long" != "xyes"); then
		echo " *	ReiserFS: no (long long type missing)"

	elif ( test "x$ac_cv_header_reiserfs_lib_h"  != "xyes" ); then
		echo " *	ReiserFS: no (reiserfs_lib.h header missing)"

	elif (test "x$ac_cv_header_unistd_h" != "xyes"); then
		echo " *	ReiserFS: no (unistd.h missing)"

	elif (test "x$ac_cv_header_sys_wait_h" != "xyes"	\
		&& test "x$ac_cv_header_wait_h" != "xyes"	\
		); then
		echo " *	ReiserFS: no (wait.h & sys/wait.h missing)"

	elif (test "x$ac_cv_header_unistd_h" != "xyes"); then
		echo " *	ReiserFS: no (unistd.h missing)"

	elif (test "x$ac_cv_func_fork" != "xyes"); then
		echo " *	ReiserFS: no (fork() missing)"

	elif (test "x$ac_cv_lib_core_reiserfs_open" != "xyes"); then
		echo " *	ReiserFS: no (library missing)"
	else
		echo " *	ReiserFS: no (waitpid() and wait() missing)"
	fi
fi

echo "***********************************"

