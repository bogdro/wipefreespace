#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(wipefreespace, 0.7, bogdandr@op.pl)
AM_INIT_AUTOMAKE
AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile po/Makefile.in po/Makefile])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])

# ==================== Set of available languages (deprecated).
#ALL_LINGUAS="pl"

# ==================== Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB
AM_CONDITIONAL(ISGCC, test "x$GCC" == xyes)

# ==================== Checks for libraries.
AC_CHECK_LIB(com_err,com_err)
AC_CHECK_LIB(ext2fs,ext2fs_open)
AC_CHECK_LIB(cap,cap_init)
AC_CHECK_LIB(ntfs,ntfs_pwrite)

#AC_CHECK_LIB(pthread,pthread_create)
#AC_CHECK_LIB(uuid,uuid_unparse)
#if test "x$ac_cv_lib_uuid_uuid_unparse" = xyes; then
#	AC_CHECK_LIB(core,reiserfs_open,,,-lmisc -luuid)
#else
#	AC_MSG_WARN("ReiserFS support impossible without the uuid library.")
#fi

# ==================== Checks for header files.
AC_HEADER_STDC
#AC_CHECK_HEADER(getopt.h, [AC_DEFINE(HAVE_GETOPT_H)], [AC_MSG_ERROR("I need getopt.h to work!")])

AC_CHECK_HEADERS([getopt.h])

if test "x$ac_cv_header_getopt_h" != xyes; then
	AC_MSG_ERROR("I need the getopt.h to work.")
fi

AC_CHECK_HEADERS([sys/param.h sys/mount.h mntent.h stdarg.h sys/types.h])

if test "x$ac_cv_lib_ext2fs_ext2fs_open" = xyes; then
	AC_CHECK_HEADERS([ext2fs/ext2fs.h])
	if (test "x$ac_cv_header_ext2fs_ext2fs_h" != xyes ); then
		AC_CHECK_HEADERS([ext2fs.h])
	fi
fi

AC_CHECK_TYPES([long long])

if (test "x$ac_cv_type_long_long" != xyes); then

	AC_MSG_WARN("XFS support impossible without the long long type.")
fi

if (test "x$ac_cv_type_long_long" != xyes && test "x$ac_cv_lib_ntfs_ntfs_pwrite" = xyes); then

	AC_MSG_WARN("NTFS support impossible without the long long type.")

elif (test "x$ac_cv_type_long_long" = xyes && test "x$ac_cv_lib_ntfs_ntfs_pwrite" = xyes); then

	AC_CHECK_HEADERS([ntfs/ntfs_volume.h],,,
		[[#ifdef HAVE_STDARG_H
	  	  # include <stdarg.h>
		  #endif]])

	if (test "x$ac_cv_header_ntfs_ntfs_volume_h" != xyes); then
		AC_CHECK_HEADERS([ntfs/volume.h],,,
			[[#ifdef HAVE_STDARG_H
		  	  # include <stdarg.h>
			  #endif]])

		if (test "x$ac_cv_header_ntfs_volume_h" != xyes); then
			AC_CHECK_HEADERS([volume.h],,,
				[[#ifdef HAVE_STDARG_H
		  		  # include <stdarg.h>
				  #endif]])
		fi
	fi
fi

#if test "x$ac_cv_lib_core_reiserfs_open" = xyes; then
#	AC_CHECK_HEADERS([reiserfs_lib.h],,,
#		[[#include <misc.h>]])
#fi

AM_CONDITIONAL(EXT2FS, \
	(test "x$ac_cv_header_ext2fs_ext2fs_h" = xyes || \
	test "x$ac_cv_header_ext2fs_h" = xyes) &&\
	test "x$ac_cv_lib_ext2fs_ext2fs_open" = xyes)
AM_CONDITIONAL(NTFS, \
	(test "x$ac_cv_header_ntfs_volume_h" = xyes || \
	test "x$ac_cv_header_volume_h" = xyes) &&\
	test "x$ac_cv_lib_ntfs_ntfs_pwrite" = xyes)
#AM_CONDITIONAL(REISERFS, \
#	test "x$ac_cv_header_reiserfs_lib_h" = xyes &&\
#	test "x$ac_cv_lib_core_reiserfs_open" = xyes)

AC_CHECK_HEADERS([et/com_err.h])
if (test "x$ac_cv_header_et_com_err_h" != xyes); then
	AC_CHECK_HEADERS([com_err.h])
fi

AM_CONDITIONAL(COMERR, \
	(test "x$ac_cv_header_et_com_err_h" = xyes || \
	test "x$ac_cv_header_com_err_h" = xyes) && \
	test "x$ac_cv_lib_com_err_com_err" = xyes)

AC_CHECK_HEADERS([libintl.h locale.h stdlib.h string.h unistd.h errno.h signal.h malloc.h \
	time.h sys/stat.h sys/capability.h libgen.h limits.h sys/wait.h fcntl.h paths.h \
	sched.h])

if (test "x$ac_cv_type_long_long" = xyes && test "x$ac_cv_header_unistd_h" != xyes); then

	AC_MSG_WARN("XFS support impossible without the unistd.h header with its functions.")
fi

AM_CONDITIONAL(SYSCAP, \
	test "x$ac_cv_header_sys_capability_h" = xyes && \
	test "x$ac_cv_lib_cap_cap_init" = xyes)

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

if test "x$ac_cv_type_signal" != xvoid; then
	AC_DEFINE([RETSIG_ISINT],[1], [Is return type of signal equal to int])
fi

AC_CHECK_FUNCS([memset memcpy malloc setlocale strtoul getopt_long random srandom \
	clearenv getuid geteuid snprintf daemon sigaction access fork execvp dup2 \
	pipe memmove close waitpid wait sleep kill getpid hasmntopt getmntent_r   \
	sched_yield])

if test "x$ac_cv_func_getopt_long" != xyes; then
	AC_MSG_ERROR("I need the getopt_long() function.")
fi

if test "x$ac_cv_func_malloc" != xyes; then
	AC_MSG_ERROR("I need the malloc() function.")
fi

AM_CONDITIONAL(XFS, \
	test "x$ac_cv_type_long_long" = xyes && \
	test "x$ac_cv_header_unistd_h" = xyes && \
	test "x$ac_cv_header_fcntl_h" = xyes && \
	test "x$ac_cv_func_fork" = xyes && \
	test "x$ac_cv_func_execvp" = xyes && \
	test "x$ac_cv_func_dup2" = xyes && \
	test "x$ac_cv_func_close" = xyes && \
	test "x$ac_cv_func_pipe" = xyes && \
		(test "x$ac_cv_func_waitpid" = xyes || test "x$ac_cv_func_wait" = xyes \
		 || test "x$ac_cv_func_kill" = xyes ) \
	)

if ( \
	test "x$ac_cv_type_long_long" = xyes && \
	test "x$ac_cv_header_unistd_h" = xyes && \
	test "x$ac_cv_header_fcntl_h" = xyes && \
	test "x$ac_cv_func_fork" = xyes && \
	test "x$ac_cv_func_execvp" = xyes && \
	test "x$ac_cv_func_dup2" = xyes && \
	test "x$ac_cv_func_close" = xyes && \
	test "x$ac_cv_func_pipe" = xyes && \
		(test "x$ac_cv_func_waitpid" = xyes || test "x$ac_cv_func_wait" = xyes \
		 || test "x$ac_cv_func_kill" = xyes ) \
	); then
	wfs_have_xfs=yes;
else
	wfs_have_xfs=no;
fi

if (test "x$ac_cv_header_ext2fs_ext2fs_h" != xyes	\
    && test "x$ac_cv_header_ext2fs_h" != xyes		\
    && test "x$ac_cv_header_ntfs_volume_h" != xyes	\
    && test "x$ac_cv_header_volume_h" != xyes		\
    && test "x$wfs_have_xfs" != xyes			\
#    && test "x$ac_cv_header_reiserfs_lib_h" != xyes
    ); then
	AC_MSG_ERROR("I need at least one of the filesystem headers with its required data types (if any).")
fi


#AM_GNU_GETTEXT
AM_GNU_GETTEXT_VERSION([0.14.3])
AM_GNU_GETTEXT([external])
AC_OUTPUT

