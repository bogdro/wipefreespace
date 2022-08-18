#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(wipefreespace, 0.6, bogdandr@op.pl)
AM_INIT_AUTOMAKE
AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile po/Makefile.in po/Makefile])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])

# ==================== Set of available languages (deprecated).
#ALL_LINGUAS="pl"

# ==================== Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB
AM_CONDITIONAL(ISGCC, test $GCC == yes)

# ==================== Checks for libraries.
AC_CHECK_LIB(com_err,com_err)
AC_CHECK_LIB(ext2fs,ext2fs_open)
AC_CHECK_LIB(cap,cap_init)
AC_CHECK_LIB(ntfs,ntfs_pwrite)

# ==================== Checks for header files.
AC_HEADER_STDC
#AC_CHECK_HEADER(getopt.h, [AC_DEFINE(HAVE_GETOPT_H)], [AC_MSG_ERROR("I need getopt.h to work!")])

AC_CHECK_HEADERS([getopt.h])

if test "$ac_cv_header_getopt_h" != yes; then
	AC_MSG_ERROR("I need the getopt.h to work.")
fi

AC_CHECK_HEADERS([sys/param.h sys/mount.h mntent.h stdarg.h])
AC_CHECK_HEADERS([ext2fs/ext2fs.h ext2fs.h])
AC_CHECK_TYPES([long long])
if test "$ac_cv_type_long_long" == yes; then
	AC_CHECK_HEADERS([ntfs/volume.h volume.h],,,
		[[#ifdef HAVE_STDARG_H
	  	  # include <stdarg.h>
		  #endif]])
else
	AC_MSG_WARN("NTFS support impossible without the long long type.")
fi

if (test "$ac_cv_header_ext2fs_ext2fs_h" != yes && \
    test "$ac_cv_header_ext2fs_h" != yes &&        \
    test "$ac_cv_header_ntfs_volume_h" != yes &&   \
    test "$ac_cv_header_volume_h" != yes    ); then
	AC_MSG_ERROR("I need at least one of the filesystem headers.")
fi

AM_CONDITIONAL(EXT2FS, \
	(test "$ac_cv_header_ext2fs_ext2fs_h" == yes || \
	test "$ac_cv_header_ext2fs_h" == yes) &&\
	test "$ac_cv_lib_ext2fs_ext2fs_open" == yes)
AM_CONDITIONAL(NTFS, \
	(test "$ac_cv_header_ntfs_volume_h" == yes || \
	test "$ac_cv_header_volume_h" == yes) &&\
	test "$ac_cv_lib_ntfs_ntfs_pwrite" == yes)

AC_CHECK_HEADERS([libintl.h stdlib.h string.h unistd.h errno.h signal.h malloc.h\
	time.h sys/stat.h sys/types.h sys/capability.h et/com_err.h com_err.h\
	])

AM_CONDITIONAL(SYSCAP, \
	test "$ac_cv_header_sys_capability_h" == yes && \
	test "$ac_cv_lib_cap_cap_init" == yes)
AM_CONDITIONAL(COMERR, \
	(test "$ac_cv_header_et_com_err_h" == yes || \
	test "$ac_cv_header_com_err_h" == yes) && \
	test "$ac_cv_lib_com_err_com_err" == yes)


# ===================== Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_C_VOLATILE
AC_CHECK_TYPES([dev_t, size_t])

# Checks for library functions.
AC_FUNC_MALLOC
AC_TYPE_SIGNAL

if test $ac_cv_type_signal != void; then
	AC_DEFINE([RETSIG_ISINT],[1], [Is return type of signal equal to int])
fi

AC_CHECK_FUNCS([memset memcpy setlocale strtoul getopt_long random srandom\
	clearenv getuid geteuid snprintf])

if test "$ac_cv_func_getopt_long" != yes; then
	AC_MSG_ERROR("I need the getopt_long() function.")
fi


#AM_GNU_GETTEXT
AM_GNU_GETTEXT_VERSION([0.14.3])
AM_GNU_GETTEXT([external])
AC_OUTPUT

