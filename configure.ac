#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([wipefreespace],[2.5],[bogdro@users.sourceforge.net])
AM_INIT_AUTOMAKE
AC_CONFIG_FILES([Makefile src/Makefile doc/wipefreespace.texi wipefreespace.spec\
	src/wfs_cfg.h doc/Makefile po/Makefile.in po/Makefile test/Makefile])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

# ==================== configure arguments

AC_ARG_ENABLE(EXT234,[[  --enable-EXT234	Ext2/3/4 support (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_ext234=no
	 else
		feat_ext234=yes
	 fi
	]
	,[feat_ext234=yes])

AC_ARG_ENABLE(NTFS,[[  --enable-NTFS		NTFS support (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_ntfs=no
	 else
		feat_ntfs=yes
	 fi
	]
	,[feat_ntfs=yes])

AC_ARG_ENABLE(XFS,[[  --enable-XFS		XFS support (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_xfs=no
	 else
		feat_xfs=yes
	 fi
	]
	,[feat_xfs=yes])

AC_ARG_ENABLE(REISERFS,[[  --enable-REISERFS	ReiserFSv3 support (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_reiser=no
	 else
		feat_reiser=yes
	 fi
	]
	,[feat_reiser=yes])

AC_ARG_ENABLE(REISER4,[[  --enable-REISER4	ReiserFSv4 support (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_reiser4=no
	 else
		feat_reiser4=yes
	 fi
	]
	,[feat_reiser4=yes])

AC_ARG_ENABLE(FAT,[[  --enable-FAT		FAT12/16/32 support (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_fatfs=no
	 else
		feat_fatfs=yes
	 fi
	]
	,[feat_fatfs=yes])

AC_ARG_ENABLE(MINIX,[[  --enable-MINIX	MinixFSv1/2 support (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_minixfs=no
	 else
		feat_minixfs=yes
	 fi
	]
	,[feat_minixfs=yes])

AC_ARG_ENABLE(JFS,[[  --enable-JFS		JFS support (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_jfs=no
	 else
		feat_jfs=yes
	 fi
	]
	,[feat_jfs=yes])

AC_ARG_ENABLE(HFSP,[[  --enable-HFSP		HFS+ support (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_hfsp=no
	 else
		feat_hfsp=yes
	 fi
	]
	,[feat_hfsp=yes])

AC_ARG_ENABLE(OCFS,[[  --enable-OCFS		OCFS support (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_ocfs=no
	 else
		feat_ocfs=yes
	 fi
	]
	,[feat_ocfs=yes])

AC_ARG_ENABLE([random-method],[[  --enable-random-method	DEPRECATED: Random pattern method (like shred) instead of full Gutmann.]],
	[if (test "x$enableval" = "xyes"); then
		want_rand=yes
	 else
		want_rand=no
	 fi
	]
	,[want_rand=no])

AC_ARG_ENABLE(wfs,[[  --enable-wfs		enable wiping free space (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_wfs=no
	 else
		feat_wfs=yes
	 fi
	]
	,[feat_wfs=yes])

AC_ARG_ENABLE(unrm,[[  --enable-unrm		enable wiping undelete data (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_unrm=no
	 else
		feat_unrm=yes
	 fi
	]
	,[feat_unrm=yes])

AC_ARG_ENABLE(part,[[  --enable-part		enable wiping partially-used blocks (default=yes).]],
	[if (test "x$enableval" = "xno"); then
		feat_part=no
	 else
		feat_part=yes
	 fi
	]
	,[feat_part=yes])

AC_ARG_ENABLE(LIBHIDEIP,[[  --enable-LIBHIDEIP	Enable libhideip for wipefreespace.]],
	[if (test "x$enableval" = "xno"); then
		feat_LIBHIDEIP=no
	 else
		feat_LIBHIDEIP=yes
	 fi
	]
	,feat_LIBHIDEIP=no)

AC_ARG_ENABLE(LIBNETBLOCK,[[  --enable-LIBNETBLOCK	Enable libnetblock for wipefreespace.]],
	[if (test "x$enableval" = "xno"); then
		feat_LIBNETBLOCK=no
	 else
		feat_LIBNETBLOCK=yes
	 fi
	]
	,feat_LIBNETBLOCK=no)

if ( test "x$want_rand" = "xyes" ); then
	AC_MSG_WARN([[--enable-random-method if deprecated. Use --method <name> when running the program.]])
fi

if ( test "x$feat_wfs" != "xyes" && test "x$feat_unrm" != "xyes" && test "x$feat_part" != "xyes" ); then
	AC_MSG_ERROR([[All three options --enable-wfs=no --enable-unrm=no --enable-part=no can NOT be given together.]])
fi

if ( test "x$feat_wfs" = "xyes" ); then
	AC_DEFINE(WFS_WANT_WFS, [1], [If wiping free space has been enabled.])
fi

if ( test "x$feat_unrm" = "xyes" ); then
	AC_DEFINE(WFS_WANT_UNRM, [1], [If wiping undelete data has been enabled.])
fi

if ( test "x$feat_part" = "xyes" ); then
	AC_DEFINE(WFS_WANT_PART, [1], [If wiping partially-used blocks has been enabled.])
fi

# ==================== Set of available languages (deprecated).
#ALL_LINGUAS="pl"

# ==================== Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_RANLIB
AM_CONDITIONAL(ISGCC, [test "x$GCC" = "xyes"])

# ==================== Checks for libraries.
# OpenBSD needs libssl and libcrypto for libcom_err, which is part of
#	krb5-devel in that world. Autoconf cache makes the second test
#	(with the libraries) negative, so this is disabled.
#AC_CHECK_LIB([com_err],[com_err],,
#
#	AC_CHECK_LIB([ssl],[ssl_cert_new],,, [-lcrypto])
#	AC_CHECK_LIB([crypto],[RAND_add],,, [-lssl])
#	AC_CHECK_LIB([com_err],[com_err],,,[-lssl -lcrypto])
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
libntfs3g=no
if ( test "x$feat_ntfs" = "xyes" ); then

	libntfs3g=yes
	AC_CHECK_LIB([ntfs-3g],[ntfs_pwrite],,[libntfs3g=no])
	if ( test "x$libntfs3g" = "xno" ); then

		libntfs=yes
		AC_CHECK_LIB([ntfs],[ntfs_pwrite],,[libntfs=no])
	fi
fi

libuuid=no
if ( test "x$feat_reiser" = "xyes" || test "x$feat_reiser4" = "xyes" \
	|| test "x$feat_jfs" = "xyes" ); then
	libuuid=yes
	AC_CHECK_LIB([uuid],[uuid_unparse],,[libuuid=no])
fi

libmisc=no
libcore=no
has_patched_r3=no
if ( test "x$feat_reiser" = "xyes" ); then

	if (test "x$libuuid" = "xyes"); then

		libmisc=yes
		libcore=yes
		has_patched_r3=yes
		AC_CHECK_LIB([misc],[misc_test_bit],,[libmisc=no],[-luuid])
		AC_CHECK_LIB([core],[reiserfs_open],,[libcore=no],[-lmisc -luuid])
		AC_CHECK_FUNC([reiser3_new_bread], AC_DEFINE([HAVE_REISER3_NEW_BREAD],[1],
			[Whether you have patched Reiser3FS library.]),[has_patched_r3=no])
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
		if (test "x$libreiser4" != "xyes"); then
			libreiser4=yes
			AC_CHECK_LIB([reiser4],[reiser4_object_open],,[libreiser4=no],[-laal -luuid])
		fi
	else
		AC_MSG_WARN([[Reiser4 support impossible without the aal and uuid libraries.]])
	fi
fi

libtffs=no
if ( test "x$feat_fatfs" = "xyes" ); then

	libtffs=yes
	AC_CHECK_LIB([tffs],[TFFS_mount],,[libtffs=no])
fi

libminixfs=no
if ( test "x$feat_minixfs" = "xyes" ); then

	libminixfs=yes
	AC_CHECK_LIB([minixfs],open_fs,,[libminixfs=no])
fi

libjfs=no
has_patched_jfs=no
if ( test "x$feat_jfs" = "xyes" ); then

	libjfs=yes
	AC_CHECK_LIB([fs],ujfs_get_superblk,,[libjfs=no])
	if (test "x$libjfs" = "xyes"); then

		has_patched_jfs=yes
		AC_CHECK_FUNC([jfs_bread], AC_DEFINE([HAVE_JFS_BREAD],[1],
			[Whether you have patched JFS library.]),[has_patched_jfs=no])
	fi
fi

libhfsp=no
if ( test "x$feat_hfsp" = "xyes" ); then

	libhfsp=yes
	AC_CHECK_LIB([hfsp],volume_open,,[libhfsp=no])
fi

libocfs=no
if ( test "x$feat_ocfs" = "xyes" ); then

	libocfs=yes
	AC_CHECK_LIB([ocfs2],ocfs2_open,,[libocfs=no])
fi

if ( test "x$feat_LIBHIDEIP" = "xyes" ); then

	libhip=yes
	AC_CHECK_LIB(hideip,[libhideip_enable],,[libhip=no])
fi

if ( test "x$feat_LIBNETBLOCK" = "xyes" ); then

	libnb=yes
	AC_CHECK_LIB(netblock,[libnetblock_enable],,[libnb=no])
fi

# ==================== Checks for header files.
# AC_HEADER_STDC
# m4_warn([obsolete],
# [The preprocessor macro `STDC_HEADERS' is obsolete.
#   Except in unusual embedded environments, you can safely include all
#   ISO C90 headers unconditionally.])dnl
# Autoupdate added the next two lines to ensure that your configure
# script's behavior did not change.  They are probably safe to remove.
AC_CHECK_INCLUDES_DEFAULT
AC_PROG_EGREP

AC_CHECK_HEADERS([sys/time.h time.h sys/stat.h])
# AC_HEADER_TIME()
# m4_warn([obsolete],
# [Update your code to rely only on HAVE_SYS_TIME_H,
# then remove this warning and the obsolete code below it.
# All current systems provide time.h; it need not be checked for.
# Not all systems provide sys/time.h, but those that do, all allow
# you to include it and time.h simultaneously.])dnl
# AC_CHECK_HEADERS_ONCE([sys/time.h])
# Obsolete code to be removed.
# if test $ac_cv_header_sys_time_h = yes; then
#   AC_DEFINE([TIME_WITH_SYS_TIME],[1],[Define to 1 if you can safely include both <sys/time.h>
# 	     and <time.h>.  This macro is obsolete.])
# fi
# End of obsolete code.

AC_HEADER_STAT()
AC_HEADER_SYS_WAIT()
AC_HEADER_MAJOR()

has_uni_h=yes
AC_CHECK_HEADER([unistd.h],AC_DEFINE([HAVE_UNISTD_H],[1],
	[Whether you have the unistd.h header.]),[has_uni_h=no])

has_uuid_h=yes
if ( test "x$feat_jfs" = "xyes" ); then

	if ( test "x$libjfs" = "xyes" ); then

		AC_CHECK_HEADER([uuid/uuid.h],
			AC_DEFINE([HAVE_UUID_UUID_H],[1],[Whether you have the uuid/uuid.h header.]),
			[has_uuid_h=no])
	fi
fi

AC_CHECK_HEADERS([sys/param.h mntent.h sys/types.h linux/types.h])
AC_CHECK_HEADER([stdarg.h],[AC_DEFINE([HAVE_STDARG_H], [1], [Whether you have the stdarg.h header])],
	[AC_CHECK_HEADER([varargs.h],[AC_DEFINE([HAVE_VARARGS_H], [1],
		[Whether you have the varargs.h header])])])

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
				[has_ext234_h=no])]
			)
	fi
fi

if ( test "x$feat_xfs" = "xyes" ); then

	AC_CHECK_PROG([XFS_DB], [xfs_db], [yes], [no])
	if ( test "x$XFS_DB" = "xyes" ); then

		AC_DEFINE([HAVE_XFS_DB],[1],[Whether you have the xfs_db program.])
	fi
fi

have_ll=yes
AC_CHECK_TYPE([long long],AC_DEFINE([HAVE_LONG_LONG],[1],[Whether you have the long long type.]),
	[have_ll=no])

have_dev_t=yes
AC_CHECK_TYPE([dev_t],AC_DEFINE([HAVE_DEV_T],[1],[Whether you have the dev_t type.]),
	[have_dev_t=no],
	[[
	#ifdef HAVE_SYS_TYPES_H
	#include <sys/types.h>
	#endif
	]])

if ( test "x$feat_xfs" = "xyes" ); then

	if (test "x$have_ll" != "xyes" && test "x$XFS_DB" = "xyes" ); then

		AC_MSG_WARN([[XFS support impossible without the long long type.]])
	fi
fi

has_ntfs_h=no
if ( test "x$feat_ntfs" = "xyes" ); then

	if (test "x$have_ll" != "xyes" && (test "x$libntfs" = "xyes" || test "x$libntfs3g" = "xyes")); then

		AC_MSG_WARN([[NTFS support impossible without the long long type.]])

	elif (test "x$have_ll" = "xyes" && (test "x$libntfs" = "xyes" || test "x$libntfs3g" = "xyes")); then

		CFLAGS="$CFLAGS -I src"
		has_ntfs_h=yes
		if ( test "x$libntfs3g" = "xno" ); then
			AC_CHECK_HEADER([ntfs/volume.h],
					[AC_DEFINE([HAVE_NTFS_VOLUME_H],[1],
						[Whether you have the ntfs/volume.h header.])],
					[AC_CHECK_HEADER([ntfs/ntfs_volume.h],
						AC_DEFINE([HAVE_NTFS_NTFS_VOLUME_H],[1],
							[Whether you have the ntfs/ntfs_volume.h header.]),
						[AC_CHECK_HEADER([volume.h],
							AC_DEFINE([HAVE_VOLUME_H],[1],
								[Whether you have the volume.h header.]),
							[has_ntfs_h=no],
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
		else
			AC_CHECK_HEADER([ntfs-3g/volume.h],
					[AC_DEFINE([HAVE_NTFS_3G_VOLUME_H],[1],
						[Whether you have the ntfs-3g/volume.h header.])],
					[AC_CHECK_HEADER([ntfs-3g/ntfs_volume.h],
						AC_DEFINE([HAVE_NTFS_3G_NTFS_VOLUME_H],[1],
							[Whether you have the ntfs-3g/ntfs_volume.h header.]),
						[AC_CHECK_HEADER([volume.h],
							AC_DEFINE([HAVE_VOLUME_H],[1],
								[Whether you have the volume.h header.]),
							[has_ntfs_h=no],
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
			[has_libreiser4_h=no], [/* stub comment to avoid default #defines */])
	fi
fi

has_tffs_h=no
if ( test "x$feat_fatfs" = "xyes" ); then

	if ( test "x$libtffs" = "xyes" ); then

		has_tffs_h=yes
		AC_CHECK_HEADER([tffs.h],
			AC_DEFINE([HAVE_TFFS_H],[1],
				[Whether you have the tffs.h header.]),
			[has_tffs_h=no])
	fi
fi

has_minixfs_h=no
if ( test "x$feat_minixfs" = "xyes" ); then

	if ( test "x$libminixfs" = "xyes" ); then

		has_minixfs_h=yes
		AC_CHECK_HEADER([minix_fs.h],
			AC_DEFINE([HAVE_MINIX_FS_H],[1],
				[Whether you have the minix_fs.h header.]),
			[has_minixfs_h=no])
	fi
fi

has_jfs_h=no
if ( test "x$feat_jfs" = "xyes" ); then

	if ( test "x$libjfs" = "xyes" && test "x$has_uuid_h" = "xyes" ); then

		has_jfs_h=yes
		AC_CHECK_HEADER([jfs_superblock.h],
			AC_DEFINE([HAVE_JFS_SUPERBLOCK_H],[1],
				[Whether you have the jfs_superblock.h header.]),
					[AC_CHECK_HEADER([jfs/jfs_superblock.h],
						AC_DEFINE([HAVE_JFS_JFS_SUPERBLOCK_H],[1],
						[Whether you have the jfs/jfs_superblock.h header.]),
						[has_jfs_h=no],
						[[#include <jfs_types.h>]])],
			[[#include <jfs_types.h>]]
						)
	fi
fi

has_hfsp_h=no
if ( test "x$feat_hfsp" = "xyes" ); then

	if ( test "x$libhfsp" = "xyes" ); then

		has_hfsp_h=yes
		AC_CHECK_HEADER([libhfsp.h],
			AC_DEFINE([HAVE_LIBHFSP_H],[1],
				[Whether you have the libhfsp.h header.]),
					[AC_CHECK_HEADER([hfsplus/libhfsp.h],
						AC_DEFINE([HAVE_HFSPLUS_LIBHFSP_H],[1],
						[Whether you have the hfsplus/libhfsp.h header.]),
						[has_hfsp_h=no])])
	fi
fi

AC_CHECK_TYPES([umode_t],,,
	[[
	#ifdef HAVE_LINUX_TYPES_H
	# include <linux/types.h>
	#endif
	]])

has_ocfs_h=no
if ( test "x$feat_ocfs" = "xyes" ); then

	if ( test "x$libocfs" = "xyes" ); then

		has_ocfs_h=yes
		AC_CHECK_HEADER(
			[ocfs2/ocfs2.h],
			AC_DEFINE([HAVE_OCFS2_OCFS2_H],[1],
				[Whether you have the ocfs2/ocfs2.h header.]),
			[AC_CHECK_HEADER(
				[ocfs2.h],
				AC_DEFINE([HAVE_OCFS2_H],[1],
					[Whether you have the ocfs2.h header.]),
				[has_ocfs_h=no],
				[
					#ifndef HAVE_UMODE_T
					#define umode_t mode_t /* workaround for new glibc */
					#endif
					#ifdef HAVE_SYS_TYPES_H
					#include <sys/types.h>
					#endif
				]
			)],
			[
				#ifndef HAVE_UMODE_T
				#define umode_t mode_t /* workaround for new glibc */
				#endif
				#ifdef HAVE_SYS_TYPES_H
				#include <sys/types.h>
				#endif
			]
		)
	fi
fi

if ( test "x$feat_LIBHIDEIP" = "xyes" && test "x$libhip" = "xyes" ); then

	have_libhideip_h=yes
	AC_CHECK_HEADER([libhideip.h],AC_DEFINE([HAVE_LIBHIDEIP_H],[1],
		[Whether you have the libhideip.h header.]), have_libhideip_h=no)
fi

if ( test "x$feat_LIBNETBLOCK" = "xyes" && test "x$libnb" = "xyes" ); then

	have_libnetblock_h=yes
	AC_CHECK_HEADER([libnetblock.h],AC_DEFINE([HAVE_LIBNETBLOCK_H],[1],
		[Whether you have the libnetblock.h header.]), have_libnetblock_h=no)
fi

wfs_have_reiser4=no
if (	   test "x$has_libreiser4_h"	= "xyes"	\
	&& test "x$libreiser4"		= "xyes"	\
	&& test "x$feat_reiser4"	= "xyes"	\
	&& test "x$have_ll"		= "xyes" ); then

	wfs_have_reiser4=yes
fi

AM_CONDITIONAL(REISER4, [test "x$wfs_have_reiser4" = "xyes"] )

wfs_have_ext234fs=no
if (	   test "x$has_ext234_h"	= "xyes"	\
	&& test "x$libext234"		= "xyes"	\
	&& test "x$feat_ext234"		= "xyes"	\
	&& test "x$have_dev_t"		= "xyes" ); then

	wfs_have_ext234fs=yes
fi

AM_CONDITIONAL(EXT234FS, [test "x$wfs_have_ext234fs" = "xyes"] )

wfs_have_ntfs=no
if (	   test "x$has_ntfs_h"		= "xyes"	\
	&& (test "x$libntfs"		= "xyes" || test "x$libntfs3g" = "xyes")	\
	&& test "x$feat_ntfs"		= "xyes" ); then

	wfs_have_ntfs=yes
fi

AM_CONDITIONAL(NTFS, [test "x$wfs_have_ntfs" = "xyes"] )

wfs_have_fatfs=no
if (	   test "x$has_tffs_h"		= "xyes"	\
	&& test "x$libtffs"		= "xyes"	\
	&& test "x$feat_fatfs"		= "xyes" ); then

	wfs_have_fatfs=yes
fi

AM_CONDITIONAL(FATFS, [test "x$wfs_have_fatfs" = "xyes"] )

wfs_have_minixfs=no
if (	   test "x$has_minixfs_h"	= "xyes"	\
	&& test "x$libminixfs"		= "xyes"	\
	&& test "x$feat_minixfs"	= "xyes" ); then

	wfs_have_minixfs=yes
fi

AM_CONDITIONAL(MINIXFS, [test "x$wfs_have_minixfs" = "xyes"] )

wfs_have_jfs=no
if (	   test "x$has_jfs_h"		= "xyes"	\
	&& test "x$libjfs"		= "xyes"	\
	&& test "x$has_uuid_h"		= "xyes"	\
	&& test "x$feat_jfs"		= "xyes" ); then

	wfs_have_jfs=yes
fi

AM_CONDITIONAL(JFS, [test "x$wfs_have_jfs" = "xyes"] )

wfs_have_hfsp=no
if (	   test "x$has_hfsp_h"		= "xyes"	\
	&& test "x$libhfsp"		= "xyes"	\
	&& test "x$feat_hfsp"		= "xyes" ); then

	wfs_have_hfsp=yes
fi

AM_CONDITIONAL(HFSP, [test "x$wfs_have_hfsp" = "xyes"] )

wfs_have_ocfs=no
if (	   test "x$has_ocfs_h"		= "xyes"	\
	&& test "x$libocfs"		= "xyes"	\
	&& test "x$feat_ocfs"		= "xyes" ); then

	wfs_have_ocfs=yes
fi

AM_CONDITIONAL(OCFS, [test "x$wfs_have_ocfs" = "xyes"] )

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

AC_CHECK_HEADER([linux/loop.h],
	AC_DEFINE([HAVE_LINUX_LOOP_H],[1],[Whether you have the linux/loop.h header.]),
	[AC_CHECK_HEADER([loop.h],
		AC_DEFINE([HAVE_LOOP_H],[1],[Whether you have the loop.h header.]))]
)
AC_CHECK_HEADER([linux/hdreg.h],
	AC_DEFINE([HAVE_LINUX_HDREG_H],[1],[Whether you have the linux/hdreg.h header.]),
	[AC_CHECK_HEADER([hdreg.h],
		AC_DEFINE([HAVE_HDREG_H],[1],[Whether you have the hdreg.h header.]))]
)
AC_CHECK_HEADER([endian.h],
	AC_DEFINE([HAVE_ENDIAN_H],[1],[Whether you have the endian.h header.]),
	[AC_CHECK_HEADER([machine/endian.h],
		AC_DEFINE([HAVE_MACHINE_ENDIAN_H],[1],[Whether you have the machine/endian.h header.]))]
)

AC_CHECK_HEADERS([getopt.h locale.h stdlib.h string.h errno.h signal.h \
	malloc.h libgen.h limits.h paths.h sys/select.h sched.h asm/types.h \
	sys/sysmacros.h sys/mkdev.h sys/ioctl.h Sys/statfs.h sys/vfs.h \
	sys/byteorder.h stdbool.h strings.h])

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
	[[
	#ifndef _GNU_SOURCE
	# define _GNU_SOURCE	1
	#endif
	#ifdef HAVE_UNISTD_H
	# include <unistd.h>
	#endif
	]])

AC_CHECK_DECLS([__environ],,,
	[[
	#ifdef HAVE_UNISTD_H
	# include <unistd.h>
	#endif
	]])

# ===================== Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_C_VOLATILE
AC_CHECK_TYPES([size_t, ssize_t])
AC_CHECK_TYPES([off64_t],,,
	[[
	#define _FILE_OFFSET_BITS 64
	#define _LARGEFILE64_SOURCE
	#ifdef HAVE_SYS_TYPES_H
	# include <sys/types.h>
	#endif
	]])
AC_CHECK_TYPES([int64_t],,,
	[[
	#ifdef HAVE_SYS_TYPES_H
	# include <sys/types.h>
	#endif
	]])
AC_CHECK_TYPES([sig_atomic_t],,,
	[[
	#ifdef HAVE_SIGNAL_H
	# include <signal.h>
	#endif
	]])

# Checks for library functions.
AC_FUNC_MALLOC
# AC_TYPE_SIGNAL
# m4_warn([obsolete],
# [your code may safely assume C89 semantics that RETSIGTYPE is void.
# Remove this warning and the AC_CACHE_CHECK when you adjust the code.])dnl
AC_CACHE_CHECK([return type of signal handlers],[ac_cv_type_signal],[AC_COMPILE_IFELSE(
[AC_LANG_PROGRAM([#include <sys/types.h>
#include <signal.h>
],
		 [return *(signal (0, 0)) (0) == 1;])],
		   [ac_cv_type_signal=int],
		   [ac_cv_type_signal=void])])
AC_DEFINE_UNQUOTED([RETSIGTYPE],[$ac_cv_type_signal],[Define as the return type of signal handlers
		    (int or void).])


AC_CHECK_FUNCS([memset memcpy setlocale strtol random srandom clearenv \
	getuid geteuid snprintf daemon sigaction access sleep getpid getopt_long \
	hasmntopt getmntent getmntent_r sched_yield sync fsync select ioctl \
	getmntinfo fopen64 basename umount open stat stat64 fstat fstat64 \
	strdup strcasecmp])

# NOTE: Debian 5 does not support execvpe(), so it requires execvp()
# along with setenv() or putenv()
has_execvpe=yes
has_execvp=yes
has_kill=yes
has_setenv=yes
has_putenv=yes
AC_CHECK_FUNC([execvpe],
	AC_DEFINE([HAVE_EXECVPE],[1],[Whether you have the execvpe function.]),
	[has_execvpe=no])
AC_CHECK_FUNC([execvp],
	AC_DEFINE([HAVE_EXECVP],[1],[Whether you have the execvp function.]),
	[has_execvp=no])
AC_CHECK_FUNC([kill],
	AC_DEFINE([HAVE_KILL],[1],[Whether you have the kill function.]),
	[has_kill=no])
AC_CHECK_FUNC([setenv],
	AC_DEFINE([HAVE_SETENV],[1],[Whether you have the setenv function.]),
	[has_setenv=no])
AC_CHECK_FUNC([putenv],
	AC_DEFINE([HAVE_PUTENV],[1],[Whether you have the putenv function.]),
	[has_putenv=no])

has_malloc=yes
AC_CHECK_FUNC([malloc],
	AC_DEFINE([HAVE_MALLOC],[1],[Whether you have the malloc function.]),
	[has_malloc=no])

if (test "x$has_malloc" != "xyes"); then

	AC_MSG_ERROR([[I need the malloc() function.]])
fi

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

has_exit=yes
AC_CHECK_FUNC([exit],
	AC_DEFINE([HAVE_EXIT],[1],[Whether you have the exit function.]),
	[has_exit=no])


if ( \
	   test "x$have_ll"        = "xyes"	\
	&& test "x$has_uni_h"      = "xyes"	\
	&& test "x$has_fcntl_h"    = "xyes"	\
	&& test "x$has_fork"       = "xyes"	\
	&& (  test "x$has_execvpe" = "xyes"	\
	   || test "x$has_execvp"  = "xyes" )	\
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

if  (  test "x$wfs_have_ext234fs"	!= "xyes"	\
    && test "x$wfs_have_ntfs"		!= "xyes"	\
    && test "x$wfs_have_xfs"		!= "xyes"	\
    && test "x$wfs_have_reiserfs"	!= "xyes"	\
    && test "x$wfs_have_reiser4"	!= "xyes"	\
    && test "x$wfs_have_fatfs"		!= "xyes"	\
    && test "x$wfs_have_minixfs"	!= "xyes"	\
    && test "x$wfs_have_jfs"		!= "xyes"	\
    && test "x$wfs_have_hfsp"		!= "xyes"	\
    && test "x$wfs_have_ocfs"		!= "xyes"
    ); then
	AC_MSG_ERROR([[I need headers/libraries/programs for at least one of the filesystems.]])
fi

AM_GNU_GETTEXT_VERSION([0.21])
AM_GNU_GETTEXT([external])

# Can be /usr/local/include/libintl.h. Use --with-libintl-prefix=DIR then.
# The macros above set the correct CFLAGS if this option is given.

AC_CHECK_HEADERS([libintl.h])

have_check=no
#ACTION-IF-NOT-FOUND is required, otherwise 'configure' fails
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4], [have_check=yes], [have_check=no])
#AM_PATH_CHECK([], [have_check=yes])

AM_CONDITIONAL([WFS_TESTS_ENABLED], [test "x$have_check" = "xyes"])

if (test "x$have_check" = "xyes"); then

	AC_CHECK_FUNCS([mount])
fi

# ==================== Checks for compiler options.

if (test "x$GCC" = "xyes" ); then

	AX_GCC_WARN_UNUSED_RESULT()

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
	AX_C_CHECK_FLAG([-Wformat -Wformat-overflow=2], [CFLAGS="$CFLAGS -Wformat -Wformat-overflow=2"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wnested-externs], [CFLAGS="$CFLAGS -Wnested-externs"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wshadow], [CFLAGS="$CFLAGS -Wshadow"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wconversion], [CFLAGS="$CFLAGS -Wconversion"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wdeclaration-after-statement], [CFLAGS="$CFLAGS -Wdeclaration-after-statement"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wundef], [CFLAGS="$CFLAGS -Wundef"], [CFLAGS="$CFLAGS"])
	#AX_C_CHECK_FLAG([-Wpadded], [CFLAGS="$CFLAGS -Wpadded"], [CFLAGS="$CFLAGS"])
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
	AX_C_CHECK_FLAG([-O2], [CFLAGS="$CFLAGS -O2"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-O3], [CFLAGS="$CFLAGS -O3"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Waggregate-return], [CFLAGS="$CFLAGS -Waggregate-return"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wwrite-strings], [CFLAGS="$CFLAGS -Wwrite-strings"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wchkp], [CFLAGS="$CFLAGS -Wchkp"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wduplicated-cond], [CFLAGS="$CFLAGS -Wduplicated-cond"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wrestrict], [CFLAGS="$CFLAGS -Wrestrict"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Woverlength-strings], [CFLAGS="$CFLAGS -Woverlength-strings"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wno-nonnull-compare], [CFLAGS="$CFLAGS -Wno-nonnull-compare"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wstringop-truncation], [CFLAGS="$CFLAGS -Wstringop-truncation"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wduplicated-branches], [CFLAGS="$CFLAGS -Wduplicated-branches"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-fstack-check], [CFLAGS="$CFLAGS -fstack-check"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-g], [CFLAGS="$CFLAGS -g"], [CFLAGS="$CFLAGS"])	# needed for the 'debuginfo' rpm package

	if (test "x$have_ll" = "xyes"); then

		AX_C_CHECK_FLAG([-std=gnu99], [CFLAGS="$CFLAGS -std=gnu99"], [CFLAGS="$CFLAGS"])
		AX_C_CHECK_FLAG([-Wno-long-long], [CFLAGS="$CFLAGS -Wno-long-long"], [CFLAGS="$CFLAGS"])
	fi
fi

# Required if filesystem libraries with conflicting names are enabled,
# because the same symbols appear in multiple places.
if ( test "x$wfs_have_reiserfs" = "xyes" && test "x$wfs_have_reiser4" = "xyes"); then

	AX_C_CHECK_FLAG([-Wl,-z -Wl,muldefs], [CFLAGS="$CFLAGS -Wl,-z -Wl,muldefs"], [CFLAGS="$CFLAGS"])
	AX_CHECK_LINK_FLAG([-z muldefs])
fi

# this doubles the CFLAGS on compile:
#AC_SUBST(AM_CFLAGS,$CFLAGS)

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
	elif (test "x$have_dev_t" != "xyes"); then
		echo " *	Ext2/3/4: no (dev_t type missing)"
	else
		echo " *	Ext2/3/4: no (headers missing or unusable)"
	fi
fi

if (       test "x$has_ntfs_h"	= "xyes"	\
	&& (test "x$libntfs"	= "xyes" || test "x$libntfs3g" = "xyes")); then

		echo " *	NTFS: yes"
else
	if (test "x$feat_ntfs" != "xyes"); then
		echo " *	NTFS: no (disabled by command line)"
	elif (test "x$libntfs" != "xyes"); then
		echo " *	NTFS: no (library missing or unusable)"
	elif (test "x$libntfs3g" != "xyes"); then
		echo " *	NTFS: no (library missing or unusable)"
	else
		echo " *	NTFS: no (headers missing or unusable)"
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
		echo " *	XFS: no (unistd.h missing or unusable)"

	elif (test "x$has_fcntl_h" != "xyes"); then
		echo " *	XFS: no (fcntl.h missing or unusable)"

	elif (test "x$has_fork" != "xyes"); then
		echo " *	XFS: no (fork() missing)"

	elif (test "x$has_execvpe" != "xyes" && test "x$has_execvp" != "xyes"); then
		echo " *	XFS: no (execvpe() and execvp() missing)"

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

	echo " *	ReiserFSv3: yes"
else
	if (test "x$feat_reiser" != "xyes"); then
		echo " *	ReiserFSv3: no (disabled by command line)"

	elif (test "x$libcore" != "xyes"); then
		echo " *	ReiserFSv3: no (library missing or unusable)"

	elif (test "x$have_ll" != "xyes"); then
		echo " *	ReiserFSv3: no (long long type missing)"

	elif ( test "x$has_reiser_h"  != "xyes" ); then
		echo " *	ReiserFSv3: no (reiserfs_lib.h header missing or unusable)"

	elif (test "x$has_uni_h" != "xyes"); then
		echo " *	ReiserFSv3: no (unistd.h missing or unusable)"

	elif (test "x$has_sys_wait_h" != "xyes"); then
		echo " *	ReiserFSv3: no (wait.h & sys/wait.h missing or unusable)"

	elif (test "x$has_exit" != "xyes"); then
		echo " *	ReiserFSv3: no (exit() missing)"

	elif (test "x$has_fork" != "xyes"); then
		echo " *	ReiserFSv3: no (fork() missing)"

	else
		echo " *	ReiserFSv3: no (waitpid() and wait() missing)"
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

	elif (test "x$libreiser4" != "xyes"); then
		echo " *	Reiser4: no (library missing or unusable)"

	elif (test "x$have_ll" != "xyes"); then
		echo " *	Reiser4: no (long long type missing)"

	else	#if ( test "x$has_libreiser4_h"  != "xyes" ); then
		echo " *	Reiser4: no (libreiser4.h header missing or unusable)"
	fi
fi

if (	   test "x$has_tffs_h"		= "xyes"	\
	&& test "x$libtffs"		= "xyes"	\
	&& test "x$feat_fatfs"		= "xyes"); then

	echo " *	FAT12/16/32: yes"
else
	if (test "x$feat_fatfs" != "xyes"); then
		echo " *	FAT12/16/32: no (disabled by command line)"

	elif (test "x$libtffs" != "xyes"); then
		echo " *	FAT12/16/32: no (library missing or unusable)"

	else	#if ( test "x$has_tffs_h"  != "xyes" ); then
		echo " *	FAT12/16/32: no (tffs.h header missing or unusable)"
	fi
fi

if (	   test "x$has_minixfs_h"	= "xyes"	\
	&& test "x$libminixfs"		= "xyes"	\
	&& test "x$feat_minixfs"	= "xyes"); then

	echo " *	MinixFS: yes"
else
	if (test "x$feat_minixfs" != "xyes"); then
		echo " *	MinixFS: no (disabled by command line)"

	elif (test "x$libminixfs" != "xyes"); then
		echo " *	MinixFS: no (library missing or unusable)"

	else	#if ( test "x$has_minixfs_h"  != "xyes" ); then
		echo " *	MinixFS: no (minix_fs.h header missing or unusable)"

	fi
fi

if (	   test "x$has_jfs_h"	= "xyes"	\
	&& test "x$libjfs"	= "xyes"	\
	&& test "x$has_uuid_h"	= "xyes"	\
	&& test "x$feat_jfs"	= "xyes"); then

	echo " *	JFS: yes"
else
	if (test "x$feat_jfs" != "xyes"); then
		echo " *	JFS: no (disabled by command line)"

	elif (test "x$libjfs" != "xyes"); then
		echo " *	JFS: no (library missing or unusable)"

	elif (test "x$has_uuid_h" != "xyes"); then
		echo " *	JFS: no (<uuid/uuid.h> header missing or unusable)"

	else	#if ( test "x$has_jfs_h"  != "xyes" ); then
		echo " *	JFS: no (jfs_superblock.h header missing or unusable)"

	fi
fi

if (	   test "x$has_hfsp_h"	= "xyes"	\
	&& test "x$libhfsp"	= "xyes"	\
	&& test "x$feat_hfsp"	= "xyes"); then

	echo " *	HFS+: yes"
else
	if (test "x$feat_hfsp" != "xyes"); then
		echo " *	HFS+: no (disabled by command line)"

	elif (test "x$libhfsp" != "xyes"); then
		echo " *	HFS+: no (library missing or unusable)"

	else	#if ( test "x$has_hfsp_h"  != "xyes" ); then
		echo " *	HFS+: no (libhfsp.h header missing or unusable)"

	fi
fi

if (	   test "x$has_ocfs_h"	= "xyes"	\
	&& test "x$libocfs"	= "xyes"	\
	&& test "x$feat_ocfs"	= "xyes"); then

	echo " *	OCFS: yes"
else
	if (test "x$feat_ocfs" != "xyes"); then
		echo " *	OCFS: no (disabled by command line)"

	elif (test "x$libocfs" != "xyes"); then
		echo " *	OCFS: no (library missing or unusable)"

	else	#if ( test "x$has_ocfs_h"  != "xyes" ); then
		echo " *	OCFS: no (ocfs2.h header missing or unusable)"

	fi
fi

echo "***********************************"

if (test "x$feat_wfs" = "xyes"); then

	echo " *	Wiping free space enabled: yes"
else

	echo " *	Wiping free space enabled: no (disabled by command line)"
fi

if (test "x$feat_unrm" = "xyes"); then

	echo " *	Wiping undelete data enabled: yes"
else

	echo " *	Wiping undelete data enabled: no (disabled by command line)"
fi

if (test "x$feat_part" = "xyes"); then

	echo " *	Wiping partially used blocks enabled: yes"
else

	echo " *	Wiping partially used blocks enabled: no (disabled by command line)"
fi

echo "***********************************"

if (	test "x$feat_LIBHIDEIP" = "xyes" && test "x$libhip" = "xyes" \
	&& test "x$have_libhideip_h" = "xyes" ); then

	echo " *	LibHideIP enabled: yes"
	AC_MSG_WARN([[LibHideIP may cause network filesystem wiping not to work.]])
	AC_MSG_WARN([[If you do not wish to enable LibHideIP, re-configure wipefreespace with]])
	AC_MSG_WARN([[./configure --enable-LIBHIDEIP=no]])
else
	if (test "x$feat_LIBHIDEIP" != "xyes"); then
		echo " *	LibHideIP enabled: no (disabled by command line)"

	elif ( test "x$libhip" != "xyes" ); then
		echo " *	LibHideIP enabled: no (library missing)"

	else	#( test "x$have_libhideip_h" != "xyes" ); then
		echo " *	LibHideIP enabled: no (libhideip.h header missing)"

	fi
fi

if (	test "x$feat_LIBNETBLOCK" = "xyes" && test "x$libnb" = "xyes" \
	&& test "x$have_libnetblock_h" = "xyes" ); then

	echo " *	LibNetBlock enabled: yes"
	AC_MSG_WARN([[LibNetBlock may cause network filesystem wiping not to work.]])
	AC_MSG_WARN([[If you do not wish to enable LibNetBlock, re-configure wipefreespace with]])
	AC_MSG_WARN([[./configure --enable-LIBNETBLOCK=no]])
else
	if (test "x$feat_LIBNETBLOCK" != "xyes"); then
		echo " *	LibNetBlock enabled: no (disabled by command line)"

	elif ( test "x$libnb" != "xyes" ); then
		echo " *	LibNetBlock enabled: no (library missing)"

	else	#( test "x$have_libnetblock_h" != "xyes" ); then
		echo " *	LibNetBlock enabled: no (libnetblock.h header missing)"

	fi
fi

echo "***********************************"

if ( test "x$wfs_have_reiserfs" = "xyes" && test "x$wfs_have_reiser4" = "xyes" ); then

	AC_MSG_WARN([[ReiserFSv3 and ReiserFSv4 both enabled. They may conflict - read the REDME file.]])
fi

if ( test "x$wfs_have_reiserfs" = "xyes" && test "x$wfs_have_minixfs" = "xyes" ); then

	AC_MSG_WARN([[ReiserFSv3 and MinixFS both enabled. They may conflict - read the REDME file.]])
fi

if ( test "x$wfs_have_reiserfs" = "xyes" && test "x$wfs_have_jfs" = "xyes" ); then

	AC_MSG_WARN([[ReiserFSv3 and JFS both enabled. They may conflict - read the REDME file.]])
fi

if ( test "x$wfs_have_reiserfs" = "xyes" && test "x$wfs_have_jfs" = "xyes" \
	&& test "x$has_patched_r3" != "xyes" && test "x$has_patched_jfs" != "xyes" ); then

	AC_MSG_WARN([[ReiserFSv3 and JFS both enabled and both seem NOT patched. WipeFreeSpace can crash! Read the REDME file.]])
fi

if ( test "x$wfs_have_hfsp" = "xyes"  ); then

	AC_MSG_WARN([[HFS+ enabled. Make sure it is patched - read the REDME file.]])
fi

echo "***********************************"
