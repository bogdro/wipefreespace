/*
 * A program for secure cleaning of free space on filesystems.
 *	-- configuration header file.
 *
 * Copyright (C) 2007 Bogdan Drozdowski, bogdandr (at) op.pl
 * License: GNU General Public License, v2+
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foudation:
 *		Free Software Foundation
 *		51 Franklin Street, Fifth Floor
 *		Boston, MA 02110-1301
 *		USA
 */

#ifndef WFS_CFG_H
# define WFS_CFG_H

# ifdef HAVE_CONFIG_H
#  include <config.h>
# else
#  define HAVE_CLEARENV		1
#  define HAVE_DEV_T		1
#  define HAVE_ERRNO_H		1
#  define HAVE_ET_COM_ERR_H	1
#  define HAVE_EXT2FS_EXT2FS_H	1
#  define HAVE_GETEUID		1
#  define HAVE_GETOPT_H		1
#  define HAVE_GETOPT_LONG	1
#  define HAVE_GETTEXT		1
#  define HAVE_GETUID		1
#  define HAVE_LIBCAP		1
#  define HAVE_LIBCOM_ERR	1
#  define HAVE_LIBINTL_H	1
#  define HAVE_LIBEXT2FS	1
#  define HAVE_LIBNTFS		1
#  define HAVE_LONG_LONG	1
#  define HAVE_MALLOC		1
#  define HAVE_MALLOC_H		1
#  define HAVE_MEMCPY		1
#  define HAVE_MEMORY_H		1
#  define HAVE_MEMSET		1
#  define HAVE_MNTENT_H		1
#  define HAVE_NTFS_VOLUME_H	1
#  define HAVE_RANDOM		1
#  define HAVE_SETLOCALE	1
#  define HAVE_SIGNAL_H		1
#  define HAVE_SIZE_T		1
#  define HAVE_SNPRINTF		1
#  define HAVE_SRANDOM		1
#  define HAVE_STDARG_H		1
#  define HAVE_STDINT_H		1
#  define HAVE_STDLIB_H		1
#  define HAVE_STRING_H		1
#  define HAVE_STRTOUL		1
#  define HAVE_SYS_CAPABILITY_H	1
#  define HAVE_SYS_MOUNT_H	1
#  define HAVE_SYS_PARAM_H	1
#  define HAVE_SYS_STAT_H	1
#  define HAVE_SYS_TYPES_H	1
#  define HAVE_TIME_H		1
#  define HAVE_UNISTD_H		1

#  define STDC_HEADERS		1

#  define PACKAGE_NAME "wipefreespace"
#  define PACKAGE PACKAGE_NAME
#  define PACKAGE_VERSION "0.6"
#  define VERSION PACKAGE_VERSION
#  define LOCALEDIR "/usr/share/locale"
#  define RETSIGTYPE void
#  undef  RETSIG_ISINT
# endif

#endif	/* WFS_CFG_H */
