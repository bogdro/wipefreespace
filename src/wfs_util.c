/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- utility functions.
 *
 * Copyright (C) 2007-2024 Bogdan Drozdowski, bogdro (at) users.sourceforge.net
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "wfs_cfg.h"

#include <stdio.h>	/* FILE */

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>	/* for open() */
#endif

#ifdef HAVE_STRING_H
# if ((!defined STDC_HEADERS) || (!STDC_HEADERS)) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>	/* strncpy() */
#endif

#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>	/* required for sys/mount.h on some systems */
#endif

#ifdef HAVE_MNTENT_H
# include <mntent.h>
#endif

#ifdef HAVE_SYS_STATFS_H
# include <sys/statfs.h>
#endif

#ifdef HAVE_SYS_MOUNT_H
# include <sys/mount.h>
#endif

#ifdef HAVE_SYS_VFS_H
# include <sys/vfs.h>
#endif

#ifdef HAVE_PATHS_H
# include <paths.h>
#endif

#ifndef _PATH_MOUNTED
# ifdef MNT_MNTTAB
#  define	_PATH_MOUNTED	MNT_MNTTAB
# else
#  define	_PATH_MOUNTED	"/etc/mtab"
# endif
#endif

#define WFS_PATH_MOUNTS "/proc/mounts"

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* close() */
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

/*
#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif
*/

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* exit() */
#endif

#ifdef MAJOR_IN_MKDEV
# include <sys/mkdev.h>
#else
# if defined MAJOR_IN_SYSMACROS
#  include <sys/sysmacros.h>
# else /* ! MAJOR_IN_SYSMACROS */
#  ifdef HAVE_SYS_SYSMACROS_H
#   include <sys/sysmacros.h>
#  endif
#  ifdef HAVE_SYS_MKDEV_H
#   include <sys/mkdev.h>
#  endif
# endif /* MAJOR_IN_SYSMACROS */
#endif

#ifdef HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#if (defined HAVE_FCNTL_H) && (defined HAVE_SYS_IOCTL_H)
# include <fcntl.h>     /* O_RDWR, open() for ioctl() */
# include <sys/ioctl.h>
#else
# undef HAVE_IOCTL
#endif

#ifdef HAVE_LINUX_HDREG_H
# include <linux/hdreg.h>
#else
# ifdef HAVE_HDREG_H
#  include <hdreg.h>
# else
#  define HDIO_DRIVE_CMD	0x031f
#  define HDIO_GET_WCACHE	0x030e
#  define HDIO_SET_WCACHE	0x032b
# endif
#endif

#ifdef HAVE_LIBINTL_H
# include <libintl.h>	/* translation stuff */
#endif

#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif

#ifdef HAVE_LOOP_H
# include <loop.h>
#else
# ifdef HAVE_LINUX_LOOP_H
#  include <linux/loop.h>
# endif
#endif

#include "wipefreespace.h"
#include "wfs_util.h"

#ifndef MNTOPT_RW
# define MNTOPT_RW	"rw"
#endif

#ifndef LOOPMAJOR
# define LOOPMAJOR	7
#endif

#if (defined HAVE_MNTENT_H) && ((defined HAVE_GETMNTENT) || (defined HAVE_GETMNTENT_R))
# define WFS_HAVE_MNTENT 1
#else
# undef WFS_HAVE_MNTENT
#endif

#if (defined HAVE_SYS_MOUNT_H) && (defined HAVE_GETMNTINFO)
# define WFS_HAVE_MNTINFO 1
#else
# undef WFS_HAVE_MNTINFO
#endif

#if !( (defined WFS_HAVE_MNTENT) || (defined WFS_HAVE_MNTINFO) )
# define WFS_USED_ONLY_WITH_MOUNTS WFS_ATTR ((unused))
#else
# define WFS_USED_ONLY_WITH_MOUNTS
#endif

#ifndef HAVE_IOCTL
# define WFS_USED_ONLY_WITH_IOCTL WFS_ATTR ((unused))
#else
# define WFS_USED_ONLY_WITH_IOCTL
#endif

#if (defined HAVE_FCNTL_H) && (defined HAVE_SYS_IOCTL_H) \
	&& (defined HAVE_IOCTL) && (defined HAVE_SYS_STAT_H) \
	&& ((defined HAVE_LOOP_H) || (defined HAVE_LINUX_LOOP_H))
# define WFS_HAVE_IOCTL_LOOP 1
# define WFS_USED_ONLY_WITH_LOOP WFS_ATTR ((unused))
#else
# undef WFS_HAVE_IOCTL_LOOP
# define WFS_USED_ONLY_WITH_LOOP
#endif

#ifdef TEST_COMPILE
# undef WFS_ANSIC
#endif

/* ======================================================================== */

#ifdef WFS_HAVE_MNTENT

# ifndef WFS_ANSIC
static wfs_errcode_t GCC_WARN_UNUSED_RESULT wfs_get_mnt_point_getmntent WFS_PARAMS ((
	const char * const dev_name,
	wfs_errcode_t * const error,
	char * const mnt_point,
	const size_t mnt_point_len,
	int * const is_rw));
# endif

/**
 * Gets the mount point of the given device (if mounted), using getmntent(_r).
 * \param dev_name Device to check.
 * \param error Pointer to error variable.
 * \param mnt_point Array for the mount point.
 * \param mnt_point_len The length of the "mnt_point" array.
 * \param is_rw Pointer to a variable which will tell if the filesystem
 *	is mounted in read+write mode (=1 if yes).
 * \return 0 in case of no errors, other values otherwise.
 */
static wfs_errcode_t GCC_WARN_UNUSED_RESULT
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_get_mnt_point_getmntent (
# ifdef WFS_ANSIC
	const char * const dev_name WFS_USED_ONLY_WITH_MOUNTS,
	wfs_errcode_t * const error,
	char * const mnt_point,
	const size_t mnt_point_len WFS_USED_ONLY_WITH_MOUNTS,
	int * const is_rw )
# else
	dev_name WFS_USED_ONLY_WITH_MOUNTS,
	error,
	mnt_point,
	mnt_point_len WFS_USED_ONLY_WITH_MOUNTS,
	is_rw )
	const char * const dev_name;
	wfs_errcode_t * const error;
	char * const mnt_point;
	const size_t mnt_point_len;
	int * const is_rw;
# endif
{
	FILE *mnt_f;
	struct mntent *mnt, mnt_copy;
# ifdef HAVE_GETMNTENT_R
	char buffer[WFS_MNTBUFLEN];
# endif

	if ( (dev_name == NULL) || (mnt_point == NULL)
		|| (is_rw == NULL) || (mnt_point_len == 0) )
	{
		return WFS_BADPARAM;
	}

	*is_rw = 1;
	mnt_point[0] = '\0';

	WFS_SET_ERRNO (0);
	mnt_f = setmntent (_PATH_MOUNTED, "r");
	if ( mnt_f == NULL )
	{
# ifdef HAVE_ERRNO_H
		if ( error != NULL )
		{
			*error = (wfs_errcode_t)errno;
		}
# endif
		return WFS_MNTCHK;
	}
	do
	{
		WFS_SET_ERRNO (0);
# ifndef HAVE_GETMNTENT_R
		mnt = getmntent (mnt_f);
		WFS_MEMCOPY (&mnt_copy, mnt, sizeof (struct mntent));
# else
		mnt = getmntent_r (mnt_f, &mnt_copy, buffer, WFS_MNTBUFLEN);
# endif
		if ( mnt == NULL )
		{
			break;
		}
		if ( strcmp (dev_name, mnt->mnt_fsname) == 0 )
		{
			break;
		}

	} while ( mnt != NULL );

	endmntent (mnt_f);
	if ( (mnt == NULL)
# ifdef HAVE_ERRNO_H
/*		&& (errno == 0)*/
# endif
	   )
	{
		*is_rw = 0;
		return WFS_SUCCESS;	/* seems not to be mounted */
	}
	strncpy (mnt_point, mnt->mnt_dir, mnt_point_len);
	mnt_point[mnt_point_len - 1] = '\0';
# ifdef HAVE_HASMNTOPT
	if (hasmntopt (mnt, MNTOPT_RW) != NULL)
	{
		if ( error != NULL )
		{
			*error = (wfs_errcode_t)1L;
		}
		*is_rw = 1;
		return WFS_MNTRW;
	}
# else
	if ( error != NULL )
	{
		*error = (wfs_errcode_t)1L;
	}
	*is_rw = 1;
	return WFS_MNTRW;	/* can't check for r/w, so don't do anything */
# endif
	*is_rw = 0;
	return WFS_SUCCESS;
}
#endif /* WFS_HAVE_MNTENT */

/* ======================================================================== */

#ifndef WFS_ANSIC
static wfs_errcode_t GCC_WARN_UNUSED_RESULT wfs_get_mnt_point_mounts WFS_PARAMS ((
	const char * const dev_name,
	wfs_errcode_t * const error,
	char * const mnt_point,
	const size_t mnt_point_len,
	int * const is_rw));
#endif

static char mounts_buffer[WFS_MNTBUFLEN+1];
static char mounts_device[WFS_MNTBUFLEN+1];
static char mounts_flags[WFS_MNTBUFLEN+1];

/**
 * Gets the mount point of the given device (if mounted), using the mounts' file.
 * \param dev_name Device to check.
 * \param error Pointer to error variable.
 * \param mnt_point Array for the mount point (must be at least WFS_MNTBUFLEN characters long).
 * \param mnt_point_len The length of the "mnt_point" array.
 * \param is_rw Pointer to a variable which will tell if the filesystem
 *	is mounted in read+write mode (=1 if yes).
 * \return 0 in case of no errors, other values otherwise.
 */
static wfs_errcode_t GCC_WARN_UNUSED_RESULT
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_get_mnt_point_mounts (
#ifdef WFS_ANSIC
	const char * const dev_name WFS_USED_ONLY_WITH_MOUNTS,
	wfs_errcode_t * const error,
	char * const mnt_point,
	const size_t mnt_point_len WFS_USED_ONLY_WITH_MOUNTS,
	int * const is_rw )
#else
	dev_name WFS_USED_ONLY_WITH_MOUNTS,
	error,
	mnt_point,
	mnt_point_len WFS_USED_ONLY_WITH_MOUNTS,
	is_rw )
	const char * const dev_name;
	wfs_errcode_t * const error;
	char * const mnt_point;
	const size_t mnt_point_len;
	int * const is_rw;
#endif
{
	FILE * mounts_file;
#ifdef WFS_HAVE_IOCTL_LOOP
# ifdef HAVE_STAT64
	struct stat64 s;
# else
	struct stat s;
# endif
	int res;
	int res64;
	int fd;
# ifdef LOOP_GET_STATUS64
	struct loop_info64 li64;
# endif
# ifdef LOOP_GET_STATUS
	struct loop_info li;
# endif
#endif /* WFS_HAVE_IOCTL_LOOP */

	if ( (dev_name == NULL) || (mnt_point == NULL)
		|| (is_rw == NULL) || (mnt_point_len == 0) )
	{
		return WFS_BADPARAM;
	}

	if ( mnt_point_len < WFS_MNTBUFLEN )
	{
		return WFS_MNTCHK;
	}

	mounts_file = fopen (WFS_PATH_MOUNTS, "r");
	if ( mounts_file == NULL )
	{
#ifdef HAVE_ERRNO_H
		if ( error != NULL )
		{
			*error = (wfs_errcode_t)errno;
		}
#endif
		return WFS_MNTCHK;
	}

	while ( fgets (mounts_buffer, sizeof (mounts_buffer) - 1,
		mounts_file) != NULL )
	{
		mounts_buffer[sizeof (mounts_buffer) - 1] = '\0';
		/* sample line:
		/dev/sda1 /boot ext4 rw,seclabel,relatime,barrier=1,data=ordered 0 0
		*/
/* double macros to stringify the constant correctly */
#define WFS_STR(s) #s
#define WFS_SCANF_STRING(LEN) "%" WFS_STR(LEN) "s %" WFS_STR(LEN) "s %*s %" WFS_STR(LEN) "s %*d %*d"

		if ( sscanf (mounts_buffer,
			WFS_SCANF_STRING (WFS_MNTBUFLEN),
			/*"%1000s %1000s %*s %1000s %*d %*d",*/
			mounts_device, mnt_point, mounts_flags) == 3 )
		{
			mounts_device[sizeof (mounts_device) - 1] = '\0';
			mnt_point[mnt_point_len - 1] = '\0';
			mounts_flags[sizeof (mounts_flags) - 1] = '\0';
			if ( strcmp (mounts_device, dev_name) == 0 )
			{
				if ( strstr (mounts_flags, "rw") != NULL )
				{
					if ( error != NULL )
					{
						*error = (wfs_errcode_t)1L;
					}
					*is_rw = 1;
					fclose (mounts_file);
					return WFS_MNTRW;
				}
			}
#ifdef WFS_HAVE_IOCTL_LOOP
			/* check if the device looks like a loop device: */
# ifdef HAVE_STAT64
			res = stat64 (dev_name, &s);
# else
			res = stat (dev_name, &s);
# endif
			if ( ((res >= 0)
					&& (S_ISBLK (s.st_mode))
					&& major (s.st_rdev) == LOOPMAJOR)
				|| (strncmp (mounts_device, "/dev/loop", 9) == 0) )
			{
				/* if so, find out what it's connected to: */
				fd = open (mounts_device, O_RDONLY);
				if ( fd < 0 )
				{
					continue;
				}
# ifdef LOOP_GET_STATUS64
				WFS_MEMSET ( &li64, 0, sizeof (struct loop_info64) );
# endif
# ifdef LOOP_GET_STATUS
				WFS_MEMSET ( &li, 0, sizeof (struct loop_info) );
# endif
				res = -1;
				res64 = -1;
# ifdef LOOP_GET_STATUS64
				res64 = ioctl (fd, LOOP_GET_STATUS64, &li64);
				res = res64;
				if ( res64 < 0 )
# endif
				{
# ifdef LOOP_GET_STATUS
					res = ioctl (fd, LOOP_GET_STATUS, &li);
# endif
				}
				close (fd);
				if ( res < 0 )
				{
					continue;
				}
# ifdef HAVE_STAT64
				res = stat64 (dev_name, &s);
# else
				res = stat (dev_name, &s);
# endif
				if ( res < 0 )
				{
					continue;
				}
				if (
# ifdef LOOP_GET_STATUS64
					((res64 >= 0)
					&& (li64.lo_device == s.st_dev)
					&& (li64.lo_inode == s.st_ino))
#  ifdef LOOP_GET_STATUS
					||
#  endif
# endif
# ifdef LOOP_GET_STATUS
					((res >= 0)
					&& (li.lo_device == s.st_dev)
					&& (li.lo_inode == s.st_ino))
# endif
# if (!defined LOOP_GET_STATUS64) && (!defined LOOP_GET_STATUS)
					0
# endif
					)
				{
					/* The device being checked and the
					   loop back-device are the same object.
					   Check the flags. */
					if ( strstr (mounts_flags, "rw") != NULL )
					{
						if ( error != NULL )
						{
							*error = (wfs_errcode_t)1L;
						}
						*is_rw = 1;
						fclose (mounts_file);
						return WFS_MNTRW;
					}
				}
			}
#endif /* WFS_HAVE_IOCTL_LOOP */
		}
	}
	fclose (mounts_file);

	*is_rw = 0;
	mnt_point[mnt_point_len - 1] = '\0';
	return WFS_SUCCESS;
}

/* ======================================================================== */

#ifdef WFS_HAVE_MNTINFO

# ifndef WFS_ANSIC
static wfs_errcode_t GCC_WARN_UNUSED_RESULT wfs_get_mnt_point_getmntinfo WFS_PARAMS ((
	const char * const dev_name WFS_USED_ONLY_WITH_MOUNTS,
	wfs_errcode_t * const error,
	char * const mnt_point,
	const size_t mnt_point_len WFS_USED_ONLY_WITH_MOUNTS,
	int * const is_rw));
# endif

/**
 * Gets the mount point of the given device (if mounted), using getmntinfo.
 * \param dev_name Device to check.
 * \param error Pointer to error variable.
 * \param mnt_point Array for the mount point.
 * \param mnt_point_len The length of the "mnt_point" array.
 * \param is_rw Pointer to a variable which will tell if the filesystem
 *	is mounted in read+write mode (=1 if yes).
 * \return 0 in case of no errors, other values otherwise.
 */
static wfs_errcode_t GCC_WARN_UNUSED_RESULT
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_get_mnt_point_getmntinfo (
# ifdef WFS_ANSIC
	const char * const dev_name WFS_USED_ONLY_WITH_MOUNTS,
	wfs_errcode_t * const error,
	char * const mnt_point,
	const size_t mnt_point_len WFS_USED_ONLY_WITH_MOUNTS,
	int * const is_rw )
# else
	dev_name WFS_USED_ONLY_WITH_MOUNTS,
	error,
	mnt_point,
	mnt_point_len WFS_USED_ONLY_WITH_MOUNTS,
	is_rw )
	const char * const dev_name;
	wfs_errcode_t * const error;
	char * const mnt_point;
	const size_t mnt_point_len;
	int * const is_rw;
# endif
{
	struct statfs * filesystems = NULL;
	int count;
	int i;

	if ( (dev_name == NULL) || (mnt_point == NULL)
		|| (is_rw == NULL) || (mnt_point_len == 0) )
	{
		return WFS_BADPARAM;
	}

	count = getmntinfo (&filesystems, 0);
	if ( (count <= 0) || (filesystems == NULL) )
	{
		if ( error != NULL )
		{
			*error = (wfs_errcode_t)1L;
		}
		return WFS_MNTCHK;	/* can't check, so don't do anything */
	}
	else
	{
		/* BSD systems have a 'u_int32_t f_flags' in "struct statfs". This
		   field is a copy of the mount flags. */
		for ( i = 0; i < count; i++ )
		{
			if ( (strcmp (dev_name, filesystems[i].f_mntfromname) == 0)
				&& ((filesystems[i].f_flags & MNT_RDONLY) != MNT_RDONLY) )
			{
				if ( error != NULL )
				{
					*error = (wfs_errcode_t)1L;
				}
				*is_rw = 1;
				strncpy (mnt_point, filesystems[i].f_mntonname, mnt_point_len);
				mnt_point[mnt_point_len - 1] = '\0';
				return WFS_MNTRW;
			}
		}
		*is_rw = 0;
		return WFS_SUCCESS;
	}
}
#endif /* WFS_HAVE_MNTENT */

/* ======================================================================== */

/**
 * Gets the mount point of the given device (if mounted).
 * \param dev_name Device to check.
 * \param error Pointer to error variable.
 * \param mnt_point Array for the mount point (must be at least WFS_MNTBUFLEN characters long).
 * \param mnt_point_len The length of the "mnt_point" array.
 * \param is_rw Pointer to a variable which will tell if the filesystem
 *	is mounted in read+write mode (=1 if yes).
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_get_mnt_point (
#ifdef WFS_ANSIC
	const char * const dev_name WFS_USED_ONLY_WITH_MOUNTS,
	wfs_errcode_t * const error,
	char * const mnt_point,
	const size_t mnt_point_len WFS_USED_ONLY_WITH_MOUNTS,
	int * const is_rw )
#else
	dev_name WFS_USED_ONLY_WITH_MOUNTS,
	error,
	mnt_point,
	mnt_point_len WFS_USED_ONLY_WITH_MOUNTS,
	is_rw )
	const char * const dev_name;
	wfs_errcode_t * const error;
	char * const mnt_point;
	const size_t mnt_point_len;
	int * const is_rw;
#endif
{
	wfs_errcode_t ret;

	if ( (dev_name == NULL) || (error == NULL) || (mnt_point == NULL)
		|| (is_rw == NULL) || (mnt_point_len == 0) )
	{
		return WFS_BADPARAM;
	}

	*is_rw = 1;
	mnt_point[0] = '\0';

#ifdef WFS_HAVE_MNTENT
	ret = wfs_get_mnt_point_getmntent (dev_name, error, mnt_point,
		mnt_point_len, is_rw);
	/* don't compare only to WFS_MNTCHK, because if one method failed,
	   other may work */
	if ( (ret != WFS_SUCCESS) && (ret != WFS_MNTCHK) )
	{
		return ret;
	}
#endif /* WFS_HAVE_MNTENT */

#ifdef WFS_HAVE_MNTINFO
	ret = wfs_get_mnt_point_getmntinfo (dev_name, error, mnt_point,
		mnt_point_len, is_rw);
	/* don't compare only to WFS_MNTCHK, because if one method failed,
	   other may work */
	if ( (ret != WFS_SUCCESS) && (ret != WFS_MNTCHK) )
	{
		return ret;
	}
#endif

	ret = wfs_get_mnt_point_mounts (dev_name, error, mnt_point,
		mnt_point_len, is_rw);
	/* don't compare only to WFS_MNTCHK, because if one method failed,
	   other may work */
	if ( (ret != WFS_SUCCESS) && (ret != WFS_MNTCHK) )
	{
		return ret;
	}

	/* at least one test passed, so assume OK */
	*is_rw = 0;
	return WFS_SUCCESS;
}


/* ======================================================================== */

/**
 * Checks if the given filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_check_mounted (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
#endif
{
	wfs_errcode_t res;
	int is_rw;
	char buffer[WFS_MNTBUFLEN+1];

	res = wfs_get_mnt_point (wfs_fs.fsname, wfs_fs.fs_error, buffer,
		sizeof (buffer), &is_rw);
	buffer[WFS_MNTBUFLEN-1] = '\0';
	if ( res != WFS_SUCCESS )
	{
		return res;
	}
	/*
	else if ( is_rw != 0 )
	{
		* impossible to get here right now *
		return WFS_MNTRW;
	}
	*/
	else
	{
		return WFS_SUCCESS;
	}
}

/* ======================================================================== */

/**
 * Checks if the given loop device is assigned a backing device.
 * \param devname Device name, like /dev/loopX
 * \return 1 when loop device is assigned, 0 otherwise.
 */
int GCC_WARN_UNUSED_RESULT
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_check_loop_mounted (
#ifdef WFS_ANSIC
	const char * const dev_name)
#else
	dev_name)
	const char * const dev_name;
#endif
{
#ifdef WFS_HAVE_IOCTL_LOOP
# ifdef HAVE_STAT64
	struct stat64 s;
# else
	struct stat s;
# endif
# ifdef LOOP_GET_STATUS64
	struct loop_info64 li64;
# endif
# ifdef LOOP_GET_STATUS
	struct loop_info li;
# endif
	int res;
	int fd;
#endif /* WFS_HAVE_IOCTL_LOOP */

	if ( dev_name == NULL )
	{
		return 0;
	}
#ifdef WFS_HAVE_IOCTL_LOOP
# ifdef HAVE_STAT64
	res = stat64 (dev_name, &s);
# else
	res = stat (dev_name, &s);
# endif
	if ( ((res >= 0) && (S_ISBLK(s.st_mode)) && (major(s.st_rdev) == LOOPMAJOR))
		|| (strncmp (dev_name, "/dev/loop", 9) == 0) )
	{
		fd = open (dev_name, O_RDONLY);
		if ( fd < 0 )
		{
			return 0;
		}
		if ( lseek (fd, 1, SEEK_SET) < 0 )
		{
			close (fd);
			return 0;
		}
		res = -1;
# ifdef LOOP_GET_STATUS64
		res = ioctl (fd, LOOP_GET_STATUS64, &li64);
		if ( res < 0 )
# endif
		{
# ifdef LOOP_GET_STATUS
			res = ioctl (fd, LOOP_GET_STATUS, &li);
# endif
		}
		close (fd);
		if ( res < 0 )
		{
			return 0;
		}
		return 1;
	}
#endif /* WFS_HAVE_IOCTL_LOOP */
	/* either not a loop device or can't be checked by stat() */
	return 1;
}

/* ======================================================================== */

#ifdef malloc

# define rpl_malloc 1
# if malloc == 1	/* replacement function requested */
#  undef rpl_malloc
#  undef malloc

/* re-declare, because it was #undef'd: */
extern void* malloc WFS_PARAMS ((size_t __size));

/* Replacement malloc() function */
void *
rpl_malloc (
#  ifdef WFS_ANSIC
	size_t n)
#  else
	n)
	size_t n;
#  endif
{
	if (n == 0)
	{
		n = 1;
	}
	return malloc (n);
}
# endif
# undef rpl_malloc
#endif /* malloc */

/* ======================================================================== */

/**
 * Converts the filesystem type (enum) to filesystem name.
 * \param fs The filesystem to convert.
 * \return The filesystem name
 */
const char *
wfs_convert_fs_to_name (
#ifdef WFS_ANSIC
	const wfs_curr_fs_t fs)
#else
	fs)
	const wfs_curr_fs_t fs;
#endif
{
	if ( fs == WFS_CURR_FS_NONE )
	{
		return "<none>";
	}
	else if ( fs == WFS_CURR_FS_EXT234FS )
	{
		return "ext2/3/4";
	}
	else if ( fs == WFS_CURR_FS_NTFS )
	{
		return "NTFS";
	}
	else if ( fs == WFS_CURR_FS_XFS )
	{
		return "XFS";
	}
	else if ( fs == WFS_CURR_FS_REISERFS )
	{
		return "ReiserFSv3";
	}
	else if ( fs == WFS_CURR_FS_REISER4 )
	{
		return "Reiser4";
	}
	else if ( fs == WFS_CURR_FS_FATFS )
	{
		return "FAT12/16/32";
	}
	else if ( fs == WFS_CURR_FS_MINIXFS )
	{
		return "MinixFSv1/2";
	}
	else if ( fs == WFS_CURR_FS_JFS )
	{
		return "JFS";
	}
	else if ( fs == WFS_CURR_FS_HFSP )
	{
		return "HFS+";
	}
	else if ( fs == WFS_CURR_FS_OCFS )
	{
		return "OCFS";
	}
	return "<unknown>";
}

/* ======================================================================== */

/**
 * Re-enables drive cache when the wiping function is about to finish.
 * \param dev_name The name of the device.
 * \param total_fs The total number of filesystems in the ioctls array.
 * \param ioctls The array of filesystems.
 */
wfs_errcode_t
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_enable_drive_cache (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs WFS_USED_ONLY_WITH_IOCTL,
	const int total_fs WFS_USED_ONLY_WITH_IOCTL,
	fs_ioctl_t ioctls[] WFS_USED_ONLY_WITH_IOCTL
	)
#else
	wfs_fs WFS_USED_ONLY_WITH_IOCTL,
	total_fs WFS_USED_ONLY_WITH_IOCTL,
	ioctls WFS_USED_ONLY_WITH_IOCTL
	)
	wfs_fsid_t wfs_fs;
	const int total_fs;
	fs_ioctl_t ioctls[];
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;	/* Value returned */
#ifdef HAVE_IOCTL
	int j;
	int curr_ioctl = -1;
	int ioctl_fd;
	unsigned char hd_cmd[4];
	wfs_errcode_t * error_ret = NULL;

	if ( (ioctls != NULL) && (wfs_fs.fsname != NULL) )
	{
		for ( j = 0; j < total_fs; j++ )
		{
			/* ioctls[j].fs_name can't be NULL, it's an array */
			if ( strncmp (ioctls[j].fs_name, wfs_fs.fsname,
				sizeof (ioctls[j].fs_name) - 1) == 0 )
			{
				curr_ioctl = j;
				break;
			}
		}
		if ( (curr_ioctl >= 0) && (curr_ioctl < total_fs) )
		{
			if ( (ioctls[curr_ioctl].how_many == 0)
				&& (ioctls[curr_ioctl].was_enabled != 0) )
			{
				error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
				ioctl_fd = open (ioctls[curr_ioctl].fs_name,
						 O_RDWR | O_EXCL);
				if ( ioctl_fd >= 0 )
				{
					/* enable cache: */
					hd_cmd[0] = 0xef;	/* ATA_OP_SETFEATURES */
					hd_cmd[1] = 0;
					hd_cmd[2] = 0x02;
					hd_cmd[3] = 0;
					j = ioctl (ioctl_fd, HDIO_DRIVE_CMD, hd_cmd);
					if ( j != 0 )
					{
# ifdef HAVE_ERRNO_H
						if ( error_ret != NULL )
						{
							*error_ret = (wfs_errcode_t)errno;
						}
# endif
						ret = WFS_IOCTL;
					}
					else
					{
						ioctls[curr_ioctl].how_many--;
					}
					close (ioctl_fd);
				}
				else
				{
# ifdef HAVE_ERRNO_H
					if ( error_ret != NULL )
					{
						*error_ret = (wfs_errcode_t)errno;
					}
# endif
					ret = WFS_OPENFS;
				}
			}
		}
		else
		{
			ret = WFS_BADPARAM;
		}
	}
	else
	{
		ret = WFS_BADPARAM;
	}
#endif
	return ret;
}

/* ======================================================================== */

/**
 * Disables drive cache when the wiping function is about to finish.
 * \param dev_name The name of the device.
 * \param total_fs The total number of filesystems in the ioctls array.
 * \param ioctls The array of filesystems.
 */
wfs_errcode_t
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_disable_drive_cache (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs WFS_USED_ONLY_WITH_IOCTL,
	const int total_fs WFS_USED_ONLY_WITH_IOCTL,
	fs_ioctl_t ioctls[] WFS_USED_ONLY_WITH_IOCTL
	)
#else
	wfs_fs WFS_USED_ONLY_WITH_IOCTL,
	total_fs WFS_USED_ONLY_WITH_IOCTL,
	ioctls WFS_USED_ONLY_WITH_IOCTL
	)
	wfs_fsid_t wfs_fs;
	const int total_fs;
	fs_ioctl_t ioctls[];
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;	/* Value returned */
#ifdef HAVE_IOCTL
	int j;
	int curr_ioctl = -1;
	int ioctl_fd;
	unsigned char hd_cmd[4];
	wfs_errcode_t * error_ret = NULL;

	if ( (ioctls != NULL) && (wfs_fs.fsname != NULL) )
	{
		for ( j = 0; j < total_fs; j++ )
		{
			if ( strncmp (ioctls[j].fs_name, wfs_fs.fsname,
				sizeof (ioctls[j].fs_name) - 1) == 0 )
			{
				curr_ioctl = j;
				break;
			}
		}
		if ( (curr_ioctl >= 0) && (curr_ioctl < total_fs) )
		{
			error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
			ioctl_fd = open (ioctls[curr_ioctl].fs_name,
				O_RDWR | O_EXCL);
			if ( ioctl_fd >= 0 )
			{
				ioctls[curr_ioctl].was_enabled = 0;
				/* check if caching was enabled */
				ioctl (ioctl_fd, HDIO_GET_WCACHE,
					&ioctls[curr_ioctl].was_enabled);
				/* flush the drive's caches: */
				hd_cmd[0] = 0xe7;	/* ATA_OP_FLUSHCACHE */
				hd_cmd[1] = 0;
				hd_cmd[2] = 0;
				hd_cmd[3] = 0;
				ioctl (ioctl_fd, HDIO_DRIVE_CMD, hd_cmd);
				hd_cmd[0] = 0xea;	/* ATA_OP_FLUSHCACHE_EXT */
				hd_cmd[1] = 0;
				hd_cmd[2] = 0;
				hd_cmd[3] = 0;
				ioctl (ioctl_fd, HDIO_DRIVE_CMD, hd_cmd);
				/* disable cache: */
				hd_cmd[0] = 0xef;	/* ATA_OP_SETFEATURES */
				hd_cmd[1] = 0;
				hd_cmd[2] = 0x82;
				hd_cmd[3] = 0;
				j = ioctl (ioctl_fd, HDIO_DRIVE_CMD, hd_cmd);
				if ( j != 0 )
				{
# ifdef HAVE_ERRNO_H
					if ( error_ret != NULL )
					{
						*error_ret = (wfs_errcode_t)errno;
					}
# endif
					ret = WFS_IOCTL;
				}
				else
				{
					ioctls[curr_ioctl].how_many++;
				}
				close (ioctl_fd);
			}
			else
			{
# ifdef HAVE_ERRNO_H
				if ( error_ret != NULL )
				{
					*error_ret = (wfs_errcode_t)errno;
				}
# endif
				ret = WFS_OPENFS;
			}
		}
		else
		{
			ret = WFS_BADPARAM;
		}
	}
	else
	{
		ret = WFS_BADPARAM;
	}
#endif
	return ret;
}

/* ======================================================================== */

/**
 * Displays an error message.
 * \param msg The message.
 * \param extra Last element of the error message (fsname or signal).
 * \param wfs_fs The filesystem this message refers to.
 */
void
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_show_fs_error_gen (
#ifdef WFS_ANSIC
	const char * const	msg,
	const char * const	extra,
	const wfs_fsid_t	wfs_fs )
#else
	msg, extra, wfs_fs )
	const char * const	msg;
	const char * const	extra;
	const wfs_fsid_t	wfs_fs;
#endif
{
	wfs_errcode_t err = 0;
	const char * progname;

	if ( (wfs_is_stderr_open() == 0) || (msg == NULL) )
	{
		return;
	}
	if ( wfs_fs.fs_error != NULL )
	{
		err = *(wfs_errcode_t *)(wfs_fs.fs_error);
	}

	progname = wfs_get_program_name();
	fprintf (stderr, "%s:%s: %s " WFS_ERR_MSG_FORMAT "\n",
		(progname != NULL)? progname : "",
		(wfs_fs.fsname != NULL)? wfs_fs.fsname : "",
		_(wfs_err_msg),
		_(wfs_err_msg),
		err,
		_(msg),
		(extra != NULL)? extra : "",
		(wfs_fs.fsname != NULL)? wfs_fs.fsname : "");
	fflush (stderr);
}

/* ======================================================================== */

/**
 * Check if the given buffer has only bytes with the value zero.
 * \param buf The buffer to check.
 * \param length The length of the buffer.
 * \return 1 if this block has only bytes with the value zero.
 */
int GCC_WARN_UNUSED_RESULT
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_is_block_zero (
#ifdef WFS_ANSIC
	const unsigned char * const	buf,
	const size_t			len )
#else
	buf, len )
	const unsigned char * const	buf;
	const size_t			len;
#endif
{
	size_t i;

	if ( (buf == NULL) || (len == 0) )
	{
		return 0;
	}

	for ( i = 0; i < len; i++ )
	{
		if ( buf[i] != '\0' )
		{
			return 0;
		}
	}
	return 1;
}

/* ======================================================================== */

/**
 * Reads the given file descriptor until end of data is reached.
 * @param fd The file descriptor to empty.
 */
void
wfs_flush_pipe_input (
#ifdef WFS_ANSIC
	const int fd)
#else
	fd )
	const int fd;
#endif
{
	char c;
	ssize_t br;
	/* set non-blocking mode to quit as soon as the pipe is empty */
#ifdef HAVE_FCNTL_H
	int r;
	r = fcntl (fd, F_SETFL, fcntl (fd, F_GETFL) | O_NONBLOCK );
	if ( r != 0 )
	{
		return;
	}
#endif
	do
	{
		br = read (fd, &c, 1);
	} while (br == 1);
	/* set blocking mode again */
#ifdef HAVE_FCNTL_H
	fcntl (fd, F_SETFL, fcntl (fd, F_GETFL) & ~ O_NONBLOCK );
#endif
}

/* ======================================================================== */

/**
 * Makes a deep copy of the given array.
 * @param array The array to copy.
 * @param len The length of the array.
 * @return a new deep copy of the given array.
 */
char **
wfs_deep_copy_array (
#ifdef WFS_ANSIC
	const char * const * const array, const unsigned int len)
#else
	array, len )
	const char * const * const array;
	const unsigned int len;
#endif
{
	unsigned int i;
	char ** new_arr;

	if ( (array == NULL) || (len == 0) )
	{
		return NULL;
	}

	new_arr = (char **) malloc ( len * sizeof (char *) );
	if ( new_arr == NULL )
	{
		return NULL;
	}
	for ( i = 0; i < len; i++ )
	{
		if ( array[i] == NULL )
		{
			new_arr[i] = NULL;
			continue;
		}
		new_arr[i] = WFS_STRDUP (array[i]);
		if ( new_arr[i] == NULL )
		{
			/* free only as many as set */
			wfs_free_array_deep_copy (new_arr, i);
			return NULL;
		}
	}
	return new_arr;
}

/* ======================================================================== */

/**
 * Frees a deep copy of an array.
 * @param array The array to free.
 * @param len The length of the array.
 */
void
wfs_free_array_deep_copy (
#ifdef WFS_ANSIC
	char * array[], const unsigned int len)
#else
	array, len )
	char * array[];
	const unsigned int len;
#endif
{
	unsigned int i;

	if ( array == NULL )
	{
		return;
	}
	for ( i = 0; i < len; i++ )
	{
		if ( array[i] != NULL )
		{
			free (array[i]);
		}
	}
	free (array);
}

/* =============================================================== */

#ifndef HAVE_STRDUP
char * wfs_duplicate_string (
# ifdef WFS_ANSIC
	const char src[])
# else
	src)
	const char src[];
# endif
{
	size_t len;
	char * dest;

	if ( src == NULL )
	{
		return NULL;
	}
	len = strlen (src);
	if ( len == 0 )
	{
		return NULL;
	}
	dest = (char *) malloc (len + 1);
	if ( dest == NULL )
	{
		return NULL;
	}
# ifdef HAVE_STRING_H
	strncpy (dest, src, len);
# else
	WFS_MEMCOPY (dest, src, len);
# endif
	dest[len] = '\0';
	return dest;
}
#endif /* ! HAVE_STRDUP */

/* =============================================================== */

#ifndef HAVE_MEMCPY
void wfs_memcopy (
# ifdef WFS_ANSIC
	void * const dest, const void * const src, const size_t len)
# else
	dest, src, len)
	void * const dest;
	const void * const src;
	const size_t len;
# endif
{
	size_t i;
	char * const d = (char *)dest;
	const char * const s = (const char *)src;

	if ( (d != NULL) && (s != NULL) )
	{
		for ( i = 0; i < len; i++ )
		{
			d[i] = s[i];
		}
	}
}
#endif

/* =============================================================== */

#ifndef HAVE_MEMSET
void wfs_mem_set (
# ifdef WFS_ANSIC
	void * const dest, const char value, const size_t len)
# else
	dest, value, len)
	void * const dest;
	const char value;
	const size_t len;
# endif
{
	size_t i;
	if ( dest != NULL )
	{
		for ( i = 0; i < len; i++ )
		{
			((char *)dest)[i] = value;
		}
	}
}
#endif
