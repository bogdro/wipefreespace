/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- mount-checking functions.
 *
 * Copyright (C) 2024 Bogdan Drozdowski, bogdro (at) users.sourceforge.net
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

#ifdef HAVE_LOOP_H
# include <loop.h>
#else
# ifdef HAVE_LINUX_LOOP_H
#  include <linux/loop.h>
# endif
#endif

#include "wipefreespace.h"
#include "wfs_util.h"
#include "wfs_mount_check.h"

#ifndef MNTOPT_RW
# define MNTOPT_RW	"rw"
#endif

#ifndef LOOPMAJOR
# define LOOPMAJOR	7
#endif

#ifdef WFS_HAVE_MNTENT
# undef WFS_HAVE_MNTENT
#endif

#if (defined HAVE_MNTENT_H) && ((defined HAVE_GETMNTENT) || (defined HAVE_GETMNTENT_R))
# define WFS_HAVE_MNTENT 1
#endif

#ifdef WFS_HAVE_MNTINFO
# undef WFS_HAVE_MNTINFO
#endif

#if (defined HAVE_SYS_MOUNT_H) && (defined HAVE_GETMNTINFO)
# define WFS_HAVE_MNTINFO 1
#endif

#if !( (defined WFS_HAVE_MNTENT) || (defined WFS_HAVE_MNTINFO) )
# define WFS_USED_ONLY_WITH_MOUNTS WFS_ATTR ((unused))
#else
# define WFS_USED_ONLY_WITH_MOUNTS
#endif

#ifdef WFS_HAVE_IOCTL_LOOP
# undef WFS_HAVE_IOCTL_LOOP
#endif

#if (defined HAVE_FCNTL_H) && (defined HAVE_SYS_IOCTL_H) \
	&& (defined HAVE_IOCTL) && (defined HAVE_SYS_STAT_H) \
	&& ((defined HAVE_LOOP_H) || (defined HAVE_LINUX_LOOP_H))
# define WFS_HAVE_IOCTL_LOOP 1
# define WFS_USED_ONLY_WITH_LOOP WFS_ATTR ((unused))
#else
# define WFS_USED_ONLY_WITH_LOOP
#endif

#if (defined TEST_COMPILE) && (defined WFS_ANSIC)
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
	const struct mntent *mnt;
	struct mntent mnt_copy;
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
