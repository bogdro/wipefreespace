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

#include "wipefreespace.h"
#include "wfs_util.h"

#ifndef HAVE_IOCTL
# define WFS_USED_ONLY_WITH_IOCTL WFS_ATTR ((unused))
#else
# define WFS_USED_ONLY_WITH_IOCTL
#endif

#ifdef TEST_COMPILE
# undef WFS_ANSIC
#endif

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

/* ======================================================================== */

#ifndef HAVE_STRCASECMP

# define WFS_TOUPPER(c) ((char)( ((c) >= 'a' && (c) <= 'z')? ((c) & 0x5F) : (c) ))

/**
 * Compares the given strings case-insensitively.
 * \param string1 The first string.
 * \param string2 The second string.
 * \return 0 if the strings are equal, -1 is string1 is "less" than string2 and 1 otherwise.
 */
int
wfs_compare (
# ifdef WFS_ANSIC
	const char string1[], const char string2[])
# else
	string1, string2)
	const char string1[];
	const char string2[];
# endif
{
	size_t i, len1, len2;
	char c1, c2;

	if ( (string1 == NULL) && (string2 == NULL) )
	{
		return 0;
	}
	else if ( string1 == NULL )
	{
		return -1;
	}
	else if ( string2 == NULL )
	{
		return 1;
	}
	else
	{
		/* both strings not-null */
		len1 = strlen (string1);
		len2 = strlen (string2);
		if ( len1 < len2 )
		{
			return -1;
		}
		else if ( len1 > len2 )
		{
			return 1;
		}
		else
		{
			/* both lengths equal */
			for ( i = 0; i < len1; i++ )
			{
				c1 = WFS_TOUPPER (string1[i]);
				c2 = WFS_TOUPPER (string2[i]);
				if ( c1 < c2 )
				{
					return -1;
				}
				else if ( c1 > c2 )
				{
					return 1;
				}
			}
		}
	}
	return 0;
}
#endif /* HAVE_STRCASECMP */
