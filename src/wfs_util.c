/*
 * A program for secure cleaning of free space on filesystems.
 *	-- utility functions.
 *
 * Copyright (C) 2007-2008 Bogdan Drozdowski, bogdandr (at) op.pl
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

#include "wfs_cfg.h"

#ifdef HAVE_GETMNTENT_R
	/* getmntent_r() */
# define _GNU_SOURCE	1
#endif

#include <stdio.h>	/* FILE */

#ifdef HAVE_STRING_H
# if ((!defined STDC_HEADERS) || (!STDC_HEADERS)) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>	/* strncpy() */
#endif

#ifdef HAVE_MNTENT_H
# include <mntent.h>
#endif

#ifdef HAVE_PATHS_H
# include <paths.h>
#endif

#ifndef _PATH_DEVNULL
# define	_PATH_DEVNULL	"/dev/null"
#endif

#ifndef _PATH_MOUNTED
# ifdef MNT_MNTTAB
#  define	_PATH_MOUNTED	MNT_MNTTAB
# else
#  define	_PATH_MOUNTED	"/etc/mtab"
# endif
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#include "wipefreespace.h"
#include "wfs_util.h"

#ifndef MNTOPT_RW
# define MNTOPT_RW	"rw"
#endif
#define MNTBUFLEN 4096


/**
 * Gets the mount point of the given device (if mounted).
 * \param dev_name Device to check.
 * \param error Pointer to error variable.
 * \param mnt_point Array for the mount point.
 * \param is_rw Pointer to a variavle which will tell if the filesystem
 *	is mounted in read+write mode (=1 if yes).
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_get_mnt_point (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char * const dev_name
# if !((defined HAVE_MNTENT_H) && ((defined HAVE_GETMNTENT) || (defined HAVE_GETMNTENT_R)))
	WFS_ATTR ((unused))
# endif
	, error_type * const error,
	char * const mnt_point, int * const is_rw )
#else
	dev_name
# if !((defined HAVE_MNTENT_H) && ((defined HAVE_GETMNTENT) || (defined HAVE_GETMNTENT_R)))
	WFS_ATTR ((unused))
# endif
	, error, mnt_point, is_rw )
	const char * const dev_name;
	error_type * const error;
	char * const mnt_point;
	int * const is_rw;
#endif
{
#if (defined HAVE_MNTENT_H) && ((defined HAVE_GETMNTENT) || (defined HAVE_GETMNTENT_R))
	FILE *mnt_f;
	struct mntent *mnt, mnt_copy;
# ifdef HAVE_GETMNTENT_R
	char buffer[MNTBUFLEN];
# endif
#endif
/*
	if ( (dev_name == NULL) || (error == NULL) || (mnt_point == NULL) || (is_rw == NULL) )
		return WFS_BADPARAM;
*/
	*is_rw = 1;
	strcpy (mnt_point, "");

#if (defined HAVE_MNTENT_H) && ((defined HAVE_GETMNTENT) || (defined HAVE_GETMNTENT_R))
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	mnt_f = setmntent (_PATH_MOUNTED, "r");
	if (mnt_f == NULL)
	{
# ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
# endif
		return WFS_MNTCHK;
	}
	do
	{
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
# ifndef HAVE_GETMNTENT_R
		mnt = getmntent (mnt_f);
		memcpy ( &mnt_copy, mnt, sizeof (struct mntent) );
# else
		mnt = getmntent_r (mnt_f, &mnt_copy, buffer, MNTBUFLEN);
# endif
		if ( mnt == NULL ) break;
		if ( strcmp (dev_name, mnt->mnt_fsname) == 0 ) break;

	} while ( 1==1 );

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
# ifdef HAVE_HASMNTOPT
	if (hasmntopt (mnt, MNTOPT_RW) != NULL)
	{
		error->errcode.gerror = 1L;
		*is_rw = 1;
		strcpy (mnt_point, mnt->mnt_dir);
		return WFS_MNTRW;
	}
# else
	error->errcode.gerror = 1L;
	*is_rw = 1;
	strcpy (mnt_point, mnt->mnt_dir);
	return WFS_MNTRW;	/* can't check for r/w, so don't do anything */
# endif
	*is_rw = 0;
	strcpy (mnt_point, mnt->mnt_dir);
	return WFS_SUCCESS;
#else	/* ! HAVE_MNTENT_H */
	error->errcode.gerror = 1L;
	return WFS_MNTCHK;	/* can't check, so don't do anything */
#endif	/* HAVE_MNTENT_H */
}


/**
 * Checks if the given XFS filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_check_mounted (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char * const dev_name, error_type * const error )
#else
	dev_name, error )
	const char * const dev_name;
	error_type * const error;
#endif
{
	errcode_enum res;
	int is_rw;
	char buffer[MNTBUFLEN];

	if ( error == NULL )
	{
		return WFS_BADPARAM;
	}

	res = wfs_get_mnt_point (dev_name, error, buffer, &is_rw);
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
