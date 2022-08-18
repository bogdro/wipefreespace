/*
 * A program for secure cleaning of free space on filesystems.
 *	-- wrapper functions.
 *
 * Copyright (C) 2007-2012 Bogdan Drozdowski, bogdandr (at) op.pl
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

#include <stdio.h>	/* NULL and others */

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* sync() */
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>	/* EIO */
#endif

/* redefine the inline sig function from hfsp, each time with a different name */
extern unsigned long int wfs_wrap_sig(char c0, char c1, char c2, char c3);
#define sig(a,b,c,d) wfs_wrap_sig(a,b,c,d)

#include "wipefreespace.h"
#include "wfs_wrappers.h"

#ifdef WFS_EXT234
# include "wfs_ext234.h"
#endif

#ifdef WFS_NTFS
# include "wfs_ntfs.h"
#endif

#ifdef WFS_XFS
# include "wfs_xfs.h"
#endif

#ifdef WFS_REISER
# include "wfs_reiser.h"
#endif

#ifdef WFS_REISER4
# include "wfs_reiser4.h"
#endif

#ifdef WFS_FATFS
# include "wfs_fat.h"
#endif

#ifdef WFS_MINIXFS
# include "wfs_minixfs.h"
#endif

#ifdef WFS_JFS
# include "wfs_jfs.h"
#endif

#ifdef WFS_HFSP
# include "wfs_hfsp.h"
#endif

#ifdef WFS_OCFS
# include "wfs_ocfs.h"
#endif

/* ======================================================================== */

#ifdef WFS_WANT_UNRM
/**
 * Starts recursive directory search for deleted inodes and undelete data.
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wipe_unrm (
# ifdef WFS_ANSIC
	wfs_fsid_t FS, const wfs_curr_fs_t which_fs, wfs_error_type_t * const error )
# else
	FS, which_fs, error )
	wfs_fsid_t FS;
	const wfs_curr_fs_t which_fs;
	wfs_error_type_t * const error;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
# if (defined WFS_EXT234) || (defined WFS_REISER) \
	|| (defined WFS_NTFS) || (defined WFS_REISER4) \
	|| (defined WFS_MINIXFS) || (defined WFS_HFSP)
	wfs_fselem_t elem;
# endif

	if ( which_fs == CURR_EXT234FS )
	{
# ifdef WFS_EXT234
		elem.e2elem = EXT2_ROOT_INO;
		ret_wfs = wfs_e234_wipe_unrm (FS, elem, error);
# endif
	}
	else if ( which_fs == CURR_NTFS )
	{
# ifdef WFS_NTFS
		elem.ntfselem = NULL; /* unused anyway */
		ret_wfs = wfs_ntfs_wipe_unrm (FS, elem, error);
# endif
	}
	else if ( which_fs == CURR_XFS )
	{
# ifdef WFS_XFS
		ret_wfs = wfs_xfs_wipe_unrm (FS);
# endif
	}
	else if ( which_fs == CURR_REISERFS )
	{
# ifdef WFS_REISER
		elem.rfs_elem = root_dir_key;
		ret_wfs = wfs_reiser_wipe_unrm (FS, elem, error);
# endif
	}
	else if ( which_fs == CURR_REISER4 )
	{
# ifdef WFS_REISER4
		if ( FS.r4 != NULL )
		{
			if ( FS.r4->tree == NULL )
			{
				elem.r4node = NULL;
			}
			else
			{
				elem.r4node = FS.r4->tree->root;
			}
		}
		else
		{
			elem.r4node = NULL;
		}
		ret_wfs = wfs_r4_wipe_unrm (FS, elem, error);
# endif
	}
	else if ( which_fs == CURR_FATFS )
	{
# ifdef WFS_FATFS
		ret_wfs = wfs_fat_wipe_unrm (FS, error);
# endif
	}
	else if ( which_fs == CURR_MINIXFS )
	{
# ifdef WFS_MINIXFS
		elem.minix_ino = MINIX_ROOT_INO;
		ret_wfs = wfs_minixfs_wipe_unrm (FS, error);
# endif
	}
	else if ( which_fs == CURR_JFS )
	{
# ifdef WFS_JFS
		ret_wfs = wfs_jfs_wipe_unrm (FS, error);
# endif
	}
	else if ( which_fs == CURR_HFSP )
	{
# ifdef WFS_HFSP
		record_init_cnid (&(elem.hfsp_dirent), &(FS.hfsp_volume.catalog), HFSP_ROOT_CNID);
		ret_wfs = wfs_hfsp_wipe_unrm (FS, elem, error);
# endif
	}
	else if ( which_fs == CURR_OCFS )
	{
# ifdef WFS_OCFS
		ret_wfs = wfs_ocfs_wipe_unrm (FS, error);
# endif
	}

	if ( (ret_wfs != WFS_SUCCESS) && (error->errcode.gerror == 0) )
	{
# ifdef HAVE_ERRNO_H
		error->errcode.gerror = EIO;
# else
		error->errcode.gerror = 5L;	/* EIO */
# endif
	}
	return ret_wfs;
}
#endif /* WFS_WANT_UNRM */

#ifdef WFS_WANT_WFS
/**
 * Wipes the free space on the given filesystem.
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wipe_fs (
# ifdef WFS_ANSIC
	wfs_fsid_t FS, const wfs_curr_fs_t which_fs, wfs_error_type_t * const error )
# else
	FS, which_fs, error )
	wfs_fsid_t FS;
	const wfs_curr_fs_t which_fs;
	wfs_error_type_t * const error;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;

	if ( which_fs == CURR_EXT234FS )
	{
# ifdef WFS_EXT234
		ret_wfs = wfs_e234_wipe_fs (FS, error);
# endif
	}
	else if ( which_fs == CURR_NTFS )
	{
# ifdef WFS_NTFS
		ret_wfs = wfs_ntfs_wipe_fs (FS, error);
# endif
	}
	else if ( which_fs == CURR_XFS )
	{
# ifdef WFS_XFS
		ret_wfs = wfs_xfs_wipe_fs (FS, error);
# endif
	}
	else if ( which_fs == CURR_REISERFS )
	{
# ifdef WFS_REISER
		ret_wfs = wfs_reiser_wipe_fs (FS, error);
# endif
	}
	else if ( which_fs == CURR_REISER4 )
	{
# ifdef WFS_REISER4
		ret_wfs = wfs_r4_wipe_fs (FS, error);
# endif
	}
	else if ( which_fs == CURR_FATFS )
	{
# ifdef WFS_FATFS
		ret_wfs = wfs_fat_wipe_fs (FS, error);
# endif
	}
	else if ( which_fs == CURR_MINIXFS )
	{
# ifdef WFS_MINIXFS
		ret_wfs = wfs_minixfs_wipe_fs (FS, error);
# endif
	}
	else if ( which_fs == CURR_JFS )
	{
# ifdef WFS_JFS
		ret_wfs = wfs_jfs_wipe_fs (FS, error);
# endif
	}
	else if ( which_fs == CURR_HFSP )
	{
# ifdef WFS_HFSP
		ret_wfs = wfs_hfsp_wipe_fs (FS, error);
# endif
	}
	else if ( which_fs == CURR_OCFS )
	{
# ifdef WFS_OCFS
		ret_wfs = wfs_ocfs_wipe_fs (FS, error);
# endif
	}

	if ( (ret_wfs != WFS_SUCCESS) && (error->errcode.gerror == 0) )
	{
# ifdef HAVE_ERRNO_H
		error->errcode.gerror = EIO;
# else
		error->errcode.gerror = 5L;	/* EIO */
# endif
	}
	return ret_wfs;
}
#endif /* WFS_WANT_WFS */

#ifdef WFS_WANT_PART
/**
 * Wipes the free space in partially used blocks on the given filesystem.
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wipe_part (
# ifdef WFS_ANSIC
	const wfs_fsid_t FS, const wfs_curr_fs_t which_fs, wfs_error_type_t * const error )
# else
	FS, which_fs, error )
	const wfs_fsid_t FS;
	const wfs_curr_fs_t which_fs;
	wfs_error_type_t * const error;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;

	if ( which_fs == CURR_EXT234FS )
	{
# ifdef WFS_EXT234
		ret_wfs = wfs_e234_wipe_part (FS, error);
# endif
	}
	else if ( which_fs == CURR_NTFS )
	{
# ifdef WFS_NTFS
		ret_wfs = wfs_ntfs_wipe_part (FS, error);
# endif
	}
	else if ( which_fs == CURR_XFS )
	{
# ifdef WFS_XFS
		ret_wfs = wfs_xfs_wipe_part (FS, error);
# endif
	}
	else if ( which_fs == CURR_REISERFS )
	{
# ifdef WFS_REISER
		ret_wfs = wfs_reiser_wipe_part (FS, error);
# endif
	}
	else if ( which_fs == CURR_REISER4 )
	{
# ifdef WFS_REISER4
		ret_wfs = wfs_r4_wipe_part (FS, error);
# endif
	}
	else if ( which_fs == CURR_FATFS )
	{
# ifdef WFS_FATFS
		ret_wfs = wfs_fat_wipe_part (FS, error);
# endif
	}
	else if ( which_fs == CURR_MINIXFS )
	{
# ifdef WFS_MINIXFS
		ret_wfs = wfs_minixfs_wipe_part (FS, error);
# endif
	}
	else if ( which_fs == CURR_JFS )
	{
# ifdef WFS_JFS
		ret_wfs = wfs_jfs_wipe_part (FS, error);
# endif
	}
	else if ( which_fs == CURR_HFSP )
	{
# ifdef WFS_HFSP
		ret_wfs = wfs_hfsp_wipe_part (FS, error);
# endif
	}
	else if ( which_fs == CURR_OCFS )
	{
# ifdef WFS_OCFS
		ret_wfs = wfs_ocfs_wipe_part (FS, error);
# endif
	}

	if ( (ret_wfs != WFS_SUCCESS) && (error->errcode.gerror == 0) )
	{
# ifdef HAVE_ERRNO_H
		error->errcode.gerror = EIO;
# else
		error->errcode.gerror = 5L;	/* EIO */
# endif
	}
	return ret_wfs;
}
#endif /* WFS_WANT_PART */

/**
 * Opens a filesystem on the given device.
 * \param devname Device name, like /dev/hdXY
 * \param FS Pointer to where the result will be put.
 * \param whichfs Pointer to an int saying which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_open_fs (
#ifdef WFS_ANSIC
	const char * const dev_name, wfs_fsid_t * const FS, wfs_curr_fs_t * const which_fs,
	const wfs_fsdata_t * const data, wfs_error_type_t * const error )
#else
	dev_name, FS, which_fs, data, error )
	const char * const dev_name;
	wfs_fsid_t * const FS;
	wfs_curr_fs_t * const which_fs;
	const wfs_fsdata_t * const data;
	wfs_error_type_t * const error;
#endif
{
	wfs_errcode_t ret_wfs = WFS_OPENFS;
	*which_fs = CURR_NONE;
#ifdef WFS_EXT234
	ret_wfs = wfs_e234_open_fs (dev_name, FS, which_fs, data, error);
#endif
#ifdef WFS_NTFS
	if ( ret_wfs != WFS_SUCCESS )
	{
		error->errcode.gerror = WFS_SUCCESS;
		ret_wfs = wfs_ntfs_open_fs (dev_name, FS, which_fs, data, error);
	}
#endif
#ifdef WFS_REISER4
	if ( ret_wfs != WFS_SUCCESS )
	{
		error->errcode.gerror = WFS_SUCCESS;
		ret_wfs = wfs_r4_open_fs (dev_name, FS, which_fs, data, error);
	}
#endif
#ifdef WFS_XFS
	if ( ret_wfs != WFS_SUCCESS )
	{
		error->errcode.gerror = WFS_SUCCESS;
		ret_wfs = wfs_xfs_open_fs (dev_name, FS, which_fs, data, error);
	}
#endif
/* JFS before ReiserFSv3 */
#ifdef WFS_JFS
	if ( ret_wfs != WFS_SUCCESS )
	{
		error->errcode.gerror = WFS_SUCCESS;
		ret_wfs = wfs_jfs_open_fs (dev_name, FS, which_fs, data, error);
	}
#endif
/* FAT is probably the least specific in its header - the TFFS library can detect
   XFS and ReiserFS3/4 as FAT, which is bad. But now we have more advanced checks
   than simply using TFFS, so this can be before ReiserFSv3. */
#ifdef WFS_FATFS
	if ( ret_wfs != WFS_SUCCESS )
	{
		error->errcode.gerror = WFS_SUCCESS;
		ret_wfs = wfs_fat_open_fs (dev_name, FS, which_fs, data, error);
	}
#endif
#ifdef WFS_MINIXFS
	if ( ret_wfs != WFS_SUCCESS )
	{
		error->errcode.gerror = WFS_SUCCESS;
		ret_wfs = wfs_minixfs_open_fs (dev_name, FS, which_fs, data, error);
	}
#endif
#ifdef WFS_REISER
	if ( ret_wfs != WFS_SUCCESS )
	{
		error->errcode.gerror = WFS_SUCCESS;
		ret_wfs = wfs_reiser_open_fs (dev_name, FS, which_fs, data, error);
	}
#endif
#ifdef WFS_HFSP
	if ( ret_wfs != WFS_SUCCESS )
	{
		error->errcode.gerror = WFS_SUCCESS;
		ret_wfs = wfs_hfsp_open_fs (dev_name, FS, which_fs, data, error);
	}
#endif
#ifdef WFS_OCFS
	if ( ret_wfs != WFS_SUCCESS )
	{
		error->errcode.gerror = WFS_SUCCESS;
		ret_wfs = wfs_ocfs_open_fs (dev_name, FS, which_fs, data, error);
	}
#endif

	if ( (ret_wfs != WFS_SUCCESS) && (error->errcode.gerror == 0) )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = EINVAL;
#else
		error->errcode.gerror = 22L;
#endif
	}

	return ret_wfs;
}

/**
 * Checks if the given device is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_chk_mount (
#ifdef WFS_ANSIC
	const char * const dev_name, wfs_error_type_t * const error )
#else
	dev_name, error )
	const char * const dev_name;
	wfs_error_type_t * const error;
#endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;

#ifdef WFS_EXT234
	ret_wfs = wfs_e234_chk_mount ( dev_name, error );
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif
#if (defined WFS_NTFS)
	ret_wfs = wfs_ntfs_chk_mount ( dev_name, error );
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif
#if (defined WFS_XFS)
	ret_wfs = wfs_xfs_chk_mount ( dev_name, error );
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif
#if (defined WFS_REISER)
	ret_wfs = wfs_reiser_chk_mount ( dev_name, error );
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif
#if (defined WFS_REISER4)
	ret_wfs = wfs_r4_chk_mount ( dev_name, error );
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif
#if (defined WFS_FATFS)
	ret_wfs = wfs_fat_chk_mount ( dev_name, error );
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif
#if (defined WFS_MINIXFS)
	ret_wfs = wfs_minixfs_chk_mount ( dev_name, error );
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif
#if (defined WFS_JFS)
	ret_wfs = wfs_jfs_chk_mount ( dev_name, error );
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif
#if (defined WFS_HFSP)
	ret_wfs = wfs_hfsp_chk_mount ( dev_name, error );
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif
#if (defined WFS_OCFS)
	ret_wfs = wfs_ocfs_chk_mount ( dev_name, error );
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif

	return ret_wfs;
}

/**
 * Closes the filesystem.
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_close_fs (
#ifdef WFS_ANSIC
	const wfs_fsid_t FS, const wfs_curr_fs_t which_fs, wfs_error_type_t * const error )
#else
	FS, which_fs, error )
	const wfs_fsid_t FS;
	const wfs_curr_fs_t which_fs;
	wfs_error_type_t * const error;
#endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;

	if ( which_fs == CURR_EXT234FS )
	{
#ifdef WFS_EXT234
		ret_wfs = wfs_e234_close_fs (FS, error);
#endif
	}
	else if ( which_fs == CURR_NTFS )
	{
#ifdef WFS_NTFS
		ret_wfs = wfs_ntfs_close_fs (FS, error);
#endif
	}
	else if ( which_fs == CURR_XFS )
	{
#ifdef WFS_XFS
		ret_wfs = wfs_xfs_close_fs (FS, error);
#endif
	}
	else if ( which_fs == CURR_REISERFS )
	{
#ifdef WFS_REISER
		ret_wfs = wfs_reiser_close_fs (FS, error);
#endif
	}
	else if ( which_fs == CURR_REISER4 )
	{
#ifdef WFS_REISER4
		ret_wfs = wfs_r4_close_fs (FS, error);
#endif
	}
	else if ( which_fs == CURR_FATFS )
	{
#ifdef WFS_FATFS
		ret_wfs = wfs_fat_close_fs (FS, error);
#endif
	}
	else if ( which_fs == CURR_MINIXFS )
	{
#ifdef WFS_MINIXFS
		ret_wfs = wfs_minixfs_close_fs (FS, error);
#endif
	}
	else if ( which_fs == CURR_JFS )
	{
#ifdef WFS_JFS
		ret_wfs = wfs_jfs_close_fs (FS, error);
#endif
	}
	else if ( which_fs == CURR_HFSP )
	{
#ifdef WFS_HFSP
		ret_wfs = wfs_hfsp_close_fs (FS, error);
#endif
	}
	else if ( which_fs == CURR_OCFS )
	{
#ifdef WFS_OCFS
		ret_wfs = wfs_ocfs_close_fs (FS, error);
#endif
	}

	if ( (ret_wfs != WFS_SUCCESS) && (error->errcode.gerror == 0) )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = EIO;
#else
		error->errcode.gerror = 5L;	/* EIO */
#endif
	}

	return ret_wfs;
}

/**
 * Checks if the filesystem has errors.
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_check_err (
#ifdef WFS_ANSIC
	wfs_fsid_t FS, const wfs_curr_fs_t which_fs, wfs_error_type_t * const error
# ifndef WFS_XFS
		WFS_ATTR((unused))
# endif
	 )
#else
	FS, which_fs, error
# ifndef WFS_XFS
		WFS_ATTR((unused))
# endif
	 )
	wfs_fsid_t FS;
	const wfs_curr_fs_t which_fs;
	wfs_error_type_t * const error;
#endif
{
	if ( which_fs == CURR_EXT234FS )
	{
#ifdef WFS_EXT234
		return wfs_e234_check_err (FS);
#endif
	}
	else if ( which_fs == CURR_NTFS )
	{
#ifdef WFS_NTFS
		return wfs_ntfs_check_err (FS);
#endif
	}
	else if ( which_fs == CURR_XFS )
	{
#ifdef WFS_XFS
		return wfs_xfs_check_err (FS, error);
#endif
	}
	else if ( which_fs == CURR_REISERFS )
	{
#ifdef WFS_REISER
		return wfs_reiser_check_err (FS);
#endif
	}
	else if ( which_fs == CURR_REISER4 )
	{
#ifdef WFS_REISER4
		return wfs_r4_check_err (FS);
#endif
	}
	else if ( which_fs == CURR_FATFS )
	{
#ifdef WFS_FATFS
		return wfs_fat_check_err (FS);
#endif
	}
	else if ( which_fs == CURR_MINIXFS )
	{
#ifdef WFS_MINIXFS
		return wfs_minixfs_check_err (FS);
#endif
	}
	else if ( which_fs == CURR_JFS )
	{
#ifdef WFS_JFS
		return wfs_jfs_check_err (FS);
#endif
	}
	else if ( which_fs == CURR_HFSP )
	{
#ifdef WFS_HFSP
		return wfs_hfsp_check_err (FS);
#endif
	}
	else if ( which_fs == CURR_OCFS )
	{
#ifdef WFS_OCFS
		return wfs_ocfs_check_err (FS);
#endif
	}

	return WFS_SUCCESS;
}

/**
 * Checks if the filesystem is dirty (has unsaved changes).
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_is_dirty (
#ifdef WFS_ANSIC
	wfs_fsid_t FS, const wfs_curr_fs_t which_fs, wfs_error_type_t * const error
# ifndef WFS_XFS
		WFS_ATTR((unused))
# endif
	 )
#else
	FS, which_fs, error
# ifndef WFS_XFS
		WFS_ATTR((unused))
# endif
	 )
	wfs_fsid_t FS;
	const wfs_curr_fs_t which_fs;
	wfs_error_type_t * const error;
#endif
{
	if ( which_fs == CURR_EXT234FS )
	{
#ifdef WFS_EXT234
		return wfs_e234_is_dirty (FS);
#endif
	}
	else if ( which_fs == CURR_NTFS )
	{
#ifdef WFS_NTFS
		return wfs_ntfs_is_dirty (FS);
#endif
	}
	else if ( which_fs == CURR_XFS )
	{
#ifdef WFS_XFS
		return wfs_xfs_is_dirty (FS, error);
#endif
	}
	else if ( which_fs == CURR_REISERFS )
	{
#ifdef WFS_REISER
		return wfs_reiser_is_dirty (FS);
#endif
	}
	else if ( which_fs == CURR_REISER4 )
	{
#ifdef WFS_REISER4
		return wfs_r4_is_dirty (FS);
#endif
	}
	else if ( which_fs == CURR_FATFS )
	{
#ifdef WFS_FATFS
		return wfs_fat_is_dirty (FS);
#endif
	}
	else if ( which_fs == CURR_MINIXFS )
	{
#ifdef WFS_MINIXFS
		return wfs_minixfs_is_dirty (FS);
#endif
	}
	else if ( which_fs == CURR_JFS )
	{
#ifdef WFS_JFS
		return wfs_jfs_is_dirty (FS);
#endif
	}
	else if ( which_fs == CURR_HFSP )
	{
#ifdef WFS_HFSP
		return wfs_hfsp_is_dirty (FS);
#endif
	}
	else if ( which_fs == CURR_OCFS )
	{
#ifdef WFS_OCFS
		return wfs_ocfs_is_dirty (FS);
#endif
	}

	return WFS_SUCCESS;
}

/**
 * Flushes the filesystem.
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_flush_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t FS, const wfs_curr_fs_t which_fs, wfs_error_type_t * const error )
#else
	FS, which_fs, error )
	wfs_fsid_t FS;
	const wfs_curr_fs_t which_fs;
	wfs_error_type_t * const error;
#endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	if ( which_fs == CURR_EXT234FS )
	{
#ifdef WFS_EXT234
		ret_wfs = wfs_e234_flush_fs (FS, error);
#endif
	}
	else if ( which_fs == CURR_NTFS )
	{
#ifdef WFS_NTFS
		ret_wfs = wfs_ntfs_flush_fs (FS, error);
#endif
	}
	else if ( which_fs == CURR_XFS )
	{
#ifdef WFS_XFS
		ret_wfs = wfs_xfs_flush_fs (FS);
#endif
	}
	else if ( which_fs == CURR_REISERFS )
	{
#ifdef WFS_REISER
		ret_wfs = wfs_reiser_flush_fs (FS);
#endif
	}
	else if ( which_fs == CURR_REISER4 )
	{
#ifdef WFS_REISER4
		ret_wfs = wfs_r4_flush_fs (FS);
#endif
	}
	else if ( which_fs == CURR_FATFS )
	{
#ifdef WFS_FATFS
		ret_wfs = wfs_fat_flush_fs (FS, error);
#endif
	}
	else if ( which_fs == CURR_MINIXFS )
	{
#ifdef WFS_MINIXFS
		ret_wfs = wfs_minixfs_flush_fs (FS, error);
#endif
	}
	else if ( which_fs == CURR_JFS )
	{
#ifdef WFS_JFS
		ret_wfs = wfs_jfs_flush_fs (FS, error);
#endif
	}
	else if ( which_fs == CURR_HFSP )
	{
#ifdef WFS_HFSP
		ret_wfs = wfs_hfsp_flush_fs (FS, error);
#endif
	}
	else if ( which_fs == CURR_OCFS )
	{
#ifdef WFS_OCFS
		ret_wfs = wfs_ocfs_flush_fs (FS, error);
#endif
	}

	if ( (ret_wfs != WFS_SUCCESS) && (error->errcode.gerror == 0) )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = EIO;
#else
		error->errcode.gerror = 5L;	/* EIO */
#endif
	}

#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_SYNC)
	sync ();
#endif
	return ret_wfs;
}
