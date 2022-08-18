/*
 * A program for secure cleaning of free space on filesystems.
 *	-- wrapper functions.
 *
 * Copyright (C) 2007 Bogdan Drozdowski, bogdandr (at) op.pl
 * License: GNU General Public License, v3+
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
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

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* sync() */
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#include "wipefreespace.h"
#include "wrappers.h"

#ifdef WFS_EXT2
# include "wfs_ext23.h"
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

/**
 * Starts recursive directory search for deleted inodes and undelete data.
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wipe_unrm ( wfs_fsid_t FS, const CURR_FS which_fs, error_type * const error )
{
	errcode_enum ret_wfs = WFS_SUCCESS;
#if (defined WFS_EXT2) || (defined WFS_REISER)
	fselem_t elem;
#endif

	if ( which_fs == CURR_EXT2FS )
	{
#ifdef WFS_EXT2
		elem.e2elem = EXT2_ROOT_INO;
		ret_wfs = wfs_e2_wipe_unrm (FS, elem, error);
#endif
	}
	else if ( which_fs == CURR_NTFS )
	{
#ifdef WFS_NTFS
		ret_wfs = wfs_ntfs_wipe_unrm (FS, elem, error);
#endif
	}
	else if ( which_fs == CURR_XFS )
	{
#ifdef WFS_XFS
		ret_wfs = wfs_xfs_wipe_unrm (FS);
#endif
	}
	else if ( which_fs == CURR_REISERFS )
	{
#ifdef WFS_REISER
		elem.rfs_elem = root_dir_key;
		ret_wfs = wfs_reiser_wipe_unrm (FS, elem, error);
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
 * Wipes the free space on the given filesystem.
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wipe_fs ( wfs_fsid_t FS, const CURR_FS which_fs, error_type * const error )
{
	errcode_enum ret_wfs = WFS_SUCCESS;

	if ( which_fs == CURR_EXT2FS )
	{
#ifdef WFS_EXT2
		ret_wfs = wfs_e2_wipe_fs (FS, error);
#endif
	}
	else if ( which_fs == CURR_NTFS )
	{
#ifdef WFS_NTFS
		ret_wfs = wfs_ntfs_wipe_fs (FS, error);
#endif
	}
	else if ( which_fs == CURR_XFS )
	{
#ifdef WFS_XFS
		ret_wfs = wfs_xfs_wipe_fs (FS, error);
#endif
	}
	else if ( which_fs == CURR_REISERFS )
	{
#ifdef WFS_REISER
		ret_wfs = wfs_reiser_wipe_fs (FS, error);
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
 * Wipes the free space in partially used blocks on the given filesystem.
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wipe_part ( const wfs_fsid_t FS, const CURR_FS which_fs, error_type * const error )
{
	errcode_enum ret_wfs = WFS_SUCCESS;

	if ( which_fs == CURR_EXT2FS )
	{
#ifdef WFS_EXT2
		ret_wfs = wfs_e2_wipe_part (FS, error);
#endif
	}
	else if ( which_fs == CURR_NTFS )
	{
#ifdef WFS_NTFS
		ret_wfs = wfs_ntfs_wipe_part (FS, error);
#endif
	}
	else if ( which_fs == CURR_XFS )
	{
#ifdef WFS_XFS
		ret_wfs = wfs_xfs_wipe_part (FS);
#endif
	}
	else if ( which_fs == CURR_REISERFS )
	{
#ifdef WFS_REISER
		ret_wfs = wfs_reiser_wipe_part (FS, error);
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
 * Opens a filesystem on the given device.
 * \param devname Device name, like /dev/hdXY
 * \param FS Pointer to where the result will be put.
 * \param whichfs Pointer to an int saying which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_open_fs ( const char * const dev_name, wfs_fsid_t * const FS, CURR_FS * const which_fs,
	const fsdata * const data, error_type * const error )
{
	errcode_enum ret_wfs = WFS_SUCCESS;
	*which_fs = CURR_NONE;

#ifdef WFS_EXT2
	ret_wfs = wfs_e2_open_fs (dev_name, FS, which_fs, data, error);
#endif
#ifdef WFS_NTFS
	if ( ret_wfs != WFS_SUCCESS )
	{
		error->errcode.gerror = WFS_SUCCESS;
		ret_wfs = wfs_ntfs_open_fs (dev_name, FS, which_fs, data, error);
	}
#endif
#ifdef WFS_XFS
	if ( ret_wfs != WFS_SUCCESS )
	{
		error->errcode.gerror = WFS_SUCCESS;
		ret_wfs = wfs_xfs_open_fs (dev_name, FS, which_fs, data, error);
	}
#endif
#ifdef WFS_REISER
	if ( ret_wfs != WFS_SUCCESS )
	{
		error->errcode.gerror = WFS_SUCCESS;
		ret_wfs = wfs_reiser_open_fs (dev_name, FS, which_fs, data, error);
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
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_chk_mount ( const char * const dev_name, error_type * const error )
{
	errcode_enum ret_wfs = WFS_SUCCESS;

#ifdef WFS_EXT2
	ret_wfs = wfs_e2_chk_mount ( dev_name, error );
	if ( ret_wfs != WFS_SUCCESS ) return ret_wfs;
#endif
#if (defined WFS_NTFS)
	ret_wfs = wfs_ntfs_chk_mount ( dev_name, error );
	if ( ret_wfs != WFS_SUCCESS ) return ret_wfs;
#endif
#if (defined WFS_XFS)
	ret_wfs = wfs_xfs_chk_mount ( dev_name, error );
	if ( ret_wfs != WFS_SUCCESS ) return ret_wfs;
#endif
#if (defined WFS_REISER)
	ret_wfs = wfs_reiser_chk_mount ( dev_name, error );
	if ( ret_wfs != WFS_SUCCESS ) return ret_wfs;
#endif
	return ret_wfs;
}

/**
 * Closes the filesystem.
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((nonnull))
wfs_close_fs ( const wfs_fsid_t FS, const CURR_FS which_fs, error_type * const error )
{
	errcode_enum ret_wfs = WFS_SUCCESS;

	if ( which_fs == CURR_EXT2FS )
	{
#ifdef WFS_EXT2
		ret_wfs = wfs_e2_close_fs (FS, error);
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
wfs_check_err ( wfs_fsid_t FS, const CURR_FS which_fs )
{
	if ( which_fs == CURR_EXT2FS )
	{
#ifdef WFS_EXT2
		return wfs_e2_check_err (FS);
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
		return wfs_xfs_check_err (FS);
#endif
	}
	else if ( which_fs == CURR_REISERFS )
	{
#ifdef WFS_REISER
		return wfs_reiser_check_err (FS);
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
wfs_is_dirty ( wfs_fsid_t FS, const CURR_FS which_fs )
{
	if ( which_fs == CURR_EXT2FS )
	{
#ifdef WFS_EXT2
		return wfs_e2_is_dirty (FS);
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
		return wfs_xfs_is_dirty (FS);
#endif
	}
	else if ( which_fs == CURR_REISERFS )
	{
#ifdef WFS_REISER
		return wfs_reiser_is_dirty (FS);
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
errcode_enum WFS_ATTR ((nonnull))
wfs_flush_fs ( wfs_fsid_t FS, const CURR_FS which_fs, error_type * const error )
{
	errcode_enum ret_wfs = WFS_SUCCESS;
	if ( which_fs == CURR_EXT2FS )
	{
#ifdef WFS_EXT2
		ret_wfs = wfs_e2_flush_fs (FS, error);
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

