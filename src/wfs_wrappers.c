/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- wrapper functions.
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

#include <stdio.h>	/* NULL and others */

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* sync() */
#endif

#include "wipefreespace.h"
#include "wfs_wrappers.h"
#include "wfs_util.h"

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

#ifdef TEST_COMPILE
# undef WFS_ANSIC
#endif

/* ======================================================================== */

#ifdef WFS_WANT_UNRM
/**
 * Starts recursive directory search for deleted inodes and undelete data.
 * \param wfs_fs The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wipe_unrm (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;

	if ( wfs_fs.whichfs == WFS_CURR_FS_EXT234FS )
	{
# ifdef WFS_EXT234
		ret_wfs = wfs_e234_wipe_unrm (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_NTFS )
	{
# ifdef WFS_NTFS
		ret_wfs = wfs_ntfs_wipe_unrm (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_XFS )
	{
# ifdef WFS_XFS
		ret_wfs = wfs_xfs_wipe_unrm (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_REISERFS )
	{
# ifdef WFS_REISER
		ret_wfs = wfs_reiser_wipe_unrm (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_REISER4 )
	{
# ifdef WFS_REISER4
		ret_wfs = wfs_r4_wipe_unrm (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_FATFS )
	{
# ifdef WFS_FATFS
		ret_wfs = wfs_fat_wipe_unrm (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_MINIXFS )
	{
# ifdef WFS_MINIXFS
		ret_wfs = wfs_minixfs_wipe_unrm (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_JFS )
	{
# ifdef WFS_JFS
		ret_wfs = wfs_jfs_wipe_unrm (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_HFSP )
	{
# ifdef WFS_HFSP
		ret_wfs = wfs_hfsp_wipe_unrm (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_OCFS )
	{
# ifdef WFS_OCFS
		ret_wfs = wfs_ocfs_wipe_unrm (wfs_fs);
# endif
	}

	return ret_wfs;
}
#endif /* WFS_WANT_UNRM */

/* ======================================================================== */

#ifdef WFS_WANT_WFS
/**
 * Wipes the free space on the given filesystem.
 * \param wfs_fs The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wipe_fs (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;

	if ( wfs_fs.whichfs == WFS_CURR_FS_EXT234FS )
	{
# ifdef WFS_EXT234
		ret_wfs = wfs_e234_wipe_fs (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_NTFS )
	{
# ifdef WFS_NTFS
		ret_wfs = wfs_ntfs_wipe_fs (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_XFS )
	{
# ifdef WFS_XFS
		ret_wfs = wfs_xfs_wipe_fs (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_REISERFS )
	{
# ifdef WFS_REISER
		ret_wfs = wfs_reiser_wipe_fs (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_REISER4 )
	{
# ifdef WFS_REISER4
		ret_wfs = wfs_r4_wipe_fs (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_FATFS )
	{
# ifdef WFS_FATFS
		ret_wfs = wfs_fat_wipe_fs (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_MINIXFS )
	{
# ifdef WFS_MINIXFS
		ret_wfs = wfs_minixfs_wipe_fs (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_JFS )
	{
# ifdef WFS_JFS
		ret_wfs = wfs_jfs_wipe_fs (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_HFSP )
	{
# ifdef WFS_HFSP
		ret_wfs = wfs_hfsp_wipe_fs (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_OCFS )
	{
# ifdef WFS_OCFS
		ret_wfs = wfs_ocfs_wipe_fs (wfs_fs);
# endif
	}

	return ret_wfs;
}
#endif /* WFS_WANT_WFS */

/* ======================================================================== */

#ifdef WFS_WANT_PART
/**
 * Wipes the free space in partially used blocks on the given filesystem.
 * \param wfs_fs The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wipe_part (
# ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;

	if ( wfs_fs.whichfs == WFS_CURR_FS_EXT234FS )
	{
# ifdef WFS_EXT234
		ret_wfs = wfs_e234_wipe_part (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_NTFS )
	{
# ifdef WFS_NTFS
		ret_wfs = wfs_ntfs_wipe_part (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_XFS )
	{
# ifdef WFS_XFS
		ret_wfs = wfs_xfs_wipe_part (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_REISERFS )
	{
# ifdef WFS_REISER
		ret_wfs = wfs_reiser_wipe_part (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_REISER4 )
	{
# ifdef WFS_REISER4
		ret_wfs = wfs_r4_wipe_part (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_FATFS )
	{
# ifdef WFS_FATFS
		ret_wfs = wfs_fat_wipe_part (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_MINIXFS )
	{
# ifdef WFS_MINIXFS
		ret_wfs = wfs_minixfs_wipe_part (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_JFS )
	{
# ifdef WFS_JFS
		ret_wfs = wfs_jfs_wipe_part (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_HFSP )
	{
# ifdef WFS_HFSP
		ret_wfs = wfs_hfsp_wipe_part (wfs_fs);
# endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_OCFS )
	{
# ifdef WFS_OCFS
		ret_wfs = wfs_ocfs_wipe_part (wfs_fs);
# endif
	}

	return ret_wfs;
}
#endif /* WFS_WANT_PART */

/* ======================================================================== */

/**
 * Opens a filesystem on the given device.
 * \param devname Device name, like /dev/hdXY
 * \param wfs_fs Pointer to where the result will be put.
 * \param whichfs Pointer to an int saying which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_open_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t * const wfs_fs,
	const wfs_fsdata_t * const data)
#else
	wfs_fs, data)
	wfs_fsid_t * const wfs_fs;
	const wfs_fsdata_t * const data;
#endif
{
	wfs_errcode_t ret_wfs = WFS_OPENFS;
#ifdef WFS_EXT234
	ret_wfs = wfs_e234_open_fs (wfs_fs, data);
#endif
#ifdef WFS_NTFS
	if ( ret_wfs != WFS_SUCCESS )
	{
		ret_wfs = wfs_ntfs_open_fs (wfs_fs, data);
	}
#endif
#ifdef WFS_REISER4
	if ( ret_wfs != WFS_SUCCESS )
	{
		ret_wfs = wfs_r4_open_fs (wfs_fs, data);
	}
#endif
#ifdef WFS_XFS
	if ( ret_wfs != WFS_SUCCESS )
	{
		ret_wfs = wfs_xfs_open_fs (wfs_fs, data);
	}
#endif
/* JFS before ReiserFSv3 */
#ifdef WFS_JFS
	if ( ret_wfs != WFS_SUCCESS )
	{
		ret_wfs = wfs_jfs_open_fs (wfs_fs, data);
	}
#endif
/* FAT is probably the least specific in its header - the TFFS library can detect
   XFS and ReiserFS3/4 as FAT, which is bad. But now we have more advanced checks
   than simply using TFFS, so this can be before ReiserFSv3. */
#ifdef WFS_FATFS
	if ( ret_wfs != WFS_SUCCESS )
	{
		ret_wfs = wfs_fat_open_fs (wfs_fs, data);
	}
#endif
#ifdef WFS_MINIXFS
	if ( ret_wfs != WFS_SUCCESS )
	{
		ret_wfs = wfs_minixfs_open_fs (wfs_fs, data);
	}
#endif
#ifdef WFS_REISER
	if ( ret_wfs != WFS_SUCCESS )
	{
		ret_wfs = wfs_reiser_open_fs (wfs_fs, data);
	}
#endif
#ifdef WFS_HFSP
	if ( ret_wfs != WFS_SUCCESS )
	{
		ret_wfs = wfs_hfsp_open_fs (wfs_fs, data);
	}
#endif
#ifdef WFS_OCFS
	if ( ret_wfs != WFS_SUCCESS )
	{
		ret_wfs = wfs_ocfs_open_fs (wfs_fs, data);
	}
#endif

	return ret_wfs;
}

/* ======================================================================== */

/**
 * Checks if the given device is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_chk_mount (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
#endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;

#ifdef WFS_EXT234
	ret_wfs = wfs_e234_chk_mount (wfs_fs);
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif
#if (defined WFS_NTFS)
	ret_wfs = wfs_ntfs_chk_mount (wfs_fs);
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif
#if (defined WFS_XFS)
	ret_wfs = wfs_xfs_chk_mount (wfs_fs);
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif
#if (defined WFS_REISER)
	ret_wfs = wfs_reiser_chk_mount (wfs_fs);
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif
#if (defined WFS_REISER4)
	ret_wfs = wfs_r4_chk_mount (wfs_fs);
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif
#if (defined WFS_FATFS)
	ret_wfs = wfs_fat_chk_mount (wfs_fs);
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif
#if (defined WFS_MINIXFS)
	ret_wfs = wfs_minixfs_chk_mount (wfs_fs);
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif
#if (defined WFS_JFS)
	ret_wfs = wfs_jfs_chk_mount (wfs_fs);
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif
#if (defined WFS_HFSP)
	ret_wfs = wfs_hfsp_chk_mount (wfs_fs);
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif
#if (defined WFS_OCFS)
	ret_wfs = wfs_ocfs_chk_mount (wfs_fs);
	if ( ret_wfs != WFS_SUCCESS )
	{
		return ret_wfs;
	}
#endif

	return ret_wfs;
}

/* ======================================================================== */

/**
 * Closes the filesystem.
 * \param wfs_fs The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_close_fs (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
#endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;

	if ( wfs_fs.whichfs == WFS_CURR_FS_EXT234FS )
	{
#ifdef WFS_EXT234
		ret_wfs = wfs_e234_close_fs (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_NTFS )
	{
#ifdef WFS_NTFS
		ret_wfs = wfs_ntfs_close_fs (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_XFS )
	{
#ifdef WFS_XFS
		ret_wfs = wfs_xfs_close_fs (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_REISERFS )
	{
#ifdef WFS_REISER
		ret_wfs = wfs_reiser_close_fs (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_REISER4 )
	{
#ifdef WFS_REISER4
		ret_wfs = wfs_r4_close_fs (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_FATFS )
	{
#ifdef WFS_FATFS
		ret_wfs = wfs_fat_close_fs (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_MINIXFS )
	{
#ifdef WFS_MINIXFS
		ret_wfs = wfs_minixfs_close_fs (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_JFS )
	{
#ifdef WFS_JFS
		ret_wfs = wfs_jfs_close_fs (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_HFSP )
	{
#ifdef WFS_HFSP
		ret_wfs = wfs_hfsp_close_fs (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_OCFS )
	{
#ifdef WFS_OCFS
		ret_wfs = wfs_ocfs_close_fs (wfs_fs);
#endif
	}

	return ret_wfs;
}

/* ======================================================================== */

/**
 * Checks if the filesystem has errors.
 * \param wfs_fs The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_check_err (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs;
#endif
{
	if ( wfs_fs.whichfs == WFS_CURR_FS_EXT234FS )
	{
#ifdef WFS_EXT234
		return wfs_e234_check_err (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_NTFS )
	{
#ifdef WFS_NTFS
		return wfs_ntfs_check_err (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_XFS )
	{
#ifdef WFS_XFS
		return wfs_xfs_check_err (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_REISERFS )
	{
#ifdef WFS_REISER
		return wfs_reiser_check_err (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_REISER4 )
	{
#ifdef WFS_REISER4
		return wfs_r4_check_err (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_FATFS )
	{
#ifdef WFS_FATFS
		return wfs_fat_check_err (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_MINIXFS )
	{
#ifdef WFS_MINIXFS
		return wfs_minixfs_check_err (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_JFS )
	{
#ifdef WFS_JFS
		return wfs_jfs_check_err (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_HFSP )
	{
#ifdef WFS_HFSP
		return wfs_hfsp_check_err (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_OCFS )
	{
#ifdef WFS_OCFS
		return wfs_ocfs_check_err (wfs_fs);
#endif
	}

	return WFS_SUCCESS;
}

/* ======================================================================== */

/**
 * Checks if the filesystem is dirty (has unsaved changes).
 * \param wfs_fs The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_is_dirty (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs;
#endif
{
	if ( wfs_fs.whichfs == WFS_CURR_FS_EXT234FS )
	{
#ifdef WFS_EXT234
		return wfs_e234_is_dirty (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_NTFS )
	{
#ifdef WFS_NTFS
		return wfs_ntfs_is_dirty (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_XFS )
	{
#ifdef WFS_XFS
		return wfs_xfs_is_dirty (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_REISERFS )
	{
#ifdef WFS_REISER
		return wfs_reiser_is_dirty (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_REISER4 )
	{
#ifdef WFS_REISER4
		return wfs_r4_is_dirty (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_FATFS )
	{
#ifdef WFS_FATFS
		return wfs_fat_is_dirty (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_MINIXFS )
	{
#ifdef WFS_MINIXFS
		return wfs_minixfs_is_dirty (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_JFS )
	{
#ifdef WFS_JFS
		return wfs_jfs_is_dirty (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_HFSP )
	{
#ifdef WFS_HFSP
		return wfs_hfsp_is_dirty (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_OCFS )
	{
#ifdef WFS_OCFS
		return wfs_ocfs_is_dirty (wfs_fs);
#endif
	}

	return WFS_SUCCESS;
}

/* ======================================================================== */

/**
 * Flushes the filesystem.
 * \param wfs_fs The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_flush_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs;
#endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	if ( wfs_fs.whichfs == WFS_CURR_FS_EXT234FS )
	{
#ifdef WFS_EXT234
		ret_wfs = wfs_e234_flush_fs (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_NTFS )
	{
#ifdef WFS_NTFS
		ret_wfs = wfs_ntfs_flush_fs (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_XFS )
	{
#ifdef WFS_XFS
		ret_wfs = wfs_xfs_flush_fs (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_REISERFS )
	{
#ifdef WFS_REISER
		ret_wfs = wfs_reiser_flush_fs (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_REISER4 )
	{
#ifdef WFS_REISER4
		ret_wfs = wfs_r4_flush_fs (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_FATFS )
	{
#ifdef WFS_FATFS
		ret_wfs = wfs_fat_flush_fs (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_MINIXFS )
	{
#ifdef WFS_MINIXFS
		ret_wfs = wfs_minixfs_flush_fs (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_JFS )
	{
#ifdef WFS_JFS
		ret_wfs = wfs_jfs_flush_fs (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_HFSP )
	{
#ifdef WFS_HFSP
		ret_wfs = wfs_hfsp_flush_fs (wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_OCFS )
	{
#ifdef WFS_OCFS
		ret_wfs = wfs_ocfs_flush_fs (wfs_fs);
#endif
	}

#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_SYNC)
	sync ();
#endif
	return ret_wfs;
}

/* ======================================================================== */

/**
 * Print the versions of the libraries.
 */
void wfs_print_version (WFS_VOID)
{
#ifdef WFS_EXT234
	wfs_e234_print_version();
#endif
#ifdef WFS_NTFS
	wfs_ntfs_print_version();
#endif
#ifdef WFS_XFS
	wfs_xfs_print_version();
#endif
#ifdef WFS_REISER
	wfs_reiser_print_version();
#endif
#ifdef WFS_REISER4
	wfs_r4_print_version();
#endif
#ifdef WFS_FATFS
	wfs_fat_print_version();
#endif
#ifdef WFS_MINIXFS
	wfs_minixfs_print_version();
#endif
#ifdef WFS_JFS
	wfs_jfs_print_version();
#endif
#ifdef WFS_HFSP
	wfs_hfsp_print_version();
#endif
#ifdef WFS_OCFS
	wfs_ocfs_print_version();
#endif
}

/* ======================================================================== */

/**
 * Get the preferred size of the error variable.
 * \return the preferred size of the error variable.
 */
size_t wfs_get_err_size (WFS_VOID)
{
	size_t ret = sizeof (wfs_errcode_t);
#if (defined WFS_EXT234) || (defined WFS_NTFS) || (defined WFS_XFS) \
	|| (defined WFS_REISER) || (defined WFS_REISER4) \
	|| (defined WFS_FATFS) || (defined WFS_MINIXFS) \
	|| (defined WFS_JFS) || (defined WFS_HFSP) || (defined WFS_OCFS)

	size_t tmp;
#endif

#ifdef WFS_EXT234
	tmp = wfs_e234_get_err_size();
	if ( tmp > ret )
	{
		ret = tmp;
	}
#endif
#ifdef WFS_NTFS
	tmp = wfs_ntfs_get_err_size();
	if ( tmp > ret )
	{
		ret = tmp;
	}
#endif
#ifdef WFS_XFS
	tmp = wfs_xfs_get_err_size();
	if ( tmp > ret )
	{
		ret = tmp;
	}
#endif
#ifdef WFS_REISER
	tmp = wfs_reiser_get_err_size();
	if ( tmp > ret )
	{
		ret = tmp;
	}
#endif
#ifdef WFS_REISER4
	tmp = wfs_r4_get_err_size();
	if ( tmp > ret )
	{
		ret = tmp;
	}
#endif
#ifdef WFS_FATFS
	tmp = wfs_fat_get_err_size();
	if ( tmp > ret )
	{
		ret = tmp;
	}
#endif
#ifdef WFS_MINIXFS
	tmp = wfs_minixfs_get_err_size();
	if ( tmp > ret )
	{
		ret = tmp;
	}
#endif
#ifdef WFS_JFS
	tmp = wfs_jfs_get_err_size();
	if ( tmp > ret )
	{
		ret = tmp;
	}
#endif
#ifdef WFS_HFSP
	tmp = wfs_hfsp_get_err_size();
	if ( tmp > ret )
	{
		ret = tmp;
	}
#endif
#ifdef WFS_OCFS
	tmp = wfs_ocfs_get_err_size();
	if ( tmp > ret )
	{
		ret = tmp;
	}
#endif
	if ( ret < sizeof (long int) )
	{
		ret = sizeof (long int);
	}

	return ret;
}

/* ======================================================================== */

/**
 * Initialize the libraries.
 */
void wfs_lib_init (WFS_VOID)
{
#ifdef WFS_EXT234
	wfs_e234_init ();
#endif
#ifdef WFS_NTFS
	wfs_ntfs_init ();
#endif
#ifdef WFS_XFS
	wfs_xfs_init ();
#endif
#ifdef WFS_REISER
	wfs_reiser_init ();
#endif
#ifdef WFS_REISER4
	wfs_r4_init ();
#endif
#ifdef WFS_FATFS
	wfs_fat_init ();
#endif
#ifdef WFS_MINIXFS
	wfs_minixfs_init ();
#endif
#ifdef WFS_JFS
	wfs_jfs_init ();
#endif
#ifdef WFS_HFSP
	wfs_hfsp_init ();
#endif
#ifdef WFS_OCFS
	wfs_ocfs_init ();
#endif
}

/* ======================================================================== */

/**
 * De-initialize the libraries.
 */
void wfs_lib_deinit (WFS_VOID)
{
#ifdef WFS_EXT234
	wfs_e234_deinit ();
#endif
#ifdef WFS_NTFS
	wfs_ntfs_deinit ();
#endif
#ifdef WFS_XFS
	wfs_xfs_deinit ();
#endif
#ifdef WFS_REISER
	wfs_reiser_deinit ();
#endif
#ifdef WFS_REISER4
	wfs_r4_deinit ();
#endif
#ifdef WFS_FATFS
	wfs_fat_deinit ();
#endif
#ifdef WFS_MINIXFS
	wfs_minixfs_deinit ();
#endif
#ifdef WFS_JFS
	wfs_jfs_deinit ();
#endif
#ifdef WFS_HFSP
	wfs_hfsp_deinit ();
#endif
#ifdef WFS_OCFS
	wfs_ocfs_deinit ();
#endif
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
wfs_show_error (
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
	if ( wfs_fs.whichfs == WFS_CURR_FS_EXT234FS )
	{
#ifdef WFS_EXT234
		wfs_e234_show_error (msg, extra, wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_NTFS )
	{
#ifdef WFS_NTFS
		wfs_ntfs_show_error (msg, extra, wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_XFS )
	{
#ifdef WFS_XFS
		wfs_xfs_show_error (msg, extra, wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_REISERFS )
	{
#ifdef WFS_REISER
		wfs_reiser_show_error (msg, extra, wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_REISER4 )
	{
#ifdef WFS_REISER4
		wfs_r4_show_error (msg, extra, wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_FATFS )
	{
#ifdef WFS_FATFS
		wfs_fat_show_error (msg, extra, wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_MINIXFS )
	{
#ifdef WFS_MINIXFS
		wfs_minixfs_show_error (msg, extra, wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_JFS )
	{
#ifdef WFS_JFS
		wfs_jfs_show_error (msg, extra, wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_HFSP )
	{
#ifdef WFS_HFSP
		wfs_hfsp_show_error (msg, extra, wfs_fs);
#endif
	}
	else if ( wfs_fs.whichfs == WFS_CURR_FS_OCFS )
	{
#ifdef WFS_OCFS
		wfs_ocfs_show_error (msg, extra, wfs_fs);
#endif
	}
	else
	{
		wfs_show_fs_error_gen (msg, extra, wfs_fs);
	}
}
