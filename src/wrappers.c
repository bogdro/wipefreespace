/*
 * A program for secure cleaning of free space on filesystems.
 *	-- wrapper functions.
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

#include "cfg.h"

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* sync() */
#endif

#include "wipefreespace.h"
#include "wrappers.h"

#ifdef WFS_EXT2
# include "ext23.h"
#endif

#ifdef WFS_NTFS
# include "wfs_ntfs.h"
#endif


/**
 * Starts recursive directory search for deleted inodes and undelete data.
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
int ATTR((warn_unused_result)) wipe_unrm ( wfs_fsid_t FS, int whichfs ) {

	int ret_wfs = WFS_SUCCESS;
	fselem_t elem;

	if ( whichfs == CURR_EXT2FS ) {
#ifdef WFS_EXT2
		elem.e2elem = EXT2_ROOT_INO;
		ret_wfs = wfs_e2wipe_unrm(FS, elem);
#endif
	}
	else if ( whichfs == CURR_NTFS ) {
#ifdef WFS_NTFS
		ret_wfs = wfs_ntfswipe_unrm(FS, elem);
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
int ATTR((warn_unused_result)) wipe_fs ( wfs_fsid_t FS, int whichfs ) {

	if ( whichfs == CURR_EXT2FS ) {
#ifdef WFS_EXT2
		return wfs_e2wipe_fs(FS);
#endif
	}
	else if ( whichfs == CURR_NTFS ) {
#ifdef WFS_NTFS
		return wfs_ntfswipe_fs(FS);
#endif
	}
	return WFS_SUCCESS;
}

/**
 * Wipes the free space in partially used blocks on the given filesystem.
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
int ATTR((warn_unused_result)) wipe_part ( wfs_fsid_t FS, int whichfs ) {

	if ( whichfs == CURR_EXT2FS ) {
#ifdef WFS_EXT2
		return wfs_e2wipe_part(FS);
#endif
	}
	else if ( whichfs == CURR_NTFS ) {
#ifdef WFS_NTFS
		return wfs_ntfswipe_part(FS);
#endif
	}
	return WFS_SUCCESS;
}

/**
 * Opens a filesystem on the given device.
 * \param devname Device name, like /dev/hdXY
 * \param FS Pointer to where the result will be put.
 * \param whichfs Pointer to an int saying which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
int ATTR((warn_unused_result)) ATTR((nonnull)) wfs_openfs ( const char*const devname,
	wfs_fsid_t *FS, int *whichfs, fsdata* data ) {

	int ret = WFS_SUCCESS;
	*whichfs = 0;

#ifdef WFS_EXT2
	ret = wfs_e2openfs(devname, FS, whichfs, data);
#endif
	if ( ret != WFS_SUCCESS ) {
#ifdef WFS_NTFS
		/*error.errcode.e2error = 0;*/
		ret = wfs_ntfsopenfs(devname, FS, whichfs, data);
#endif
	}

	return ret;
}

/**
 * Checks if the given device is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \return 0 in case of no errors, other values otherwise.
 */
int ATTR((warn_unused_result)) ATTR((nonnull)) wfs_chkmount ( const char*const devname ) {

	int ret = WFS_SUCCESS;

#ifdef WFS_EXT2
	ret = wfs_e2chkmount ( devname );
#endif
#if defined WFS_NTFS
	ret += wfs_ntfschkmount ( devname );
#endif

	return ret;
}

/**
 * Closes the filesystem.
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
int wfs_closefs ( wfs_fsid_t FS, int whichfs ) {

	int ret = WFS_SUCCESS;

	if ( whichfs == CURR_EXT2FS ) {
#ifdef WFS_EXT2
		ret = wfs_e2closefs(FS);
#endif
	}
	else if ( whichfs == CURR_NTFS ) {
#ifdef WFS_NTFS
		ret = wfs_ntfsclosefs(FS);
#endif
	}

	return ret;
}

/**
 * Checks if the filesystem has errors.
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
int ATTR((warn_unused_result)) wfs_checkerr ( wfs_fsid_t FS, int whichfs ) {

	if ( whichfs == CURR_EXT2FS ) {
#ifdef WFS_EXT2
		return wfs_e2checkerr(FS);
#endif
	}
	else if ( whichfs == CURR_NTFS ) {
#ifdef WFS_NTFS
		return wfs_ntfscheckerr(FS);
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
int ATTR((warn_unused_result)) wfs_isdirty ( wfs_fsid_t FS, int whichfs ) {

	if ( whichfs == CURR_EXT2FS ) {
#ifdef WFS_EXT2
		return wfs_e2isdirty(FS);
#endif
	}
	else if ( whichfs == CURR_NTFS ) {
#ifdef WFS_NTFS
		return wfs_ntfsisdirty(FS);
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
int wfs_flushfs ( wfs_fsid_t FS, int whichfs ) {

	int ret = WFS_SUCCESS;
	if ( whichfs == CURR_EXT2FS ) {
#ifdef WFS_EXT2
		ret = wfs_e2flushfs (FS);
#endif
	}
	else if ( whichfs == CURR_NTFS ) {
#ifdef WFS_NTFS
		ret = wfs_ntfsflushfs (FS);
#endif
	}

#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H)
	sync();
#endif
	return ret;
}

/**
 * Returns the buffer size needed to work on the smallest physical unit on a filesystem
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return Block size on the filesystem. Deafults to 4096 if not available.
 */
int ATTR((warn_unused_result)) wfs_getblocksize ( wfs_fsid_t FS, int whichfs ) {

	if ( whichfs == CURR_EXT2FS ) {
#ifdef WFS_EXT2
		return wfs_e2getblocksize(FS);
#endif
	}
	else if ( whichfs == CURR_NTFS ) {
#ifdef WFS_NTFS
		return wfs_ntfsgetblocksize(FS);
#endif
	}
	return 4096;
}

