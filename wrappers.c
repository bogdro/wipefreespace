/*
 * A program for secure cleaning of free space on ext2/3 partitions.
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

#include "ext23.h"
#include <unistd.h>


/**
 * Starts recursive directory search for deleted inodes and undelete data.
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
int ATTR((warn_unused_result)) wipe_unrm ( fsid FS, int whichfs ) {

	fselem elem;
#ifdef WFS_EXT2
	elem.e2elem = EXT2_ROOT_INO;
#endif

	if ( whichfs == CURR_EXT2FS ) {
#ifdef WFS_EXT2
		return e2wipe_unrm(FS, elem);
#endif
	}
	return WFS_SUCCESS;
}

/**
 * Wipes the free space on the given filesystem.
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
int ATTR((warn_unused_result)) wipe_fs ( fsid FS, int whichfs ) {

	if ( whichfs == CURR_EXT2FS ) {
#ifdef WFS_EXT2
		return e2wipe_fs(FS);
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
int ATTR((warn_unused_result)) wipe_part ( fsid FS, int whichfs ) {

	if ( whichfs == CURR_EXT2FS ) {
#ifdef WFS_EXT2
		return e2wipe_part(FS);
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
	fsid *FS, int *whichfs, fsdata* data ) {

	int ret = WFS_SUCCESS;
	*whichfs = 0;

#ifdef WFS_EXT2
	error.e2error = ext2fs_open ( devname, EXT2_FLAG_RW
# ifdef EXT2_FLAG_EXCLUSIVE
		| EXT2_FLAG_EXCLUSIVE
# endif
		, (int)(data->e2fs.super_off), (unsigned int)(data->e2fs.blocksize),
		unix_io_manager, &FS->e2fs );
	if ( error.e2error != 0 ) {
		error.e2error = ext2fs_open ( devname, EXT2_FLAG_RW, (int)(data->e2fs.super_off),
			(unsigned int)(data->e2fs.blocksize), unix_io_manager, &FS->e2fs );
	}
	if ( error.e2error == 0 ) {
		*whichfs = CURR_EXT2FS;
		return WFS_SUCCESS;
	}
#endif

	return ret;
}

/**
 * Checks if the given device is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \return 0 in case of no errors, other values otherwise.
 */
int ATTR((warn_unused_result)) ATTR((nonnull)) wfs_chkmount ( const char*const devname ) {

	int ret = WFS_SUCCESS;
	int mtflags = 0;		/* Mount flags */

#ifdef WFS_EXT2
	/* reject if mounted for read and write (when we can't go on with our work) */
	error.e2error = ext2fs_check_if_mounted ( devname, &mtflags );
	if ( error.e2error != 0 ) {
		/* go to the next device on the command line and set the "last error" value */
		ret = WFS_MNTCHK;
	}
	if ( ((mtflags & EXT2_MF_MOUNTED) != 0) && ((mtflags & EXT2_MF_READONLY) == 0) ) {
		error.e2error = 1L;
		ret = WFS_MNTRW;
	}
#endif

	return ret;
}

/**
 * Closes the filesystem.
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
int wfs_closefs ( fsid FS, int whichfs ) {

	int ret = WFS_SUCCESS;

	if ( whichfs == CURR_EXT2FS ) {
#ifdef WFS_EXT2
		error.e2error = ext2fs_close ( FS.e2fs );
		if ( error.e2error != 0 ) {
			show_error ( error, err_msg_close, fsname );
			ret = WFS_FSCLOSE;
		}
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
int ATTR((warn_unused_result)) wfs_checkerr ( fsid FS, int whichfs ) {

	if ( whichfs == CURR_EXT2FS ) {
#ifdef WFS_EXT2
		return (FS.e2fs->super->s_state & EXT2_ERROR_FS);
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
int ATTR((warn_unused_result)) wfs_isdirty ( fsid FS, int whichfs ) {

	if ( whichfs == CURR_EXT2FS ) {
#ifdef WFS_EXT2
		return ( ((FS.e2fs->super->s_state & EXT2_VALID_FS) == 0) ||
			((FS.e2fs->flags & EXT2_FLAG_DIRTY) != 0) ||
			(ext2fs_test_changed(FS.e2fs) != 0)
			);
#else
		return WFS_SUCCESS;
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
int wfs_flushfs ( fsid FS, int whichfs ) {

	int ret = WFS_SUCCESS;
	if ( whichfs == CURR_EXT2FS ) {
#ifdef WFS_EXT2
		error.e2error = ext2fs_flush ( FS.e2fs );
		if ( error.e2error != 0 ) {
			show_error ( error, err_msg_flush, fsname );
			ret = WFS_FLUSHFS;
		}
#endif
	}
#if !defined __STRICT_ANSI__
	sync();
#endif
	return ret;
}

/**
 * Returns the buffer size needed to work on the smallest physical unit on a filesystem
 * \param FS The filesystem.
 * \param whichfs Tells which fs is curently in use.
 * \return 0 in case of no errors, other values otherwise.
 */
int ATTR((warn_unused_result)) wfs_getblocksize ( fsid FS, int whichfs ) {

	if ( whichfs == CURR_EXT2FS ) {
#ifdef WFS_EXT2
		return WFS_BLOCKSIZE(FS.e2fs);
#endif
	}
	return 4096;
}

