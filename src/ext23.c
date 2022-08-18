/*
 * A program for secure cleaning of free space on filesystems.
 *	-- ext2 and ext3 file system-specific functions.
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>		/* dev_t: just for ext2fs.h */
#elif defined HAVE_SYS_STAT_H
# include <sys/stat.h>
#elif !defined HAVE_DEV_T
# error No dev_t
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#elif !defined HAVE_SIZE_T
typedef unsigned size_t;
#endif

#if (defined HAVE_EXT2FS_EXT2FS_H) && (defined HAVE_LIBEXT2FS)
# include <ext2fs/ext2fs.h>
#elif (defined HAVE_EXT2FS_H) && (defined HAVE_LIBEXT2FS)
# include <ext2fs.h>
#else
# error Something wrong. Ext2/3 requested, but ext2fs.h or libext2fs missing.
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* sync() */
#endif

#include "wipefreespace.h"
#include "ext23.h"

static blk_t last_block_no;

/**
 * Wipes a block on an ext2/3 filesystem and writes it to the media.
 * \param FS The filesystem which the block is on.
 * \param BLOCKNR Pointer to physical block number.
 * \param BLOCKCNT Block type (<0 for metadata blocks, >=0 is the number of the block in the i-node).
 * \param PRIVATE Private data. If not NULL, is a pointer to an i-node, whose last block
 *	is to be partially wiped. We need the object size from the i-node.
 * \return 0 in case of no errors, and BLOCK_ABORT in case of signal or error.
 */
static int ATTR((nonnull(2))) ATTR((warn_unused_result)) e2do_block (
			const ext2_filsys		FS,
			const blk_t * const 		BLOCKNR,
			const int			BLOCKCNT,
			/*@null@*/ void * const		PRIVATE)
		/*@requires notnull FS, BLOCKNR @*/ {

	unsigned long int j;
	int returns = WFS_SUCCESS;
	size_t buf_start = 0;
	wfs_fsid_t FSID;
	FSID.e2fs = FS;

	if ( (PRIVATE != NULL) && (sig_recvd == 0) ) {
		buf_start = (size_t)(wfs_e2getblocksize(FSID) -
			( ((struct ext2_inode *)PRIVATE)->i_size % wfs_e2getblocksize(FSID) ) );
		/* The beginning of the block must NOT be wiped, read it here. */
		error.errcode.e2error = io_channel_read_blk(FS->io, *BLOCKNR, 1, buf);
		if ( error.errcode.e2error != 0 ) {
			show_error ( error, err_msg_rdblk, fsname );
			return BLOCK_ABORT;
		}
	}

	/* mark bad blocks if needed. Taken from libext2fs->lib/ext2fs/inode.c */
	if (FS->badblocks == NULL) {
		error.errcode.e2error = ext2fs_read_bb_inode(FS, &FS->badblocks);
		if ( (error.errcode.e2error != 0) && (FS->badblocks != NULL) ) {
			ext2fs_badblocks_list_free(FS->badblocks);
			FS->badblocks = NULL;
		}
	}

	/* do nothing on metadata blocks or if incorrect block number given */
	if ( (BLOCKCNT < 0) || (*BLOCKNR == 0) ) return WFS_SUCCESS;

	for ( j = 0; (j < npasses) && (sig_recvd == 0); j++ ) {

		fill_buffer ( j, buf+buf_start, wfs_e2getblocksize(FSID)-buf_start );
		if ( sig_recvd != 0 ) {
			returns = BLOCK_ABORT;
		       	break;
		}
		error.errcode.e2error = io_channel_write_blk(FS->io, *BLOCKNR, 1, buf);
		if ( (error.errcode.e2error != 0) ) {
			/* check if block is marked as bad. If there is no 'badblocks' list
			   or the block is marked OK, then print the error. */
			if ( (FS->badblocks == NULL)
				|| (ext2fs_badblocks_list_test(FS->badblocks, *BLOCKNR) == 0)
			 ) {
				show_error ( error, err_msg_wrtblk, fsname );
				returns = BLOCK_ABORT;
			}
		}
		/* Flush after each writing, if more than 1 overwriting needs to be done.
		   Allow I/O bufferring (efficiency), if just one pass is needed. */
		if ( (npasses > 1) && (sig_recvd == 0) ) {
			error.errcode.gerror = wfs_e2flushfs ( FSID );
#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H)
			sync();
#endif
		}
	}
	if ( sig_recvd != 0 ) {
		return BLOCK_ABORT;
	} else {
		return returns;
	}
}

/**
 * Finds the last block number used by an Ext2/3 i-node. Simply gets all block numbers one at
 * a time and saves the last one.
 * \param FS The filesystem which the block is on (unused).
 * \param BLOCKNR Pointer to physical block number.
 * \param BLOCKCNT Block type (<0 for metadata blocks, >=0 is the number of the block in the i-node), unused.
 * \param PRIVATE Private data (unused).
 * \return This function always returns 0.
 */
static int ATTR((nonnull(2))) e2count_blocks (
		/*@unused@*/ 		const ext2_filsys	FS ATTR((unused)),
					blk_t * const		BLOCKNR,
		/*@unused@*/ 		const int		BLOCKCNT ATTR((unused)),
		/*@unused@*/ /*@null@*/	void *			PRIVATE ATTR((unused)))
		/*@requires notnull BLOCKNR @*/ {

	last_block_no = *BLOCKNR;
	return WFS_SUCCESS;
}

/**
 * Wipes undelete information from the given Ext2/3 directory i-node.
 * \param dir I-node number of the direcotry being browsed.
 * \param entry Type of directory entry.
 * \param DIRENT Pointer to a ext2_dir_entry structure describing current directory entry.
 * \param OFFSET Offset of the ext2_dir_entry structure from beginning of the directory block.
 * \param BLOCKSIZE Size of a block on the file system (unused).
 * \param BUF Pointer to contents of the directory block.
 * \param PRIVATE Points to a wipedata structure, describing the current filesystem and pass number.
 * \return 0 in case of no errors, DIRENT_ABORT in case of error and DIRENT_CHANGED in case
 *	data was moified.
 */
static ATTR((nonnull)) int e2wipe_unrm_dir (
					ext2_ino_t		dir,
					int			entry,
			 		struct ext2_dir_entry*	DIRENT,
					int 			OFFSET,
		/*@unused@*/		int 			BLOCKSIZE ATTR((unused)),
					char* const		BUF,
          				void* const		PRIVATE )
	/*@requires notnull DIRENT,BUF,PRIVATE @*/ {

	const wipedata * const wd = (wipedata*)PRIVATE;
	const unsigned long int j = wd->passno;
	int ret_unrm = WFS_SUCCESS;
	int changed = 0;
	struct ext2_inode unrm_ino;
	char* filename = BUF + OFFSET + sizeof(DIRENT->inode) + sizeof(DIRENT->rec_len)
		+ sizeof(DIRENT->name_len);

	/* is the current entry deleted? */
	if ( (entry == DIRENT_DELETED_FILE) && (sig_recvd == 0) ) {

		fill_buffer ( j, (unsigned char *)filename, (size_t)(DIRENT->name_len & 0xFF) );
		changed = 1;

	/* is the current i-node a directory? If so, dig into it. */
	} else if ( 	(entry != DIRENT_DOT_FILE)
			&& (entry != DIRENT_DOT_DOT_FILE)
			&& (DIRENT->inode != 0)
			&& (DIRENT->inode != dir)
			&& (sig_recvd == 0)
		) {

		error.errcode.e2error = ext2fs_read_inode ( wd->filesys.e2fs, DIRENT->inode, &unrm_ino );
		if ( error.errcode.e2error != 0 ) {
			show_error ( error, err_msg_rdino, fsname );
			ret_unrm = WFS_INOREAD;
		}

	 	if (    (ret_unrm == WFS_SUCCESS)
	 		&& (sig_recvd == 0)
	 		&& LINUX_S_ISDIR(unrm_ino.i_mode)
		) {

			error.errcode.e2error = ext2fs_dir_iterate2 ( wd->filesys.e2fs, DIRENT->inode,
				DIRENT_FLAG_INCLUDE_EMPTY | DIRENT_FLAG_INCLUDE_REMOVED, NULL,
				&e2wipe_unrm_dir, PRIVATE );
			if ( error.errcode.e2error != 0 ) {
				show_error ( error, err_msg_diriter, fsname );
				ret_unrm = WFS_DIRITER;
			}
		}

	} /* do nothing on non-deleted, non-directory i-nodes */

	if ( (ret_unrm != WFS_SUCCESS) || (sig_recvd != 0) ) {
		return DIRENT_ABORT;
	} else if ( changed != 0 ) {
		return DIRENT_CHANGED;
	} else {
		return WFS_SUCCESS;
	}
}

/**
 * Wipes the free space in partially used blocks on the given Ext2/3 filesystem.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int ATTR((warn_unused_result)) wfs_e2wipe_part ( wfs_fsid_t FS ) {

	ext2_inode_scan ino_scan = 0;
	ext2_ino_t ino_number = 0;
	struct ext2_inode ino;
	int ret_part = WFS_SUCCESS;

	error.errcode.e2error = ext2fs_open_inode_scan ( FS.e2fs, 0, &ino_scan );
	if ( error.errcode.e2error != 0 ) {
		show_error ( error, err_msg_openscan, fsname );
		return WFS_INOSCAN;
	} else {

		do {
			error.errcode.e2error = ext2fs_get_next_inode (ino_scan, &ino_number, &ino);
			if ( error.errcode.e2error != 0 ) continue;
			if ( ino_number == 0 ) break;	/* 0 means "last done" */

			if ( ino_number < (ext2_ino_t)EXT2_FIRST_INO(FS.e2fs->super) ) continue;
	        	if ( sig_recvd != 0 ) break;

			if ( ino.i_blocks == 0 ) continue;

			/* e2fsprogs:
		 	 * If i_blocks is non-zero, or the index flag is set, then
		 	 * this is a bogus device/fifo/socket
		 	 */
			if ( (ext2fs_inode_data_blocks(FS.e2fs, &ino) != 0) ||
				((ino.i_flags & EXT2_INDEX_FL) != 0)
			   )
					continue;

		        if ( sig_recvd != 0 ) break;

			/* check if there's unused space in any block */
			if ( (ino.i_size % wfs_e2getblocksize(FS)) == 0 ) continue;

			/* find the last data block number. */
			last_block_no = 0;
			error.errcode.e2error = ext2fs_block_iterate (FS.e2fs, ino_number,
				BLOCK_FLAG_DATA_ONLY, NULL, &e2count_blocks, NULL);
			if ( error.errcode.e2error != 0 ) {
				show_error ( error, err_msg_blkiter, fsname );
				ret_part = WFS_BLKITER;
			}
	        	if ( sig_recvd != 0 ) break;
			/* partially wipe the last block */
			ret_part = e2do_block (FS.e2fs, &last_block_no, 1, &ino);
			if ( ret_part != WFS_SUCCESS ) break;

		} while ( (
				(error.errcode.e2error == 0)
				|| (error.errcode.e2error == EXT2_ET_BAD_BLOCK_IN_INODE_TABLE)
			  ) && (sig_recvd == 0) );

		ext2fs_close_inode_scan (ino_scan);
#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H)
		sync();
#endif
	}
	if ( sig_recvd != 0 ) return WFS_SIGNAL;
	return ret_part;
}

/**
 * Wipes the free space on the given Ext2/3 filesystem.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int ATTR((warn_unused_result)) wfs_e2wipe_fs ( wfs_fsid_t FS ) {

	int ret_wfs = WFS_SUCCESS;
	blk_t blno;			/* block number */

	/* read the bitmap of blocks */
	error.errcode.e2error = ext2fs_read_block_bitmap ( FS.e2fs );
	if ( error.errcode.e2error != 0 ) {
		show_error ( error, err_msg_rdblbm, fsname );
		error.errcode.e2error = ext2fs_close ( FS.e2fs );
		if ( error.errcode.e2error != 0 ) {
			show_error ( error, err_msg_close, fsname );
		}
		return WFS_BLBITMAPREAD;
	}

	/* wiping free blocks on the whole device */
	for ( blno = 1; (blno < FS.e2fs->super->s_blocks_count) && (sig_recvd == 0); blno++ ) {

		/* if we find an empty block, we shred it */
		if ( ext2fs_test_block_bitmap ( FS.e2fs->block_map, blno ) == 0 ) {

			ret_wfs = e2do_block (FS.e2fs, &blno, 1, NULL);
			if ( (ret_wfs != WFS_SUCCESS) || (sig_recvd != 0) ) break;
		}
	}
	if ( sig_recvd != 0 ) return WFS_SIGNAL;
	return ret_wfs;
}

/**
 * Starts recursive directory search for deleted inodes and undelete data on the given Ext2/3 fs.
 * \param FS The filesystem.
 * \param node Directory i-node number.
 * \return 0 in case of no errors, other values otherwise.
 */
int ATTR((warn_unused_result)) wfs_e2wipe_unrm ( wfs_fsid_t FS, fselem_t node ) {

	unsigned long int j;
	wipedata wd;

	wd.filesys = FS;
	for ( j = 0; (j < npasses) && (sig_recvd == 0); j++ ) {

		wd.passno = j;
		error.errcode.e2error = ext2fs_dir_iterate2 ( FS.e2fs, node.e2elem,
			DIRENT_FLAG_INCLUDE_EMPTY | DIRENT_FLAG_INCLUDE_REMOVED, NULL,
			&e2wipe_unrm_dir, &wd );
		if ( error.errcode.e2error != 0 ) {
			show_error ( error, err_msg_diriter, fsname );
			return WFS_DIRITER;
		}
		if ( (npasses > 1) && (sig_recvd == 0) ) {
			error.errcode.gerror = wfs_e2flushfs ( FS );
#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H)
			sync();
#endif
		}
	}

	return WFS_SUCCESS;
}



/**
 * Opens an ext2/3 filesystem on the given device.
 * \param devname Device name, like /dev/hdXY
 * \param FS Pointer to where the result will be put.
 * \param whichfs Pointer to an int saying which fs is curently in use.
 * \param data Pointer to fsdata structure containing information which may be needed to
 *	open the filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int ATTR((warn_unused_result)) ATTR((nonnull)) wfs_e2openfs ( const char*const devname,
	wfs_fsid_t *FS, int *whichfs, fsdata* data ) {

	int ret = WFS_SUCCESS;

	if ( (devname == NULL) || (FS == NULL) || (whichfs == NULL) || (data == NULL) ) {
		return WFS_OPENFS;
	}

	*whichfs = 0;
	error.errcode.e2error = ext2fs_open ( devname, EXT2_FLAG_RW
# ifdef EXT2_FLAG_EXCLUSIVE
		| EXT2_FLAG_EXCLUSIVE
# endif
		, (int)(data->e2fs.super_off), (unsigned int)(data->e2fs.blocksize),
		unix_io_manager, &FS->e2fs );

	if ( error.errcode.e2error != 0 ) {
		ret = WFS_OPENFS;
		error.errcode.e2error = ext2fs_open ( devname, EXT2_FLAG_RW, (int)(data->e2fs.super_off),
			(unsigned int)(data->e2fs.blocksize), unix_io_manager, &FS->e2fs );
	}
	if ( error.errcode.e2error == 0 ) {
		*whichfs = CURR_EXT2FS;
		ret = WFS_SUCCESS;
	}
	return ret;
}

/**
 * Checks if the given ext2/3 filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \return 0 in case of no errors, other values otherwise.
 */
int ATTR((warn_unused_result)) ATTR((nonnull)) wfs_e2chkmount ( const char*const devname ) {

	int ret = WFS_SUCCESS;
	int mtflags = 0;		/* Mount flags */

	initialize_ext2_error_table();

	if ( devname == NULL ) return WFS_MNTCHK;

	/* reject if mounted for read and write (when we can't go on with our work) */
	error.errcode.e2error = ext2fs_check_if_mounted ( devname, &mtflags );
	if ( error.errcode.e2error != 0 ) {

		ret = WFS_MNTCHK;
	}
	if ( 	(ret == WFS_SUCCESS) &&
		((mtflags & EXT2_MF_MOUNTED) != 0) &&
		((mtflags & EXT2_MF_READONLY) == 0)
	) {
		error.errcode.e2error = 1L;
		ret = WFS_MNTRW;
	}

	return ret;
}

/**
 * Closes the ext2/3 filesystem.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int wfs_e2closefs ( wfs_fsid_t FS ) {

	int ret = WFS_SUCCESS;

	error.errcode.e2error = ext2fs_close ( FS.e2fs );
	if ( error.errcode.e2error != 0 ) {
		show_error ( error, err_msg_close, fsname );
		ret = WFS_FSCLOSE;
	}
	return ret;
}

/**
 * Checks if the ext2/3 filesystem has errors.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int ATTR((warn_unused_result)) wfs_e2checkerr ( wfs_fsid_t FS ) {

	return (FS.e2fs->super->s_state & EXT2_ERROR_FS);
}


/**
 * Checks if the ext2/3 filesystem is dirty (has unsaved changes).
 * \param FS The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int ATTR((warn_unused_result)) wfs_e2isdirty ( wfs_fsid_t FS ) {

	return ( ((FS.e2fs->super->s_state & EXT2_VALID_FS) == 0) ||
		((FS.e2fs->flags & EXT2_FLAG_DIRTY) != 0) ||
		(ext2fs_test_changed(FS.e2fs) != 0)
		);
}

/**
 * Flushes the ext2/3 filesystem.
 * \param FS The ext2/3 filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int wfs_e2flushfs ( wfs_fsid_t FS ) {

	int ret = WFS_SUCCESS;

	error.errcode.e2error = ext2fs_flush ( FS.e2fs );
	if ( error.errcode.e2error != 0 ) {
		show_error ( error, err_msg_flush, fsname );
		ret = WFS_FLUSHFS;
	}
	return ret;
}

/**
 * Returns the buffer size needed to work on the smallest physical unit on a ext2/3 filesystem
 * \param FS The filesystem.
 * \return Block size on the filesystem.
 */
int ATTR((warn_unused_result)) wfs_e2getblocksize ( wfs_fsid_t FS ) {

	return EXT2_BLOCK_SIZE(FS.e2fs->super);
}


