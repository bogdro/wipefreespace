/*
 * A program for secure cleaning of free space on filesystems.
 *	-- ext2/3/4 file system-specific functions.
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>		/* dev_t: just for ext2fs.h */
#else
# if defined HAVE_SYS_STAT_H
#  include <sys/stat.h>
# else
#  if !defined HAVE_DEV_T
#   error No dev_t
#  endif
# endif
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
# if ((!defined STDC_HEADERS) || (!STDC_HEADERS)) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>	/* memset() */
#endif

/* redefine the inline sig function from hfsp, each time with a different name */
extern unsigned long int wfs_e234_sig(char c0, char c1, char c2, char c3);
#define sig(a,b,c,d) wfs_e234_sig(a,b,c,d)

#include "wipefreespace.h"
/* fix conflict with reiser4: */
#undef blk_t

/* fix e2fsprogs inline functions - some linkers saw double definitions and
   failed with an error message */
#if (defined HAVE_LIBEXT2FS) && ((defined HAVE_EXT2FS_EXT2FS_H) || (defined HAVE_EXT2FS_H))
# ifndef _EXT2_USE_C_VERSIONS_
#  define _EXT2_USE_C_VERSIONS_	1
# endif
# ifndef NO_INLINE_FUNCS
#  define NO_INLINE_FUNCS	1
# endif
#endif

#if (defined HAVE_EXT2FS_EXT2FS_H) && (defined HAVE_LIBEXT2FS)
# include <ext2fs/ext2fs.h>
#else
# if (defined HAVE_EXT2FS_H) && (defined HAVE_LIBEXT2FS)
#  include <ext2fs.h>
# else
#  error Something wrong. Ext2/3/4 requested, but ext2fs.h or libext2fs missing.
# endif
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* sync() */
#endif

/*
#ifdef HAVE_MALLOC_H
# include <malloc.h>
#else
*/
#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#include "wfs_ext234.h"
#include "wfs_signal.h"
#include "wfs_wiping.h"

struct wfs_e234_block_data
{
	struct ext2_inode *ino;
	/* progress bar stuff: */
	unsigned int curr_inode;
	wfs_wipedata_t wd;
	unsigned int prev_percent;
	unsigned int number_of_blocks_in_inode;
};

/* ======================================================================== */

#ifndef WFS_ANSIC
static size_t WFS_ATTR ((warn_unused_result)) wfs_e234_get_block_size WFS_PARAMS ((const wfs_fsid_t FS));
#endif

/**
 * Returns the buffer size needed to work on the smallest physical unit on a ext2/3/4 filesystem.
 * \param FS The filesystem.
 * \return Block size on the filesystem.
 */
static size_t WFS_ATTR ((warn_unused_result))
wfs_e234_get_block_size (
#ifdef WFS_ANSIC
	const wfs_fsid_t FS )
#else
	FS)
	const wfs_fsid_t FS;
#endif
{
	if ( FS.e2fs == NULL )
	{
		return 0;
	}
	if ( FS.e2fs->super == NULL )
	{
		return 0;
	}
	return (size_t) EXT2_BLOCK_SIZE (FS.e2fs->super);
}

#ifndef WFS_ANSIC
static int WFS_ATTR ((warn_unused_result)) e2_do_block WFS_PARAMS ((const ext2_filsys FS,
	blk_t * const BLOCKNR, const int BLOCKCNT, void * const PRIVATE));
#endif

/* ======================================================================== */

/**
 * Wipes a block on an ext2/3/4 filesystem and writes it to the media.
 * \param FS The filesystem which the block is on.
 * \param BLOCKNR Pointer to physical block number.
 * \param BLOCKCNT Block type (<0 for metadata blocks, >=0 is the number of the block in the i-node).
 * \param PRIVATE Private data. Pointer to a 'struct wfs_e234_block_data'.
 * \return 0 in case of no errors, and BLOCK_ABORT in case of signal or error.
 */
static int WFS_ATTR ((warn_unused_result))
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
e2_do_block (
#ifdef WFS_ANSIC
		const ext2_filsys		FS,
		blk_t * const	 		BLOCKNR,
		const int			BLOCKCNT,
		void * const			PRIVATE)
#else
		FS, BLOCKNR, BLOCKCNT, PRIVATE)
		const ext2_filsys		FS;
		blk_t * const	 		BLOCKNR;
		const int			BLOCKCNT;
		void * const			PRIVATE;
#endif
		/*@requires notnull FS, BLOCKNR @*/
{
	unsigned long int j;
	int returns = 0;
	size_t buf_start = 0;
	int selected[WFS_NPAT];
	wfs_error_type_t error;
	struct wfs_e234_block_data *bd;
	static int first_journ = 1;

	if ( (FS == NULL) || (BLOCKNR == NULL) || (PRIVATE == NULL) )
	{
		return BLOCK_ABORT;
	}

	bd = (struct wfs_e234_block_data *)PRIVATE;
	if ( (bd->ino == NULL) || (bd->wd.buf == NULL) )
	{
		return BLOCK_ABORT;
	}

	/* for partial wiping: */
	if ( (bd->ino != NULL) && (sig_recvd == 0) )
	{
		buf_start = (size_t)(bd->ino->i_size % wfs_e234_get_block_size (bd->wd.filesys));
		/* The beginning of the block must NOT be wiped, read it here. */
		error.errcode.e2error = io_channel_read_blk (FS->io, *BLOCKNR, 1, bd->wd.buf);
		if ( error.errcode.e2error != 0 )
		{
			return BLOCK_ABORT;
		}
	}

	/* mark bad blocks if needed. Taken from libext2fs->lib/ext2fs/inode.c */
	if (FS->badblocks == NULL)
	{
		error.errcode.e2error = ext2fs_read_bb_inode (FS, &(FS->badblocks));
		if ( (error.errcode.e2error != 0) && (FS->badblocks != NULL) )
		{
			ext2fs_badblocks_list_free (FS->badblocks);
			FS->badblocks = NULL;
		}
	}

	/* do nothing on metadata blocks or if incorrect block number given */
	if ( (BLOCKCNT < 0) || (*BLOCKNR == 0) )
	{
		return WFS_SUCCESS;
	}

	for ( j = 0; (j < bd->wd.filesys.npasses) && (sig_recvd == 0); j++ )
	{
		fill_buffer (j, bd->wd.buf + buf_start /* buf OK */,
			wfs_e234_get_block_size (bd->wd.filesys) - buf_start, selected, bd->wd.filesys);
		if ( sig_recvd != 0 )
		{
			returns = BLOCK_ABORT;
		       	break;
		}
		error.errcode.e2error = 0;
		/* do NOT overwrite the first block of the journal */
		if ( ((bd->wd.isjournal != 0) && (first_journ == 0)) || (bd->wd.isjournal == 0) )
		{
			error.errcode.e2error = io_channel_write_blk (FS->io, *BLOCKNR, 1, bd->wd.buf);
		}
		if ( (error.errcode.e2error != 0) )
		{
			/* check if block is marked as bad. If there is no 'badblocks' list
			   or the block is marked OK, then print the error. */
			if (FS->badblocks == NULL)
			{
				returns = BLOCK_ABORT;
				break;
			}
			else if (ext2fs_badblocks_list_test (FS->badblocks, *BLOCKNR) == 0)
			{
				returns = BLOCK_ABORT;
				break;
			}
		}
		/* Flush after each writing, if more than 1 overwriting needs to be done.
		   Allow I/O bufferring (efficiency), if just one pass is needed. */
		if ( (bd->wd.filesys.npasses > 1) && (sig_recvd == 0) )
		{
			error.errcode.gerror = wfs_e234_flush_fs (bd->wd.filesys, &error);
		}
	}
	if ( (bd->wd.filesys.zero_pass != 0) && (sig_recvd == 0) )
	{
		/* perform last wipe with zeros */
#ifdef HAVE_MEMSET
		memset (bd->wd.buf + buf_start, 0, wfs_e234_get_block_size (bd->wd.filesys) - buf_start);
#else
		for ( j=0; j < wfs_e234_get_block_size (bd->wd.filesys) - buf_start; j++ )
		{
			bd->wd.buf[buf_start+j] = '\0';
		}
#endif
		error.errcode.e2error = 0;
		/* do NOT overwrite the first block of the journal */
		if ( (((bd->wd.isjournal != 0) && (first_journ == 0)) || (bd->wd.isjournal == 0))
			&& (sig_recvd == 0) )
		{
			error.errcode.e2error = io_channel_write_blk (FS->io, *BLOCKNR, 1, bd->wd.buf);
		}
		if ( (error.errcode.e2error != 0) )
		{
			/* check if block is marked as bad. If there is no 'badblocks' list
			   or the block is marked OK, then print the error. */
			if (FS->badblocks == NULL)
			{
				returns = BLOCK_ABORT;
			}
			else if (ext2fs_badblocks_list_test (FS->badblocks, *BLOCKNR) == 0)
			{
				returns = BLOCK_ABORT;
			}
		}
		/* Flush after each writing, if more than 1 overwriting needs to be done.
		   Allow I/O bufferring (efficiency), if just one pass is needed. */
		if ( (bd->wd.filesys.npasses > 1) && (sig_recvd == 0) )
		{
			error.errcode.gerror = wfs_e234_flush_fs (bd->wd.filesys, &error);
		}
	}
	/* zero-out the journal after wiping */
	if ( (bd->wd.isjournal != 0) && (sig_recvd == 0) )
	{
		/* skip the first block of the journal */
		if ( first_journ != 0 )
		{
			first_journ--;
		}
		else
		{
#ifdef HAVE_MEMSET
			memset (bd->wd.buf + buf_start, 0,
				wfs_e234_get_block_size (bd->wd.filesys) - buf_start);
#else
			for ( j=0; j < wfs_e234_get_block_size (bd->wd.filesys) - buf_start; j++ )
			{
				bd->wd.buf[buf_start+j] = '\0';
			}
#endif
			if ( sig_recvd != 0 )
			{
				returns = BLOCK_ABORT;
			}
			error.errcode.e2error = io_channel_write_blk (FS->io, *BLOCKNR, 1, bd->wd.buf);
			if ( (error.errcode.e2error != 0) )
			{
				/* check if block is marked as bad. If there is no 'badblocks' list
				   or the block is marked OK, then print the error. */
				if (FS->badblocks == NULL)
				{
					returns = BLOCK_ABORT;
				}
				else if (ext2fs_badblocks_list_test (FS->badblocks, *BLOCKNR) == 0)
				{
					returns = BLOCK_ABORT;
				}
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			   Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (bd->wd.filesys.npasses > 1) && (sig_recvd == 0) )
			{
				error.errcode.gerror = wfs_e234_flush_fs (bd->wd.filesys, &error);
			}
		}
		bd->curr_inode++;
		show_progress (WFS_PROGRESS_UNRM,
			50 /* unrm i-nodes */ + (bd->curr_inode * 50)/(bd->number_of_blocks_in_inode),
			& (bd->prev_percent));
	}
	if ( sig_recvd != 0 )
	{
		return BLOCK_ABORT;
	}
	else
	{
		return returns;
	}
}

#ifdef WFS_WANT_PART
# ifndef WFS_ANSIC
static int e2_count_blocks WFS_PARAMS ((const ext2_filsys FS WFS_ATTR ((unused)),
	blk_t * const BLOCKNR, const int BLOCKCNT WFS_ATTR ((unused)), void * PRIVATE));
# endif

/* ======================================================================== */

/**
 * Finds the last block number used by an ext2/3/4 i-node. Simply gets all block numbers one at
 * a time and saves the last one.
 * \param FS The filesystem which the block is on (unused).
 * \param BLOCKNR Pointer to physical block number.
 * \param BLOCKCNT Block type (<0 for metadata blocks, >=0 is the number
 *	of the block in the i-node), unused.
 * \param PRIVATE Private data (unused).
 * \return This function always returns 0.
 */
static int
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
e2_count_blocks (
# ifdef WFS_ANSIC
		/*@unused@*/ 		const ext2_filsys	FS WFS_ATTR ((unused)),
					blk_t * const		BLOCKNR,
		/*@unused@*/ 		const int		BLOCKCNT WFS_ATTR ((unused)),
					void *			PRIVATE
		)
# else
		/*@unused@*/ 		FS,
					BLOCKNR,
		/*@unused@*/ 		BLOCKCNT,
					PRIVATE
		)
		/*@unused@*/ 		const ext2_filsys	FS WFS_ATTR ((unused));
					blk_t * const		BLOCKNR;
		/*@unused@*/ 		const int		BLOCKCNT WFS_ATTR ((unused));
					void *			PRIVATE;
# endif
		/*@requires notnull BLOCKNR, PRIVATE @*/
{
	if ( (BLOCKNR == NULL) || (PRIVATE == NULL) )
	{
		return BLOCK_ABORT;
	}
	*((blk_t*)PRIVATE) = *BLOCKNR;
	return 0;
}
#endif /* WFS_WANT_PART */

/* ======================================================================== */

#ifdef WFS_WANT_UNRM
# ifndef WFS_ANSIC
static int e2_wipe_unrm_dir WFS_PARAMS ((ext2_ino_t dir, int entry, struct ext2_dir_entry * DIRENT,
	int OFFSET, int BLOCKSIZE WFS_ATTR ((unused)), char * const BUF, void * const PRIVATE ));
# endif

/**
 * Wipes undelete information from the given ext2/3/4 directory i-node.
 * \param dir I-node number of the direcotry being browsed.
 * \param entry Type of directory entry.
 * \param DIRENT Pointer to a ext2_dir_entry structure describing current directory entry.
 * \param OFFSET Offset of the ext2_dir_entry structure from beginning of the directory block.
 * \param BLOCKSIZE Size of a block on the file system (unused).
 * \param BUF Pointer to contents of the directory block.
 * \param PRIVATE Points to a wfs_wipedata_t structure, describing the current filesystem and pass number.
 * \return 0 in case of no errors, DIRENT_ABORT in case of error and DIRENT_CHANGED in case
 *	data was moified.
 */
static int
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
e2_wipe_unrm_dir (
# ifdef WFS_ANSIC
			ext2_ino_t		dir,
			int			entry,
	 		struct ext2_dir_entry*	DIRENT,
			int 			OFFSET,
	/*@unused@*/	int 			BLOCKSIZE WFS_ATTR ((unused)),
			char* const		BUF,
       			void* const		PRIVATE )
# else
			dir,
			entry,
	 		DIRENT,
			OFFSET,
	/*@unused@*/	BLOCKSIZE,
			BUF,
       			PRIVATE )
			ext2_ino_t		dir;
			int			entry;
	 		struct ext2_dir_entry*	DIRENT;
			int 			OFFSET;
	/*@unused@*/	int 			BLOCKSIZE WFS_ATTR ((unused));
			char* const		BUF;
       			void* const		PRIVATE;
# endif
	/*@requires notnull DIRENT, BUF, PRIVATE @*/
{
	struct wfs_e234_block_data * bd;
	const wfs_wipedata_t * wd;
	unsigned long int j;
	wfs_errcode_t ret_unrm = WFS_SUCCESS;
	int changed = 0;
	struct ext2_inode unrm_ino;
	char* filename;
	int selected[WFS_NPAT];
	wfs_error_type_t error;

	if ( (DIRENT == NULL) || (BUF == NULL) || (PRIVATE == NULL) )
	{
		return DIRENT_ABORT;
	}

	filename = BUF + OFFSET + sizeof (DIRENT->inode) + sizeof (DIRENT->rec_len)
		+ sizeof (DIRENT->name_len);
	bd = (struct wfs_e234_block_data *) PRIVATE;
	if ( bd->wd.filesys.e2fs == NULL )
	{
		return DIRENT_ABORT;
	}
	if ( bd->wd.filesys.e2fs->super == NULL )
	{
		return DIRENT_ABORT;
	}
	wd = & (bd->wd);
	j = wd->passno;

	/* is the current entry deleted? */
	if ( (entry == DIRENT_DELETED_FILE) && (sig_recvd == 0) )
	{
		if ( wd->filesys.zero_pass != 0 )
		{
			if ( j < wd->filesys.npasses )
			{
				fill_buffer (j, (unsigned char *)filename /* buf OK */,
					(size_t) (DIRENT->name_len & 0xFF), selected, wd->filesys);
			}
			else
			{
# ifdef HAVE_MEMSET
				memset ((unsigned char *)filename, 0, (size_t)(DIRENT->name_len&0xFF));
# else
				for ( j=0; j < (size_t) (DIRENT->name_len & 0xFF); j++ )
				{
					filename[j] = '\0';
				}
# endif
				if ( j == wd->filesys.npasses )
				{
					DIRENT->name_len = 0;
					DIRENT->inode = 0;
				}
			}
		}
		else
		{
			fill_buffer (j, (unsigned char *)filename /* buf OK */,
				(size_t) (DIRENT->name_len & 0xFF), selected, wd->filesys);
			if ( j == wd->filesys.npasses-1 )
			{
				DIRENT->name_len = 0;
				DIRENT->inode = 0;
			}
		}
		changed = 1;
	}		/* is the current i-node a directory? If so, dig into it. */
	else if ( 	(entry != DIRENT_DOT_FILE)
			&& (entry != DIRENT_DOT_DOT_FILE)
			&& (DIRENT->inode != 0)
			&& (DIRENT->inode != dir)
			&& (sig_recvd == 0)
		)
	{
		error.errcode.e2error = ext2fs_read_inode (wd->filesys.e2fs, DIRENT->inode, &unrm_ino);
		if ( error.errcode.e2error != 0 )
		{
			ret_unrm = WFS_INOREAD;
		}

	 	if (    (ret_unrm == WFS_SUCCESS)
	 		&& (sig_recvd == 0)
	 		&& LINUX_S_ISDIR (unrm_ino.i_mode)
		   )
		{
			error.errcode.e2error = ext2fs_dir_iterate2 ( wd->filesys.e2fs, DIRENT->inode,
				DIRENT_FLAG_INCLUDE_EMPTY | DIRENT_FLAG_INCLUDE_REMOVED, NULL,
				&e2_wipe_unrm_dir, PRIVATE );
			bd->curr_inode++;
			show_progress (WFS_PROGRESS_UNRM,
				(bd->curr_inode * 50)/(wd->filesys.e2fs->super->s_inodes_count
					- wd->filesys.e2fs->super->s_free_inodes_count),
				& (bd->prev_percent));
			if ( error.errcode.e2error != 0 )
			{
				ret_unrm = WFS_DIRITER;
			}
		}

	} /* do nothing on non-deleted, non-directory i-nodes */

	if ( (ret_unrm != WFS_SUCCESS) || (sig_recvd != 0) )
	{
		return DIRENT_ABORT;
	}
	else if ( changed != 0 )
	{
		return DIRENT_CHANGED;
	}
	else
	{
		return 0;
	}
}
#endif /* WFS_WANT_UNRM */

/* ======================================================================== */

#ifdef WFS_WANT_PART
/**
 * Wipes the free space in partially used blocks on the given ext2/3/4 filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_e234_wipe_part (
# ifdef WFS_ANSIC
	wfs_fsid_t FS, wfs_error_type_t * const error_ret)
# else
	FS, error_ret)
	wfs_fsid_t FS;
	wfs_error_type_t * const error_ret;
# endif
{
	ext2_inode_scan ino_scan = 0;
	ext2_ino_t ino_number = 0;
	struct ext2_inode ino;
	wfs_errcode_t ret_part = WFS_SUCCESS;
	blk_t last_block_no = 0;
	struct wfs_e234_block_data block_data;
	unsigned int prev_percent = 0;
	unsigned int curr_inode = 0;
	wfs_error_type_t error = {CURR_EXT234FS, {0}};

	if ( FS.e2fs == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	if ( FS.e2fs->super == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	block_data.wd.buf = (unsigned char *) malloc (wfs_e234_get_block_size (FS));
	if ( block_data.wd.buf == NULL )
	{
# ifdef HAVE_ERRNO_H
		error.errcode.gerror = errno;
# else
		error.errcode.gerror = 12L;	/* ENOMEM */
# endif
		show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}
	block_data.wd.filesys = FS;
	block_data.wd.passno = 0;
	block_data.wd.ret_val = WFS_SUCCESS;
	block_data.wd.total_fs = 0;	/* dummy value, unused */
	block_data.wd.isjournal = 0;

	error.errcode.e2error = ext2fs_open_inode_scan (FS.e2fs, 0, &ino_scan);
	if ( error.errcode.e2error != 0 )
	{
		free (block_data.wd.buf);
		show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_INOSCAN;
	}
	else
	{
		do
		{
			error.errcode.e2error = ext2fs_get_next_inode (ino_scan, &ino_number, &ino);

			if ( error.errcode.e2error != 0 )
			{
				continue;
			}
			if ( ino_number == 0 )
			{
				break;	/* 0 means "last done" */
			}

			if ( ino_number < (ext2_ino_t) EXT2_FIRST_INO (FS.e2fs->super) )
			{
				continue;
			}

	        	if ( sig_recvd != 0 )
			{
				break;
			}

			/* skip if no data blocks */
			if ( ext2fs_inode_data_blocks (FS.e2fs, &ino) == 0 )
			{
				continue;
			}

			/* e2fsprogs:
		 	 * If the index flag is set, then
		 	 * this is a bogus device/fifo/socket
		 	 */
			if ( /*(ext2fs_inode_data_blocks (FS.e2fs, &ino) != 0) ||*/
				((ino.i_flags & EXT2_INDEX_FL) != 0)
			   )
			{
				continue;
			}

		        if ( sig_recvd != 0 )
			{
				break;
			}

			/* check if there's unused space in any block */
			if ( (ino.i_size % wfs_e234_get_block_size (FS)) == 0 )
			{
				continue;
			}

			/* find the last data block number. */
			last_block_no = 0;
			error.errcode.e2error = ext2fs_block_iterate (FS.e2fs, ino_number,
				BLOCK_FLAG_DATA_ONLY, NULL, &e2_count_blocks, &last_block_no);
			if ( error.errcode.e2error != 0 )
			{
				ret_part = WFS_BLKITER;
			}
	        	if ( sig_recvd != 0 )
			{
				break;
			}
			/* partially wipe the last block */
			block_data.ino = &ino;
			ret_part = e2_do_block (FS.e2fs, &last_block_no, 1, &block_data);

			if ( ret_part != WFS_SUCCESS )
			{
				break;
			}

			curr_inode++;
			show_progress (WFS_PROGRESS_PART,
				(curr_inode * 100)/(FS.e2fs->super->s_inodes_count
					- FS.e2fs->super->s_free_inodes_count),
				&prev_percent);
		}
		while ( (
				(error.errcode.e2error == 0)
				|| (error.errcode.e2error == EXT2_ET_BAD_BLOCK_IN_INODE_TABLE)
			) && (sig_recvd == 0) );

		ext2fs_close_inode_scan (ino_scan);
		if ( (FS.npasses > 1) && (sig_recvd == 0) )
		{
			error.errcode.gerror = wfs_e234_flush_fs (FS, &error);
		}
	}
	show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
	free (block_data.wd.buf);
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	if ( sig_recvd != 0 )
	{
		return WFS_SIGNAL;
	}
	return ret_part;
}
#endif /* WFS_WANT_PART */

/* ======================================================================== */

#ifdef WFS_WANT_WFS
/**
 * Wipes the free space on the given ext2/3/4 filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_e234_wipe_fs (
# ifdef WFS_ANSIC
	const wfs_fsid_t FS, wfs_error_type_t * const error_ret)
# else
	FS, error_ret)
	const wfs_fsid_t FS;
	wfs_error_type_t * const error_ret;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	blk_t blno;			/* block number */
	struct wfs_e234_block_data block_data;
	unsigned int prev_percent = 0;
	wfs_error_type_t error = {CURR_EXT234FS, {0}};

	if ( FS.e2fs == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	if ( FS.e2fs->super == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	block_data.wd.buf = (unsigned char *) malloc (wfs_e234_get_block_size (FS));
	if ( block_data.wd.buf == NULL )
	{
# ifdef HAVE_ERRNO_H
		error.errcode.gerror = errno;
# else
		error.errcode.gerror = 12L;	/* ENOMEM */
# endif
		show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}
	block_data.wd.filesys = FS;
	block_data.wd.passno = 0;
	block_data.wd.ret_val = WFS_SUCCESS;
	block_data.wd.total_fs = 0;	/* dummy value, unused */
	block_data.ino = NULL;
	block_data.wd.isjournal = 0;
	block_data.curr_inode = 0;
	block_data.prev_percent = 0;
	block_data.number_of_blocks_in_inode = 0;

	/* read the bitmap of blocks */
	error.errcode.e2error = ext2fs_read_block_bitmap (FS.e2fs);
	if ( error.errcode.e2error != 0 )
	{
		error.errcode.e2error = ext2fs_close (FS.e2fs);
		free (block_data.wd.buf);
		show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BLBITMAPREAD;
	}

	/* wiping free blocks on the whole device */
	for ( blno = 1; (blno < FS.e2fs->super->s_blocks_count) && (sig_recvd == 0); blno++ )
	{
		/* if we find an empty block, we shred it */
		if ( ext2fs_test_block_bitmap (FS.e2fs->block_map, blno) == 0 )
		{
			ret_wfs = e2_do_block (FS.e2fs, &blno, 1, &block_data);
			show_progress (WFS_PROGRESS_WFS, (blno * 100)/FS.e2fs->super->s_blocks_count,
				&prev_percent);
			if ( (ret_wfs != WFS_SUCCESS) || (sig_recvd != 0) )
			{
				break;
			}
		}
	}
	show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
	free (block_data.wd.buf);
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	if ( sig_recvd != 0 )
	{
		return WFS_SIGNAL;
	}
	return ret_wfs;
}
#endif /* WFS_WANT_WFS */

/* ======================================================================== */

#ifdef WFS_WANT_UNRM
# ifndef WFS_ANSIC
static wfs_errcode_t wfs_e234_wipe_journal WFS_PARAMS ((const wfs_fsid_t FS, wfs_error_type_t * const error));
# endif

/**
 * Wipes the journal on an ext2/3/4 filesystem.
 * \param FS The ext2/3/4 filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
static wfs_errcode_t
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_e234_wipe_journal (
# ifdef WFS_ANSIC
	const wfs_fsid_t FS, wfs_error_type_t * const error_ret)
# else
	FS, error_ret )
	const wfs_fsid_t FS;
	wfs_error_type_t * const error_ret;
# endif
{
	wfs_errcode_t ret_journ = WFS_SUCCESS;
	struct wfs_e234_block_data block_data;
	struct ext2_inode jino;
	wfs_error_type_t error = {CURR_EXT234FS, {0}};

	if ( FS.e2fs == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	if ( FS.e2fs->super == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	block_data.wd.filesys = FS;
	block_data.wd.passno = 0;
	block_data.wd.ret_val = WFS_SUCCESS;
	block_data.wd.total_fs = 0;	/* dummy value, unused */
	block_data.ino = NULL;
	block_data.wd.isjournal = 1;
	block_data.curr_inode = 0;
	block_data.prev_percent = 50;

# if (defined EXT2_HAS_COMPAT_FEATURE) && (defined EXT3_FEATURE_COMPAT_HAS_JOURNAL)
	if ( EXT2_HAS_COMPAT_FEATURE (FS.e2fs->super, EXT3_FEATURE_COMPAT_HAS_JOURNAL)
		!= EXT3_FEATURE_COMPAT_HAS_JOURNAL)
	{
		show_progress (WFS_PROGRESS_UNRM, 100, &(block_data.prev_percent));
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return ret_journ;
	}
# endif
	/* do nothing if external journal */
	if ( FS.e2fs->super->s_journal_inum == 0 )
	{
		show_progress (WFS_PROGRESS_UNRM, 100, &(block_data.prev_percent));
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return ret_journ;
	}

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	block_data.wd.buf = (unsigned char *) malloc ( wfs_e234_get_block_size (FS) );
	if ( block_data.wd.buf == NULL )
	{
# ifdef HAVE_ERRNO_H
		error.errcode.gerror = errno;
# else
		error.errcode.gerror = 12L;	/* ENOMEM */
# endif
		show_progress (WFS_PROGRESS_UNRM, 100, &(block_data.prev_percent));
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	error.errcode.e2error = ext2fs_read_inode (FS.e2fs, FS.e2fs->super->s_journal_inum, &jino);
	block_data.number_of_blocks_in_inode = jino.i_blocks;

	error.errcode.e2error = ext2fs_block_iterate (FS.e2fs,
		FS.e2fs->super->s_journal_inum,	/*EXT2_JOURNAL_INO,*/
		BLOCK_FLAG_DATA_ONLY, NULL, &e2_do_block, &block_data);

	if ( error.errcode.e2error != 0 )
	{
		ret_journ = WFS_BLKITER;
	}

	show_progress (WFS_PROGRESS_UNRM, 100, &(block_data.prev_percent));
	free (block_data.wd.buf);
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	if ( sig_recvd != 0 )
	{
		return WFS_SIGNAL;
	}
	return ret_journ;
}

/* ======================================================================== */

/**
 * Starts recursive directory search for deleted inodes and undelete data on the given ext2/3/4 fs.
 * \param FS The filesystem.
 * \param node Directory i-node number.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_e234_wipe_unrm (
# ifdef WFS_ANSIC
	const wfs_fsid_t FS, const wfs_fselem_t node, wfs_error_type_t * const error_ret)
# else
	FS, node, error_ret)
	const wfs_fsid_t FS;
	const wfs_fselem_t node;
	wfs_error_type_t * const error_ret;
# endif
{
	unsigned long int j;
	struct wfs_e234_block_data bd;
	wfs_errcode_t ret = WFS_SUCCESS;
	wfs_error_type_t error = {CURR_EXT234FS, {0}};

	if ( FS.e2fs == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}

	bd.wd.filesys = FS;
	bd.wd.passno = 0;
	bd.wd.ret_val = WFS_SUCCESS;
	bd.wd.total_fs = 0;	/* dummy value, unused */
	bd.curr_inode = 0;
	bd.prev_percent = 0;

	for ( j = 0; (j <= FS.npasses) && (sig_recvd == 0) /*&& (ret == WFS_SUCCESS)*/; j++ )
	{
		if ( (FS.zero_pass == 0) && (j == FS.npasses) )
		{
			break;
		}
		bd.wd.passno = j;
		error.errcode.e2error = ext2fs_dir_iterate2 (FS.e2fs, node.e2elem,
			DIRENT_FLAG_INCLUDE_EMPTY | DIRENT_FLAG_INCLUDE_REMOVED, NULL,
			&e2_wipe_unrm_dir, &bd);
		if ( error.errcode.e2error != 0 )
		{
			ret = WFS_DIRITER;
			break;
		}
		if ( (FS.npasses > 1) && (sig_recvd == 0) )
		{
			error.errcode.gerror = wfs_e234_flush_fs (FS, &error);
		}
	}

	show_progress (WFS_PROGRESS_UNRM, 50, &(bd.prev_percent));
	if ( ret == WFS_SUCCESS )
	{
		ret = wfs_e234_wipe_journal (FS, &error);
	}
	else if ( ret != WFS_SIGNAL )
	{
		wfs_e234_wipe_journal (FS, &error);
	}
	else
	{
		show_progress (WFS_PROGRESS_UNRM, 100, &(bd.prev_percent));
	}
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}

	return ret;
}
#endif /* WFS_WANT_UNRM */

/* ======================================================================== */

/**
 * Opens an ext2/3/4 filesystem on the given device.
 * \param devname Device name, like /dev/hdXY
 * \param FS Pointer to where the result will be put.
 * \param whichfs Pointer to an int saying which fs is curently in use.
 * \param data Pointer to wfs_fsdata_t structure containing information which may be needed to
 *	open the filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_e234_open_fs (
#ifdef WFS_ANSIC
	const char * const dev_name, wfs_fsid_t * const FS, wfs_curr_fs_t * const whichfs,
	const wfs_fsdata_t * const data, wfs_error_type_t * const error_ret)
#else
	dev_name, FS, whichfs, data, error_ret)
	const char * const dev_name;
	wfs_fsid_t * const FS;
	wfs_curr_fs_t * const whichfs;
	const wfs_fsdata_t * const data;
	wfs_error_type_t * const error_ret;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	wfs_error_type_t error = {CURR_EXT234FS, {0}};

	if ((dev_name == NULL) || (FS == NULL) || (whichfs == NULL) || (data == NULL))
	{
		return WFS_BADPARAM;
	}

	*whichfs = CURR_NONE;
	error.errcode.e2error = ext2fs_open (dev_name, EXT2_FLAG_RW
#ifdef EXT2_FLAG_EXCLUSIVE
		| EXT2_FLAG_EXCLUSIVE
#endif
		, (int)(data->e2fs.super_off), (unsigned int) (data->e2fs.blocksize),
		unix_io_manager, &(FS->e2fs));

	if ( error.errcode.e2error != 0 )
	{
		ret = WFS_OPENFS;
		error.errcode.e2error = ext2fs_open (dev_name, EXT2_FLAG_RW, (int)(data->e2fs.super_off),
			(unsigned int) (data->e2fs.blocksize), unix_io_manager, &(FS->e2fs));
	}
	if ( error.errcode.e2error == 0 )
	{
		*whichfs = CURR_EXT234FS;
		ret = WFS_SUCCESS;
	}
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return ret;
}

/* ======================================================================== */

/**
 * Checks if the given ext2/3/4 filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_e234_chk_mount (
#ifdef WFS_ANSIC
	const char * const dev_name, wfs_error_type_t * const error_ret)
#else
	dev_name, error_ret)
	const char * const dev_name;
	wfs_error_type_t * const error_ret;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	int mtflags = 0;		/* Mount flags */
	wfs_error_type_t error = {CURR_EXT234FS, {0}};

	initialize_ext2_error_table ();

	if ( dev_name == NULL )
	{
		return WFS_BADPARAM;
	}

	/* reject if mounted for read and write (when we can't go on with our work) */
	error.errcode.e2error = ext2fs_check_if_mounted (dev_name, &mtflags);
	if ( error.errcode.e2error != 0 )
	{
		ret = WFS_MNTCHK;
	}
	if ( 	(ret == WFS_SUCCESS) &&
		((mtflags & EXT2_MF_MOUNTED) != 0) &&
		((mtflags & EXT2_MF_READONLY) == 0)
	   )
	{
		error.errcode.e2error = 1L;
		ret = WFS_MNTRW;
	}
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}

	return ret;
}

/* ======================================================================== */

/**
 * Closes the ext2/3/4 filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_e234_close_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t FS, wfs_error_type_t * const error)
#else
	FS, error)
	wfs_fsid_t FS;
	wfs_error_type_t * const error;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	errcode_t wfs_err;

	if ( FS.e2fs == NULL )
	{
		return WFS_BADPARAM;
	}

	wfs_err = ext2fs_close (FS.e2fs);
	if ( wfs_err != 0 )
	{
		ret = WFS_FSCLOSE;
		if ( error != NULL )
		{
			error->errcode.e2error = wfs_err;
		}
	}
	return ret;
}

/* ======================================================================== */

/**
 * Checks if the ext2/3/4 filesystem has errors.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_e234_check_err (
#ifdef WFS_ANSIC
	const wfs_fsid_t FS)
#else
	FS)
	const wfs_fsid_t FS;
#endif
{
	return (FS.e2fs->super->s_state & EXT2_ERROR_FS);
}


/* ======================================================================== */

/**
 * Checks if the ext2/3/4 filesystem is dirty (has unsaved changes).
 * \param FS The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_e234_is_dirty (
#ifdef WFS_ANSIC
	const wfs_fsid_t FS)
#else
	FS)
	const wfs_fsid_t FS;
#endif
{
	if ( FS.e2fs == NULL )
	{
		return 1;
	}
	if ( FS.e2fs->super == NULL )
	{
		return 1;
	}
	return ( ((FS.e2fs->super->s_state & EXT2_VALID_FS) == 0) ||
		((FS.e2fs->flags & EXT2_FLAG_DIRTY) != 0) ||
		(ext2fs_test_changed (FS.e2fs) != 0)
		);
}

/* ======================================================================== */

/**
 * Flushes the ext2/3/4 filesystem.
 * \param FS The ext2/3/4 filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_e234_flush_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t FS, wfs_error_type_t * const error)
#else
	FS, error)
	wfs_fsid_t FS;
	wfs_error_type_t * const error;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	errcode_t wfs_err;

	if ( FS.e2fs == NULL )
	{
		return WFS_BADPARAM;
	}
	wfs_err = ext2fs_flush (FS.e2fs);
	if ( wfs_err != 0 )
	{
		ret = WFS_FLUSHFS;
		if ( error != NULL )
		{
			error->errcode.e2error = wfs_err;
		}
	}
#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_SYNC)
	sync ();
#endif
	return ret;
}
