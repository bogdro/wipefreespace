/*
 * A program for secure cleaning of free space on filesystems.
 *	-- ext2/3/4 file system-specific functions.
 *
 * Copyright (C) 2007-2022 Bogdan Drozdowski, bogdro (at) users.sourceforge.net
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>		/* dev_t: just for ext2fs.h */
#else
# if defined HAVE_SYS_STAT_H
#  include <sys/stat.h>
# else
#  if !defined HAVE_DEV_T
#   error No dev_t
No dev_t /* make a syntax error, because not all compilers treat #error as an error */
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

#include "wipefreespace.h"

#ifdef HAVE_COM_ERR_H
# include <com_err.h>
#else
# if defined HAVE_ET_COM_ERR_H
#  include <et/com_err.h>
# endif
#endif

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
/* make a syntax error, because not all compilers treat #error as an error */
Something wrong. Ext2/3/4 requested, but ext2fs.h or libext2fs missing.
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

#ifdef HAVE_LIBINTL_H
# include <libintl.h>	/* translation stuff */
#endif

#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif

#include "wfs_ext234.h"
#include "wfs_signal.h"
#include "wfs_util.h"
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

#ifdef TEST_COMPILE
# undef WFS_ANSIC
#endif

/* ======================================================================== */

#ifndef WFS_ANSIC
static size_t GCC_WARN_UNUSED_RESULT wfs_e234_get_block_size WFS_PARAMS ((const wfs_fsid_t wfs_fs));
#endif

/**
 * Returns the buffer size needed to work on the smallest physical unit on a ext2/3/4 filesystem.
 * \param wfs_fs The filesystem.
 * \return Block size on the filesystem.
 */
static size_t GCC_WARN_UNUSED_RESULT
wfs_e234_get_block_size (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs )
#else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
#endif
{
	ext2_filsys e2fs;

	e2fs = (ext2_filsys) wfs_fs.fs_backend;
	if ( e2fs == NULL )
	{
		return 0;
	}
	if ( e2fs->super == NULL )
	{
		return 0;
	}
	return (size_t) EXT2_BLOCK_SIZE (e2fs->super);
}

#ifndef WFS_ANSIC
static int GCC_WARN_UNUSED_RESULT e2_do_block WFS_PARAMS ((const ext2_filsys wfs_fs,
	blk_t * const BLOCKNR, const int BLOCKCNT, void * const PRIVATE));
#endif

/* ======================================================================== */

/**
 * Wipes a block on an ext2/3/4 filesystem and writes it to the media.
 * \param wfs_fs The filesystem which the block is on.
 * \param BLOCKNR Pointer to physical block number.
 * \param BLOCKCNT Block type (<0 for metadata blocks, >=0 is the number of the block in the i-node).
 * \param PRIVATE Private data. Pointer to a 'struct wfs_e234_block_data'.
 * \return 0 in case of no errors, and BLOCK_ABORT in case of signal or error.
 */
static int GCC_WARN_UNUSED_RESULT
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
e2_do_block (
#ifdef WFS_ANSIC
		const ext2_filsys		wfs_fs,
		blk_t * const	 		BLOCKNR,
		const int			BLOCKCNT,
		void * const			PRIVATE)
#else
		wfs_fs, BLOCKNR, BLOCKCNT, PRIVATE)
		const ext2_filsys		wfs_fs;
		blk_t * const	 		BLOCKNR;
		const int			BLOCKCNT;
		void * const			PRIVATE;
#endif
		/*@requires notnull wfs_fs, BLOCKNR @*/
{
	unsigned long int j;
	int returns = 0;
	size_t buf_start = 0;
	int selected[WFS_NPAT] = {0};
	struct wfs_e234_block_data *bd;
	static int first_journ = 1;
	errcode_t * error_ret;
	errcode_t e2error = 0;
	wfs_errcode_t gerror = 0;
	size_t fs_block_size;

	if ( (wfs_fs == NULL) || (BLOCKNR == NULL) || (PRIVATE == NULL) )
	{
		return BLOCK_ABORT;
	}

	bd = (struct wfs_e234_block_data *)PRIVATE;
	error_ret = (errcode_t *) bd->wd.filesys.fs_error;
	if ( bd->wd.buf == NULL )
	{
		return BLOCK_ABORT;
	}
	fs_block_size = wfs_e234_get_block_size (bd->wd.filesys);
	if ( fs_block_size == 0 )
	{
		return BLOCK_ABORT;
	}

	/* for partial wiping: */
	if ( (bd->ino != NULL) && (sig_recvd == 0) )
	{
		buf_start = (size_t)(bd->ino->i_size % fs_block_size);
		/* The beginning of the block must NOT be wiped, read it here. */
		e2error = io_channel_read_blk (wfs_fs->io, *BLOCKNR, 1, bd->wd.buf);
		if ( e2error != 0 )
		{
			if ( error_ret != NULL )
			{
				*error_ret = e2error;
			}
			return BLOCK_ABORT;
		}
	}
	else if ( bd->wd.filesys.no_wipe_zero_blocks != 0 )
	{
		/* read the block to see if it's all-zeros */
		e2error = io_channel_read_blk (wfs_fs->io, *BLOCKNR, 1, bd->wd.buf);
		if ( e2error != 0 )
		{
			if ( error_ret != NULL )
			{
				*error_ret = e2error;
			}
			return BLOCK_ABORT;
		}
	}

	/* mark bad blocks if needed. Taken from libext2fs->lib/ext2fs/inode.c */
	if (wfs_fs->badblocks == NULL)
	{
		e2error = ext2fs_read_bb_inode (wfs_fs, &(wfs_fs->badblocks));
		if ( (e2error != 0) && (wfs_fs->badblocks != NULL) )
		{
			ext2fs_badblocks_list_free (wfs_fs->badblocks);
			wfs_fs->badblocks = NULL;
		}
	}

	/* do nothing on metadata blocks or if incorrect block number given */
	if ( (BLOCKCNT < 0) || (*BLOCKNR == 0) )
	{
		return 0;
	}

	for ( j = 0; (j < bd->wd.filesys.npasses) && (sig_recvd == 0); j++ )
	{
		if ( bd->wd.filesys.no_wipe_zero_blocks != 0 )
		{
			if ( wfs_is_block_zero (bd->wd.buf, fs_block_size) != 0 )
			{
				/* this block is all-zeros - don't wipe, as requested */
				j = bd->wd.filesys.npasses * 2;
				break;
			}
		}
		fill_buffer (j, bd->wd.buf + buf_start /* buf OK */,
			fs_block_size - buf_start,
			selected, bd->wd.filesys);
		if ( sig_recvd != 0 )
		{
			returns = BLOCK_ABORT;
		       	break;
		}
		e2error = 0;
		/* do NOT overwrite the first block of the journal */
		if ( ((bd->wd.isjournal != 0) && (first_journ == 0))
			|| (bd->wd.isjournal == 0) )
		{
			e2error = io_channel_write_blk (
				wfs_fs->io, *BLOCKNR, 1, bd->wd.buf);
		}
		if ( (e2error != 0) )
		{
			/* check if block is marked as bad. If there is no 'badblocks' list
			   or the block is marked OK, then print the error. */
			if (wfs_fs->badblocks == NULL)
			{
				returns = BLOCK_ABORT;
				break;
			}
			else if (ext2fs_badblocks_list_test (
				wfs_fs->badblocks, *BLOCKNR) == 0)
			{
				returns = BLOCK_ABORT;
				break;
			}
		}
		/* Flush after each writing, if more than 1 overwriting needs to be done.
		   Allow I/O bufferring (efficiency), if just one pass is needed. */
		if ( WFS_IS_SYNC_NEEDED(bd->wd.filesys) )
		{
			gerror = wfs_e234_flush_fs (bd->wd.filesys);
		}
	}
	if ( (bd->wd.filesys.zero_pass != 0) && (sig_recvd == 0) )
	{
		/* perform last wipe with zeros */
		if ( j != bd->wd.filesys.npasses * 2 )
		{
			WFS_MEMSET (bd->wd.buf + buf_start, 0,
				fs_block_size - buf_start);
			e2error = 0;
			/* do NOT overwrite the first block of the journal */
			if ( (((bd->wd.isjournal != 0) && (first_journ == 0))
				|| (bd->wd.isjournal == 0))
				&& (sig_recvd == 0) )
			{
				e2error = io_channel_write_blk (
					wfs_fs->io, *BLOCKNR, 1, bd->wd.buf);
			}
			if ( (e2error != 0) )
			{
				/* check if block is marked as bad. If there is no 'badblocks' list
				or the block is marked OK, then print the error. */
				if (wfs_fs->badblocks == NULL)
				{
					returns = BLOCK_ABORT;
				}
				else if (ext2fs_badblocks_list_test (
					wfs_fs->badblocks, *BLOCKNR) == 0)
				{
					returns = BLOCK_ABORT;
				}
			}
			/* No need to flush the last writing of a given block. *
			if ( (bd->wd.filesys.npasses > 1) && (sig_recvd == 0) )
			{
				gerror = wfs_e234_flush_fs (bd->wd.filesys);
			}*/
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
			j = 1;
			if ( bd->wd.filesys.no_wipe_zero_blocks != 0 )
			{
				if ( wfs_is_block_zero (bd->wd.buf,
					fs_block_size) != 0 )
				{
					/* this block is all-zeros - don't wipe, as requested */
					j = 0;
				}
			}
			if ( j == 1 )
			{
				WFS_MEMSET (bd->wd.buf + buf_start, 0,
					fs_block_size - buf_start);
				if ( sig_recvd != 0 )
				{
					returns = BLOCK_ABORT;
				}
				e2error = io_channel_write_blk (wfs_fs->io,
					*BLOCKNR, 1, bd->wd.buf);
				if ( (e2error != 0) )
				{
					/* check if block is marked as bad. If there is no 'badblocks' list
					or the block is marked OK, then print the error. */
					if (wfs_fs->badblocks == NULL)
					{
						returns = BLOCK_ABORT;
					}
					else if (ext2fs_badblocks_list_test (
						wfs_fs->badblocks, *BLOCKNR) == 0)
					{
						returns = BLOCK_ABORT;
					}
				}
				/* No need to flush the last writing of a given block. *
				if ( (bd->wd.filesys.npasses > 1) && (sig_recvd == 0) )
				{
					gerror = wfs_e234_flush_fs (bd->wd.filesys);
				} */
			}
		}
		bd->curr_inode++;
		wfs_show_progress (WFS_PROGRESS_UNRM,
			50 /* unrm i-nodes */ + (bd->curr_inode * 50)/(bd->number_of_blocks_in_inode),
			& (bd->prev_percent));
	}
	if ( error_ret != NULL )
	{
		if ( e2error != 0 )
		{
			*error_ret = e2error;
		}
		else
		{
			*error_ret = (errcode_t)gerror;
		}
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
static int e2_count_blocks WFS_PARAMS ((const ext2_filsys wfs_fs WFS_ATTR ((unused)),
	blk_t * const BLOCKNR, const int BLOCKCNT WFS_ATTR ((unused)), void * PRIVATE));
# endif

/* ======================================================================== */

/**
 * Finds the last block number used by an ext2/3/4 i-node. Simply gets all block numbers one at
 * a time and saves the last one.
 * \param wfs_fs The filesystem which the block is on (unused).
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
		/*@unused@*/ 		const ext2_filsys	wfs_fs WFS_ATTR ((unused)),
					blk_t * const		BLOCKNR,
		/*@unused@*/ 		const int		BLOCKCNT WFS_ATTR ((unused)),
					void *			PRIVATE
		)
# else
		/*@unused@*/ 		wfs_fs,
					BLOCKNR,
		/*@unused@*/ 		BLOCKCNT,
					PRIVATE
		)
		/*@unused@*/ 		const ext2_filsys	wfs_fs WFS_ATTR ((unused));
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
	int selected[WFS_NPAT] = {0};
	ext2_filsys e2fs;
	errcode_t * error_ret;
	errcode_t e2error = 0;

	if ( (DIRENT == NULL) || (BUF == NULL) || (PRIVATE == NULL) )
	{
		return DIRENT_ABORT;
	}

	filename = BUF + OFFSET + sizeof (DIRENT->inode) + sizeof (DIRENT->rec_len)
		+ sizeof (DIRENT->name_len);
	bd = (struct wfs_e234_block_data *) PRIVATE;
	e2fs = (ext2_filsys) bd->wd.filesys.fs_backend;
	error_ret = (errcode_t *) bd->wd.filesys.fs_error;
	if ( e2fs == NULL )
	{
		return DIRENT_ABORT;
	}
	if ( e2fs->super == NULL )
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
					(size_t) (DIRENT->name_len & 0xFF),
					selected, wd->filesys);
			}
			else
			{
				WFS_MEMSET ((unsigned char *)filename, 0,
					(size_t)(DIRENT->name_len&0xFF));
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
				(size_t) (DIRENT->name_len & 0xFF),
				selected, wd->filesys);
			if ( j == wd->filesys.npasses-1 )
			{
				DIRENT->name_len = 0;
				DIRENT->inode = 0;
			}
		}
		changed = 1;
		bd->curr_inode++;
		wfs_show_progress (WFS_PROGRESS_UNRM,
			(bd->curr_inode * 50) *
			(unsigned int)(wd->passno / wd->filesys.npasses) /
			(e2fs->super->s_inodes_count - e2fs->super->s_free_inodes_count),
			& (bd->prev_percent));
	}		/* is the current i-node a directory? If so, dig into it. */
	else if ( 	(entry != DIRENT_DOT_FILE)
			&& (entry != DIRENT_DOT_DOT_FILE)
			&& (DIRENT->inode != 0)
			&& (DIRENT->inode != dir)
			&& (sig_recvd == 0)
		)
	{
		e2error = ext2fs_read_inode (e2fs,
			DIRENT->inode, &unrm_ino);
		if ( e2error != 0 )
		{
			ret_unrm = WFS_INOREAD;
		}

	 	if (    (ret_unrm == WFS_SUCCESS)
	 		&& (sig_recvd == 0)
	 		&& LINUX_S_ISDIR (unrm_ino.i_mode)
		   )
		{
			e2error = ext2fs_dir_iterate2 ( e2fs, DIRENT->inode,
				DIRENT_FLAG_INCLUDE_EMPTY | DIRENT_FLAG_INCLUDE_REMOVED,
				NULL, &e2_wipe_unrm_dir, PRIVATE );
			bd->curr_inode++;
			wfs_show_progress (WFS_PROGRESS_UNRM,
				(bd->curr_inode * 50) *
				(unsigned int)(wd->passno / wd->filesys.npasses) /
				(e2fs->super->s_inodes_count - e2fs->super->s_free_inodes_count),
				& (bd->prev_percent));
			if ( e2error != 0 )
			{
				ret_unrm = WFS_DIRITER;
			}
		}

	} /* do nothing on non-deleted, non-directory i-nodes */

	if ( error_ret != NULL )
	{
		*error_ret = e2error;
	}
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
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_e234_wipe_part (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
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
	ext2_filsys e2fs;
	errcode_t * error_ret;
	errcode_t e2error = 0;
	wfs_errcode_t gerror = 0;
	size_t fs_block_size;

	e2fs = (ext2_filsys) wfs_fs.fs_backend;
	error_ret = (errcode_t *) wfs_fs.fs_error;
	if ( e2fs == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = WFS_BADPARAM;
		}
		return WFS_BADPARAM;
	}
	if ( e2fs->super == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = WFS_BADPARAM;
		}
		return WFS_BADPARAM;
	}
	fs_block_size = wfs_e234_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	WFS_SET_ERRNO (0);
	block_data.wd.buf = (unsigned char *) malloc (fs_block_size);
	if ( block_data.wd.buf == NULL )
	{
		e2error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = e2error;
		}
		return WFS_MALLOC;
	}
	block_data.wd.filesys = wfs_fs;
	block_data.wd.passno = 0;
	block_data.wd.ret_val = WFS_SUCCESS;
	block_data.wd.total_fs = 0;	/* dummy value, unused */
	block_data.wd.isjournal = 0;

	e2error = ext2fs_open_inode_scan (e2fs, 0, &ino_scan);
	if ( e2error != 0 )
	{
		free (block_data.wd.buf);
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = e2error;
		}
		return WFS_INOSCAN;
	}
	else
	{
		do
		{
			e2error = ext2fs_get_next_inode (
				ino_scan, &ino_number, &ino);

			if ( e2error != 0 )
			{
				curr_inode++;
				wfs_show_progress (WFS_PROGRESS_PART,
					(curr_inode * 100)/(e2fs->super->s_inodes_count
						- e2fs->super->s_free_inodes_count),
					&prev_percent);
				continue;
			}
			if ( ino_number == 0 )
			{
				break;	/* 0 means "last done" */
			}

			if ( ino_number < (ext2_ino_t) EXT2_FIRST_INO (e2fs->super) )
			{
				curr_inode++;
				wfs_show_progress (WFS_PROGRESS_PART,
					(curr_inode * 100)/(e2fs->super->s_inodes_count
						- e2fs->super->s_free_inodes_count),
					&prev_percent);
				continue;
			}

	        	if ( sig_recvd != 0 )
			{
				break;
			}

			/* skip if no data blocks */
			if ( ext2fs_inode_data_blocks (e2fs, &ino) == 0 )
			{
				curr_inode++;
				wfs_show_progress (WFS_PROGRESS_PART,
					(curr_inode * 100)/(e2fs->super->s_inodes_count
						- e2fs->super->s_free_inodes_count),
					&prev_percent);
				continue;
			}

			/* e2fsprogs:
		 	 * If the index flag is set, then
		 	 * this is a bogus device/fifo/socket
		 	 */
			if ( /*(ext2fs_inode_data_blocks (e2fs, &ino) != 0) ||*/
				((ino.i_flags & EXT2_INDEX_FL) != 0)
			   )
			{
				curr_inode++;
				wfs_show_progress (WFS_PROGRESS_PART,
					(curr_inode * 100)/(e2fs->super->s_inodes_count
						- e2fs->super->s_free_inodes_count),
					&prev_percent);
				continue;
			}

		        if ( sig_recvd != 0 )
			{
				break;
			}

			/* check if there's unused space in any block */
			if ( (ino.i_size % fs_block_size) == 0 )
			{
				curr_inode++;
				wfs_show_progress (WFS_PROGRESS_PART,
					(curr_inode * 100)/(e2fs->super->s_inodes_count
						- e2fs->super->s_free_inodes_count),
					&prev_percent);
				continue;
			}

			/* find the last data block number. */
			last_block_no = 0;
			e2error = ext2fs_block_iterate (e2fs, ino_number,
				BLOCK_FLAG_DATA_ONLY, NULL, &e2_count_blocks,
				&last_block_no);
			if ( e2error != 0 )
			{
				ret_part = WFS_BLKITER;
				break;
			}
	        	if ( sig_recvd != 0 )
			{
				break;
			}
			/* partially wipe the last block */
			block_data.ino = &ino;
			ret_part = e2_do_block (e2fs, &last_block_no,
				1, &block_data);

			if ( ret_part != WFS_SUCCESS )
			{
				if ( error_ret != NULL )
				{
					/* get the error back */
					e2error = *error_ret;
				}
				ret_part = WFS_BLKITER;
				break;
			}

			curr_inode++;
			wfs_show_progress (WFS_PROGRESS_PART,
				(curr_inode * 100)/(e2fs->super->s_inodes_count
					- e2fs->super->s_free_inodes_count),
				&prev_percent);
		}
		while ( (
				(e2error == 0)
				|| (e2error == EXT2_ET_BAD_BLOCK_IN_INODE_TABLE)
			) && (sig_recvd == 0) );

		ext2fs_close_inode_scan (ino_scan);
		if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
		{
			gerror = wfs_e234_flush_fs (wfs_fs);
		}
	}
	wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
	free (block_data.wd.buf);

	if ( error_ret != NULL )
	{
		if ( e2error != 0 )
		{
			*error_ret = e2error;
		}
		else
		{
			*error_ret = (errcode_t)gerror;
		}
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
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_e234_wipe_fs (
# ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	blk_t blno;			/* block number */
	struct wfs_e234_block_data block_data;
	unsigned int prev_percent = 0;
	int block_ret = 0;
	ext2_filsys e2fs;
	errcode_t * error_ret;
	errcode_t e2error = 0;
	size_t fs_block_size;

	e2fs = (ext2_filsys) wfs_fs.fs_backend;
	error_ret = (errcode_t *) wfs_fs.fs_error;
	if ( e2fs == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = WFS_BADPARAM;
		}
		return WFS_BADPARAM;
	}
	if ( e2fs->super == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = WFS_BADPARAM;
		}
		return WFS_BADPARAM;
	}
	fs_block_size = wfs_e234_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	WFS_SET_ERRNO (0);
	block_data.wd.buf = (unsigned char *) malloc (fs_block_size);
	if ( block_data.wd.buf == NULL )
	{
		e2error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = e2error;
		}
		return WFS_MALLOC;
	}
	block_data.wd.filesys = wfs_fs;
	block_data.wd.passno = 0;
	block_data.wd.ret_val = WFS_SUCCESS;
	block_data.wd.total_fs = 0;	/* dummy value, unused */
	block_data.ino = NULL;
	block_data.wd.isjournal = 0;
	block_data.curr_inode = 0;
	block_data.prev_percent = 0;
	block_data.number_of_blocks_in_inode = 0;

	/* read the bitmap of blocks */
	e2error = ext2fs_read_block_bitmap (e2fs);
	if ( e2error != 0 )
	{
		free (block_data.wd.buf);
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = e2error;
		}
		return WFS_BLBITMAPREAD;
	}

	/* wiping free blocks on the whole device */
	for ( blno = 1; (blno < e2fs->super->s_blocks_count)
		&& (sig_recvd == 0); blno++ )
	{
		/* if we find an empty block, we shred it */
		if ( ext2fs_test_block_bitmap (e2fs->block_map, blno) == 0 )
		{
			block_ret = e2_do_block (e2fs, &blno, 1, &block_data);
			wfs_show_progress (WFS_PROGRESS_WFS,
				(blno * 100)/e2fs->super->s_blocks_count,
				&prev_percent);
			if ( (block_ret != 0) || (sig_recvd != 0) )
			{
				ret_wfs = WFS_BLKWR;
				break;
			}
		}
	}
	wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
	free (block_data.wd.buf);
	if ( error_ret != NULL )
	{
		*error_ret = e2error;
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
static wfs_errcode_t wfs_e234_wipe_journal WFS_PARAMS ((const wfs_fsid_t wfs_fs));
# endif

/**
 * Wipes the journal on an ext2/3/4 filesystem.
 * \param wfs_fs The ext2/3/4 filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
static wfs_errcode_t
wfs_e234_wipe_journal (
# ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_journ = WFS_SUCCESS;
	struct wfs_e234_block_data block_data;
	struct ext2_inode jino;
	ext2_filsys e2fs;
	errcode_t * error_ret;
	errcode_t e2error = 0;
	size_t fs_block_size;

	e2fs = (ext2_filsys) wfs_fs.fs_backend;
	error_ret = (errcode_t *) wfs_fs.fs_error;
	if ( e2fs == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = WFS_BADPARAM;
		}
		return WFS_BADPARAM;
	}
	if ( e2fs->super == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = WFS_BADPARAM;
		}
		return WFS_BADPARAM;
	}
	block_data.wd.filesys = wfs_fs;
	block_data.wd.passno = 0;
	block_data.wd.ret_val = WFS_SUCCESS;
	block_data.wd.total_fs = 0;	/* dummy value, unused */
	block_data.ino = NULL;
	block_data.wd.isjournal = 1;
	block_data.curr_inode = 0;
	block_data.prev_percent = 50;

# if (defined EXT2_HAS_COMPAT_FEATURE) && (defined EXT3_FEATURE_COMPAT_HAS_JOURNAL)
	if ( EXT2_HAS_COMPAT_FEATURE (e2fs->super, EXT3_FEATURE_COMPAT_HAS_JOURNAL)
		!= EXT3_FEATURE_COMPAT_HAS_JOURNAL)
	{
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &(block_data.prev_percent));
		if ( error_ret != NULL )
		{
			*error_ret = e2error;
		}
		return ret_journ;
	}
# endif
	/* do nothing if external journal */
	if ( e2fs->super->s_journal_inum == 0 )
	{
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &(block_data.prev_percent));
		if ( error_ret != NULL )
		{
			*error_ret = e2error;
		}
		return ret_journ;
	}

	fs_block_size = wfs_e234_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	WFS_SET_ERRNO (0);
	block_data.wd.buf = (unsigned char *) malloc (fs_block_size);
	if ( block_data.wd.buf == NULL )
	{
		e2error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &(block_data.prev_percent));
		if ( error_ret != NULL )
		{
			*error_ret = e2error;
		}
		return WFS_MALLOC;
	}

	e2error = ext2fs_read_inode (e2fs, e2fs->super->s_journal_inum, &jino);
	if ( e2error != 0 )
	{
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &(block_data.prev_percent));
		if ( error_ret != NULL )
		{
			*error_ret = e2error;
		}
		return WFS_BLKITER;
	}
	block_data.number_of_blocks_in_inode = jino.i_blocks;

	e2error = ext2fs_block_iterate (e2fs,
		e2fs->super->s_journal_inum,	/*EXT2_JOURNAL_INO,*/
		BLOCK_FLAG_DATA_ONLY, NULL, &e2_do_block, &block_data);

	if ( e2error != 0 )
	{
		ret_journ = WFS_BLKITER;
	}

	wfs_show_progress (WFS_PROGRESS_UNRM, 100, &(block_data.prev_percent));
	free (block_data.wd.buf);
	if ( error_ret != NULL )
	{
		*error_ret = e2error;
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
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_e234_wipe_unrm (
# ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
# endif
{
	unsigned long int j;
	struct wfs_e234_block_data bd;
	wfs_errcode_t ret = WFS_SUCCESS;
	ext2_filsys e2fs;
	errcode_t * error_ret;
	errcode_t e2error = 0;
	wfs_errcode_t gerror = 0;

	e2fs = (ext2_filsys) wfs_fs.fs_backend;
	error_ret = (errcode_t *) wfs_fs.fs_error;
	if ( e2fs == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = WFS_BADPARAM;
		}
		return WFS_BADPARAM;
	}

	bd.wd.filesys = wfs_fs;
	bd.wd.passno = 0;
	bd.wd.ret_val = WFS_SUCCESS;
	bd.wd.total_fs = 0;	/* dummy value, unused */
	bd.curr_inode = 0;
	bd.prev_percent = 0;

	for ( j = 0; (j <= wfs_fs.npasses) && (sig_recvd == 0)
		/*&& (ret == WFS_SUCCESS)*/; j++ )
	{
		if ( (wfs_fs.zero_pass == 0) && (j == wfs_fs.npasses) )
		{
			break;
		}
		bd.wd.passno = j;
		e2error = ext2fs_dir_iterate2 (e2fs, EXT2_ROOT_INO,
			DIRENT_FLAG_INCLUDE_EMPTY | DIRENT_FLAG_INCLUDE_REMOVED,
			NULL, &e2_wipe_unrm_dir, &bd);
		if ( e2error != 0 )
		{
			ret = WFS_DIRITER;
			break;
		}
		if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
		{
			gerror = wfs_e234_flush_fs (wfs_fs);
		}
	}

	wfs_show_progress (WFS_PROGRESS_UNRM, 50, &(bd.prev_percent));
	if ( sig_recvd != 0 )
	{
		ret = WFS_SIGNAL;
	}
	if ( ret == WFS_SUCCESS )
	{
		ret = wfs_e234_wipe_journal (wfs_fs);
	}
	else if ( ret != WFS_SIGNAL )
	{
		wfs_e234_wipe_journal (wfs_fs);
	}
	else
	{
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &(bd.prev_percent));
	}
	if ( error_ret != NULL )
	{
		if ( e2error != 0 )
		{
			*error_ret = e2error;
		}
		else
		{
			*error_ret = (errcode_t)gerror;
		}
	}

	return ret;
}
#endif /* WFS_WANT_UNRM */

/* ======================================================================== */

/**
 * Opens an ext2/3/4 filesystem on the given device.
 * \param devname Device name, like /dev/hdXY
 * \param wfs_fs Pointer to where the result will be put.
 * \param whichfs Pointer to an int saying which fs is curently in use.
 * \param data Pointer to wfs_fsdata_t structure containing information which may be needed to
 *	open the filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_e234_open_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t * const wfs_fs,
	const wfs_fsdata_t * const data)
#else
	wfs_fs, data)
	wfs_fsid_t * const wfs_fs;
	const wfs_fsdata_t * const data;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	errcode_t * error_ret;
	errcode_t e2error = 0;

	if ((wfs_fs == NULL) || (data == NULL))
	{
		return WFS_BADPARAM;
	}
	error_ret = (errcode_t *) wfs_fs->fs_error;
	if ( wfs_fs->fsname == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = 100;
		}
		return WFS_BADPARAM;
	}

	wfs_fs->whichfs = WFS_CURR_FS_NONE;
	e2error = ext2fs_open (wfs_fs->fsname, EXT2_FLAG_RW
#ifdef EXT2_FLAG_EXCLUSIVE
		| EXT2_FLAG_EXCLUSIVE
#endif
		, (int)(data->e2fs.super_off), data->e2fs.blocksize,
		unix_io_manager, (ext2_filsys *) &(wfs_fs->fs_backend));

	if ( e2error != 0 )
	{
		ret = WFS_OPENFS;
		e2error = ext2fs_open (wfs_fs->fsname, EXT2_FLAG_RW,
			(int)(data->e2fs.super_off),
			data->e2fs.blocksize,
			unix_io_manager,
			(ext2_filsys *) &(wfs_fs->fs_backend));
	}
	if ( e2error == 0 )
	{
		wfs_fs->whichfs = WFS_CURR_FS_EXT234FS;
		ret = WFS_SUCCESS;
	}
	if ( error_ret != NULL )
	{
		*error_ret = e2error;
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
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_e234_chk_mount (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	int mtflags = 0;		/* Mount flags */
	wfs_errcode_t error = 0;
	errcode_t e2error = 0;
	errcode_t * error_ret;

	error_ret = (errcode_t *) wfs_fs.fs_error;
	if ( wfs_fs.fsname == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = WFS_BADPARAM;
		}
		return WFS_BADPARAM;
	}

	/* reject if mounted for read and write (when we can't go on with our work) */
	e2error = ext2fs_check_if_mounted (wfs_fs.fsname, &mtflags);
	if ( e2error != 0 )
	{
		error = e2error;
		ret = WFS_MNTCHK;
	}

	if ( 	(ret == WFS_SUCCESS) &&
		((mtflags & EXT2_MF_MOUNTED) != 0) &&
		((mtflags & EXT2_MF_READONLY) == 0)
	   )
	{
		error = 1L;
		ret = WFS_MNTRW;
	}

	if ( ret == WFS_SUCCESS )
	{
		ret = wfs_check_mounted (wfs_fs);
		if ( ret == WFS_MNTRW )
		{
			error = 1L;
		}
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
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_e234_close_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	errcode_t wfs_err;
	ext2_filsys e2fs;
	errcode_t * error_ret;

	e2fs = (ext2_filsys) wfs_fs.fs_backend;
	error_ret = (errcode_t *) wfs_fs.fs_error;
	if ( e2fs == NULL )
	{
		return WFS_BADPARAM;
	}

	wfs_err = ext2fs_close (e2fs);
	if ( wfs_err != 0 )
	{
		ret = WFS_FSCLOSE;
		if ( error_ret != NULL )
		{
			*error_ret = wfs_err;
		}
	}
	return ret;
}

/* ======================================================================== */

/**
 * Checks if the ext2/3/4 filesystem has errors.
 * \param wfs_fs The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_e234_check_err (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
#endif
{
	ext2_filsys e2fs;

	e2fs = (ext2_filsys) wfs_fs.fs_backend;
	if ( e2fs != NULL )
	{
		if ( e2fs->super != NULL )
		{
			return (e2fs->super->s_state & EXT2_ERROR_FS);
		}
	}
	return 1;
}


/* ======================================================================== */

/**
 * Checks if the ext2/3/4 filesystem is dirty (has unsaved changes).
 * \param wfs_fs The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_e234_is_dirty (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
#endif
{
	ext2_filsys e2fs;

	e2fs = (ext2_filsys) wfs_fs.fs_backend;
	if ( e2fs == NULL )
	{
		return 1;
	}
	if ( e2fs->super == NULL )
	{
		return 1;
	}
	return ( ((e2fs->super->s_state & EXT2_VALID_FS) == 0) ||
		((e2fs->flags & EXT2_FLAG_DIRTY) != 0) ||
		(ext2fs_test_changed (e2fs) != 0)
		);
}

/* ======================================================================== */

/**
 * Flushes the ext2/3/4 filesystem.
 * \param wfs_fs The ext2/3/4 filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_e234_flush_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	errcode_t wfs_err;
	ext2_filsys e2fs;
	errcode_t * error_ret;

	e2fs = (ext2_filsys) wfs_fs.fs_backend;
	error_ret = (errcode_t *) wfs_fs.fs_error;
	if ( e2fs == NULL )
	{
		return WFS_BADPARAM;
	}
	wfs_err = ext2fs_flush (e2fs);
	if ( wfs_err != 0 )
	{
		ret = WFS_FLUSHFS;
		if ( error_ret != NULL )
		{
			*error_ret = wfs_err;
		}
	}
#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_SYNC)
	sync ();
#endif
	return ret;
}

/* ======================================================================== */

/**
 * Print the version of the current library, if applicable.
 */
void wfs_e234_print_version (WFS_VOID)
{
	const char *lib_ver = NULL;

	ext2fs_get_library_version ( &lib_ver, NULL );
	printf ( "Libext2fs %s Copyright (C) Theodore Ts'o\n",
		(lib_ver != NULL)? lib_ver: "<?>" );
}

/* ======================================================================== */

/**
 * Get the preferred size of the error variable.
 * \return the preferred size of the error variable.
 */
size_t wfs_e234_get_err_size (WFS_VOID)
{
	return sizeof (errcode_t);
}

/* ======================================================================== */

/**
 * Initialize the library.
 */
void wfs_e234_init (WFS_VOID)
{
	initialize_ext2_error_table ();
}

/* ======================================================================== */

/**
 * De-initialize the library.
 */
void wfs_e234_deinit (WFS_VOID)
{
#if (defined HAVE_COM_ERR_H) || (defined HAVE_ET_COM_ERR_H)
	remove_error_table (&et_ext2_error_table);
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
wfs_e234_show_error (
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
#if ((defined HAVE_ET_COM_ERR_H) || (defined HAVE_COM_ERR_H)) && (defined HAVE_LIBCOM_ERR)
	errcode_t e = 0;
	const char * progname;
#endif

	if ( (wfs_is_stderr_open() == 0) || (msg == NULL) )
	{
		return;
	}
#if ((defined HAVE_ET_COM_ERR_H) || (defined HAVE_COM_ERR_H)) && (defined HAVE_LIBCOM_ERR)
	if ( wfs_fs.fs_error != NULL )
	{
		e = *(errcode_t *)(wfs_fs.fs_error);
	}

	progname = wfs_get_program_name();
	com_err ((progname != NULL)? progname : "",
		e,
		WFS_ERR_MSG_FORMATL,
		_(wfs_err_msg),
		e,
		_(msg),
		(extra != NULL)? extra : "",
		(wfs_fs.fsname != NULL)? wfs_fs.fsname : "");
#else
	wfs_show_fs_error_gen (msg, extra, wfs_fs);
#endif
	fflush (stderr);
}
