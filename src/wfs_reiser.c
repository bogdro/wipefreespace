/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- ReiserFSv3 file system-specific functions.
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef MAJOR_IN_MKDEV
# include <sys/mkdev.h>
#else
# if defined MAJOR_IN_SYSMACROS
#  include <sys/sysmacros.h>
# else /* ! MAJOR_IN_SYSMACROS */
#  ifdef HAVE_SYS_SYSMACROS_H
#   include <sys/sysmacros.h>
#  endif
#  ifdef HAVE_SYS_MKDEV_H
#   include <sys/mkdev.h>
#  endif
# endif /* MAJOR_IN_SYSMACROS */
#endif

#ifdef HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>
#endif

#ifdef HAVE_ASM_TYPES_H
# include <asm/types.h>
#else
typedef unsigned int __u32;
typedef short int __u16;
#endif

#ifndef MAJOR_IN_MKDEV
# define MAJOR_IN_MKDEV 0
#endif

#ifndef MAJOR_IN_SYSMACROS
# define MAJOR_IN_SYSMACROS 0
#endif

#if (defined HAVE_REISERFS_LIB_H) && (defined HAVE_LIBCORE)
/* Avoid some Reiser3 header files' name conflicts:
 reiserfs_lib.h uses the same name for a function and a variable,
 so let's redefine one to avoid name conflicts */
# define div reiser_div
# define index reiser_index
# define key_format(x) key_format0 (x)
# include <reiserfs_lib.h>
# include <io.h>
# undef div
# undef index
# undef key_format
#else
# error Something wrong. ReiserFS requested, but headers or library missing.
/* make a syntax error, because not all compilers treat #error as an error */
Something wrong. ReiserFS requested, but headers or library missing.
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* sync() */
#endif

/*
#ifdef HAVE_MALLOC_H
# include <malloc.h>
#else
*/

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_STRING_H
# if ((!defined STDC_HEADERS) || (!STDC_HEADERS)) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>	/* O_EXCL, O_RDWR */
#endif

#ifndef O_EXCL
# define O_EXCL		0200
#endif
#ifndef O_RDWR
# define O_RDWR		02
#endif

#include "wipefreespace.h"
#include "wfs_reiser.h"
#include "wfs_signal.h"
#include "wfs_util.h"
#include "wfs_wiping.h"
#include "wfs_mount_check.h"

#ifdef HAVE_REISER3_NEW_BREAD
# define bread reiser3_new_bread
#else
# if (defined WFS_JFS) && (! defined HAVE_JFS_BREAD)
#  warning Detected unpatched Reiser3FS library with JFS enabled. WipeFreeSpace can crash! Read README.
# endif
#endif

/* Fix the sizes. */
static const unsigned long long int bh_dirty = BH_Dirty;
static const unsigned long long int bh_up2date = BH_Uptodate;
#define mark_buffer_dirty2(bh)    misc_set_bit (bh_dirty,   &(bh)->b_state)
#define mark_buffer_uptodate2(bh) misc_set_bit (bh_up2date, &(bh)->b_state)

#ifdef TEST_COMPILE
# undef WFS_ANSIC
#endif

/* ======================================================================== */

#ifndef WFS_ANSIC
static size_t GCC_WARN_UNUSED_RESULT wfs_reiser_get_block_size
	WFS_PARAMS ((const wfs_fsid_t wfs_fs));
#endif

/**
 * Returns the buffer size needed to work on the
 *	smallest physical unit on a ReiserFS filesystem.
 * \param wfs_fs The filesystem.
 * \return Block size on the filesystem.
 */
static size_t GCC_WARN_UNUSED_RESULT
wfs_reiser_get_block_size (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs )
#else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
#endif
{
	reiserfs_filsys_t * rfs;

	rfs = (reiserfs_filsys_t *) wfs_fs.fs_backend;
	if ( rfs == NULL )
	{
		return 0;
	}
	return rfs->fs_blocksize;
}


/* ======================================================================== */

#ifdef WFS_WANT_PART
/**
 * Wipes the free space in partially used blocks on the given ReiserFS filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_reiser_wipe_part (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_part = WFS_SUCCESS;
	struct key elem_key, *next_key;
	struct buffer_head * bh;
	struct path elem_path;
	struct item_head *head;
	int i;
	unsigned char * buf;
	unsigned long int j;
	int selected[WFS_NPAT] = {0};
	char * offset;
	unsigned long int length;
	unsigned int prev_percent = 0;
	unsigned long int curr_direlem = 0;
	wfs_errcode_t error = 0;
	reiserfs_filsys_t * rfs;
	wfs_errcode_t * error_ret;
	size_t fs_block_size;

	rfs = (reiserfs_filsys_t *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( rfs == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	fs_block_size = wfs_reiser_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	WFS_SET_ERRNO (0);
	buf = (unsigned char *) malloc ( fs_block_size );
	if ( buf == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (ENOMEM);
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	elem_key = root_dir_key;
	elem_path.path_length = ILLEGAL_PATH_ELEMENT_OFFSET;
	while ( (ret_part == WFS_SUCCESS)
		&& (reiserfs_search_by_key_4 ( rfs, &elem_key,
			&elem_path ) == ITEM_FOUND)
		&& (sig_recvd == 0)
		)
	{
        	bh = PATH_PLAST_BUFFER (&elem_path);
        	if ( bh == NULL )
        	{
			pathrelse (&elem_path);
        		break;
        	}
		if (       (not_data_block   ( rfs, bh->b_blocknr ) != 0)
			|| (block_of_bitmap  ( rfs, bh->b_blocknr ) != 0)
			|| (block_of_journal ( rfs, bh->b_blocknr ) != 0)
			|| (B_NR_ITEMS (bh) > 1)	/* not supported */
		   )
		{
			next_key = reiserfs_next_key (&elem_path);
			if (next_key != NULL)
			{
				elem_key = *next_key;
			}
			else
			{
				WFS_MEMSET (&elem_key, 0xff, KEY_SIZE);
			}

			pathrelse (&elem_path);
			if (bh->b_count != 0)
			{
				brelse (bh);
			}
			continue;
		}

		if ( sig_recvd != 0 )
		{
			pathrelse (&elem_path);
			if (bh->b_count != 0)
			{
				brelse (bh);
			}
			ret_part = WFS_SIGNAL;
	       		break;
		}

		head = get_ih (&elem_path);
		if ( head != NULL )
		{
			if ( get_key_dirid (&(head->ih_key))
				== get_key_objectid (&root_dir_key) )
			{
				curr_direlem++;
				wfs_show_progress (WFS_PROGRESS_PART,
					(unsigned int)((curr_direlem * 100)
					/get_ih_entry_count (head)),
					&prev_percent);
			}
		}
		for (i = get_item_pos (&elem_path);
			(i < (int)B_NR_ITEMS (bh))
			&& (sig_recvd == 0) /*&& (ret_part == WFS_SUCCESS)*/;
			i++, head++)
		{
			next_key = reiserfs_next_key (&elem_path);
			if (next_key != NULL)
			{
				elem_key = *next_key;
			}
			else
			{
				WFS_MEMSET (&elem_key, 0xff, KEY_SIZE);
			}

			if ( head == NULL )
			{
				continue;
			}
			if ( (bh->b_data == NULL)
				|| (head->ih2_item_len >= fs_block_size)
				|| (head->ih2_item_location + head->ih2_item_len >=
					(int)fs_block_size)
				|| (head->ih2_item_location >= fs_block_size)
				|| ((unsigned long)head->ih2_item_location
					+ (unsigned long)head->ih2_item_len >= bh->b_size)
				)
			{
				continue;
			}
			offset = &(bh->b_data[head->ih2_item_location
				+ head->ih2_item_len]);
			length = bh->b_size - (unsigned long int)(head->ih2_item_location
				+ head->ih2_item_len);
			if ( (long int)length < 0 )
			{
				length = 0;
			}

			for ( j = 0; (j < wfs_fs.npasses) && (sig_recvd == 0)
				/*&& (ret_part == WFS_SUCCESS)*/; j++ )
			{
				wfs_fill_buffer ( j, (unsigned char *) offset,
					(size_t) length, selected, wfs_fs );

				if ( sig_recvd != 0 )
				{
					ret_part = WFS_SIGNAL;
       					break;
				}
				mark_buffer_dirty2 (bh);
				mark_buffer_uptodate2 (bh);

 				error = bwrite (bh);
				if ( error != 0 )
				{
					/* check if block is marked as bad. If there is no
					   'badblocks' list or the block is marked OK,
					   then print the error. */
					if (rfs->fs_badblocks_bm == NULL)
					{
						ret_part = WFS_BLKWR;
						break;
					}
					else if (reiserfs_bitmap_test_bit (
						rfs->fs_badblocks_bm,
						(unsigned int)(bh->b_blocknr & 0x0FFFFFFFF)) == 0)
					{
						ret_part = WFS_BLKWR;
						break;
					}
				}
				/* Flush after each writing, if more than 1 overwriting needs
				   to be done. Allow I/O bufferring (efficiency), if just one
				   pass is needed. */
				if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
				{
					error = wfs_reiser_flush_fs (wfs_fs);
				}
				if ( sig_recvd != 0 )
				{
					ret_part = WFS_SIGNAL;
	       				break;
				}
			}
			if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
			{
				/* last pass with zeros: */
				WFS_MEMSET ( (unsigned char *) offset, 0,
					(size_t) length );
				if ( sig_recvd == 0 )
				{
					mark_buffer_dirty2 (bh);
					mark_buffer_uptodate2 (bh);

					error = bwrite (bh);
					if ( error != 0 )
					{
						/* check if block is marked as bad. If there is no
						'badblocks' list or the block is marked OK,
						then print the error. */
						if (rfs->fs_badblocks_bm == NULL)
						{
							ret_part = WFS_BLKWR;
							break;
						}
						else if (reiserfs_bitmap_test_bit (
							rfs->fs_badblocks_bm,
							(unsigned int)(bh->b_blocknr & 0x0FFFFFFFF)) == 0)
						{
							ret_part = WFS_BLKWR;
							break;
						}
					}
					/* No need to flush the last writing of a given block. *
					if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
					{
						error = wfs_reiser_flush_fs (wfs_fs);
					} */
					if ( sig_recvd != 0 )
					{
						ret_part = WFS_SIGNAL;
						break;
					}
				}
			}
		}	/* for i = get_item_pos (&elem_path) */
		PATH_LAST_POSITION (&elem_path) = i - 1;
		if ( i < (int)B_NR_ITEMS (bh) )
		{
			if (bh->b_count != 0)
			{
				brelse (bh);
			}
			continue;
		}

		next_key = reiserfs_next_key (&elem_path);
		if (next_key != NULL)
		{
			elem_key = *next_key;
		}
		else
		{
			WFS_MEMSET (&elem_key, 0xff, KEY_SIZE);
		}
		pathrelse (&elem_path);
		if (bh->b_count != 0)
		{
			brelse (bh);
		}

	}	/* while reiserfs_search_by_key_4 */
	wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);

	pathrelse (&elem_path);
	free (buf);

	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return ret_part;
}
#endif /* WFS_WANT_PART */

/* ======================================================================== */

#ifdef WFS_WANT_WFS
/**
 * Wipes the free space on the given ReiserFS filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_reiser_wipe_fs (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	unsigned long int blk_no;
	struct buffer_head * bh;
	int selected[WFS_NPAT] = {0};
	unsigned char *buf;
	unsigned long int j;
	unsigned int prev_percent = 0;
	unsigned long int curr_sector = 0;
	wfs_errcode_t error = 0;
	reiserfs_filsys_t * rfs;
	wfs_errcode_t * error_ret;
	size_t fs_block_size;

	rfs = (reiserfs_filsys_t *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( rfs == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}

	if ( rfs->fs_ondisk_sb == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_SUCCESS;
	}

	if ( rfs->fs_ondisk_sb->s_v1.sb_free_blocks == 0 )
	{
		/* nothing to do */
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_SUCCESS;
	}

	fs_block_size = wfs_reiser_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}
	WFS_SET_ERRNO (0);
	buf = (unsigned char *) malloc ( fs_block_size );
	if ( buf == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (ENOMEM);
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	if ( wfs_fs.wipe_mode == WFS_WIPE_MODE_PATTERN )
	{
		for ( j = 0; (j < wfs_fs.npasses) && (sig_recvd == 0)
			/*&& (ret_wfs == WFS_SUCCESS)*/; j++ )
		{
			curr_sector = 0;
			/*blk_no < wfs_fs.rfs.fs_ondisk_sb->s_v1.sb_block_count*/
			for ( blk_no = 0; (blk_no < get_sb_block_count (rfs->fs_ondisk_sb))
				&& (sig_recvd == 0) /*&& (ret_wfs == WFS_SUCCESS)*/; blk_no++ )
			{
				if (       (not_data_block   ( rfs, blk_no ) != 0)
					|| (block_of_bitmap  ( rfs, blk_no ) != 0)
					|| (block_of_journal ( rfs, blk_no ) != 0)
					|| (reiserfs_bitmap_test_bit (rfs->fs_bitmap2, (unsigned int)(blk_no & 0x0FFFFFFFF)) != 0)
				)
				{
					curr_sector++;
					wfs_show_progress (WFS_PROGRESS_WFS, (unsigned int)(((get_sb_block_count (rfs->fs_ondisk_sb) * j + curr_sector) * 100)
						/ (get_sb_block_count (rfs->fs_ondisk_sb) * wfs_fs.npasses)), &prev_percent);
					continue;
				}
				/* read the block just to fill the structure */
				bh = bread (rfs->fs_dev, blk_no, fs_block_size);
				if ( bh == NULL )
				{
					curr_sector++;
					wfs_show_progress (WFS_PROGRESS_WFS, (unsigned int)(((get_sb_block_count (rfs->fs_ondisk_sb) * j + curr_sector) * 100)
						/ (get_sb_block_count (rfs->fs_ondisk_sb) * wfs_fs.npasses)), &prev_percent);
					continue;
				}

				/* write the block here. */
				if ( wfs_fs.no_wipe_zero_blocks != 0 )
				{
					if ( wfs_is_block_zero ((unsigned char *)bh->b_data, fs_block_size) != 0 )
					{
						/* this block is all-zeros - don't wipe, as requested */
						break;
					}
				}

				wfs_fill_buffer ( j, (unsigned char *) bh->b_data,
					fs_block_size, selected, wfs_fs );
				if ( sig_recvd != 0 )
				{
					ret_wfs = WFS_SIGNAL;
					break;
				}
				mark_buffer_dirty2 (bh);
				mark_buffer_uptodate2 (bh);
				error = bwrite (bh);
				if ( error != 0 )
				{
					/* check if block is marked as bad. If there is no 'badblocks' list
					or the block is marked OK, then print the error. */
					if (rfs->fs_badblocks_bm == NULL)
					{
						ret_wfs = WFS_BLKWR;
						break;
					}
					else if (reiserfs_bitmap_test_bit (
						rfs->fs_badblocks_bm,
						(unsigned int)(blk_no & 0x0FFFFFFFF)) == 0)
					{
						ret_wfs = WFS_BLKWR;
						break;
					}
				}
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
				{
					error = wfs_reiser_flush_fs (wfs_fs);
				}
				curr_sector++;
				wfs_show_progress (WFS_PROGRESS_WFS, (unsigned int)(((get_sb_block_count (rfs->fs_ondisk_sb) * j + curr_sector) * 100)
					/ (get_sb_block_count (rfs->fs_ondisk_sb) * wfs_fs.npasses)), &prev_percent);
				if (bh->b_count != 0)
				{
					brelse (bh);
				}
			}	/* for block */
		}
		if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
		{
			if ( j != wfs_fs.npasses * 2 )
			{
				/* last pass with zeros: */
				if ( sig_recvd == 0 )
				{
					wfs_reiser_flush_fs (wfs_fs);
					/*blk_no < wfs_fs.rfs.fs_ondisk_sb->s_v1.sb_block_count*/
					for ( blk_no = 0; (blk_no < get_sb_block_count (rfs->fs_ondisk_sb))
						&& (sig_recvd == 0) /*&& (ret_wfs == WFS_SUCCESS)*/; blk_no++ )
					{
						if (       (not_data_block   ( rfs, blk_no ) != 0)
							|| (block_of_bitmap  ( rfs, blk_no ) != 0)
							|| (block_of_journal ( rfs, blk_no ) != 0)
							|| (reiserfs_bitmap_test_bit (rfs->fs_bitmap2, (unsigned int)(blk_no & 0x0FFFFFFFF)) != 0)
						)
						{
							continue;
						}
						/* read the block just to fill the structure */
						bh = bread (rfs->fs_dev, blk_no, fs_block_size);
						if ( bh == NULL )
						{
							continue;
						}
						WFS_MEMSET ( (unsigned char *) bh->b_data, 0,
							fs_block_size );

						mark_buffer_dirty2 (bh);
						mark_buffer_uptodate2 (bh);
						error = bwrite (bh);
						if ( error != 0 )
						{
							/* check if block is marked as bad. If there is no 'badblocks'
							list or the block is marked OK, then print the error. */
							if (rfs->fs_badblocks_bm == NULL)
							{
								ret_wfs = WFS_BLKWR;
								break;
							}
							else if (reiserfs_bitmap_test_bit (
								rfs->fs_badblocks_bm,
								(unsigned int)(blk_no & 0x0FFFFFFFF)) == 0)
							{
								ret_wfs = WFS_BLKWR;
								break;
							}
						}
						/* No need to flush the last writing of a given block. *
						if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
						{
							error = wfs_reiser_flush_fs (wfs_fs);
						}*/
						if (bh->b_count != 0)
						{
							brelse (bh);
						}
					}
					wfs_reiser_flush_fs (wfs_fs);
				}
			}
		}
	}
	else
	{
		/*blk_no < wfs_fs.rfs.fs_ondisk_sb->s_v1.sb_block_count*/
		for ( blk_no = 0; (blk_no < get_sb_block_count (rfs->fs_ondisk_sb))
			&& (sig_recvd == 0) /*&& (ret_wfs == WFS_SUCCESS)*/; blk_no++ )
		{
			if (       (not_data_block   ( rfs, blk_no ) != 0)
				|| (block_of_bitmap  ( rfs, blk_no ) != 0)
				|| (block_of_journal ( rfs, blk_no ) != 0)
				|| (reiserfs_bitmap_test_bit (rfs->fs_bitmap2, (unsigned int)(blk_no & 0x0FFFFFFFF)) != 0)
			)
			{
				curr_sector++;
				wfs_show_progress (WFS_PROGRESS_WFS, (unsigned int)((curr_sector * 100)
					/ get_sb_block_count (rfs->fs_ondisk_sb)), &prev_percent);
				continue;
			}
			/* read the block just to fill the structure */
			bh = bread (rfs->fs_dev, blk_no, fs_block_size);
			if ( bh == NULL )
			{
				curr_sector++;
				wfs_show_progress (WFS_PROGRESS_WFS, (unsigned int)((curr_sector * 100)
					/ get_sb_block_count (rfs->fs_ondisk_sb)), &prev_percent);
				continue;
			}

			/* write the block here. */
			for ( j = 0; (j < wfs_fs.npasses) && (sig_recvd == 0)
				/*&& (ret_wfs == WFS_SUCCESS)*/; j++ )
			{
				if ( wfs_fs.no_wipe_zero_blocks != 0 )
				{
					if ( wfs_is_block_zero ((unsigned char *)bh->b_data, fs_block_size) != 0 )
					{
						/* this block is all-zeros - don't wipe, as requested */
						j = wfs_fs.npasses * 2;
						break;
					}
				}

				wfs_fill_buffer ( j, (unsigned char *) bh->b_data,
					fs_block_size, selected, wfs_fs );
				if ( sig_recvd != 0 )
				{
					ret_wfs = WFS_SIGNAL;
					break;
				}
				mark_buffer_dirty2 (bh);
				mark_buffer_uptodate2 (bh);
				error = bwrite (bh);
				if ( error != 0 )
				{
					/* check if block is marked as bad. If there is no 'badblocks' list
					or the block is marked OK, then print the error. */
					if (rfs->fs_badblocks_bm == NULL)
					{
						ret_wfs = WFS_BLKWR;
						break;
					}
					else if (reiserfs_bitmap_test_bit (
						rfs->fs_badblocks_bm,
						(unsigned int)(blk_no & 0x0FFFFFFFF)) == 0)
					{
						ret_wfs = WFS_BLKWR;
						break;
					}
				}
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
				{
					error = wfs_reiser_flush_fs (wfs_fs);
				}
			}
			if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
			{
				if ( j != wfs_fs.npasses * 2 )
				{
					/* last pass with zeros: */
					WFS_MEMSET ( (unsigned char *) bh->b_data, 0,
						fs_block_size );
					if ( sig_recvd == 0 )
					{
						mark_buffer_dirty2 (bh);
						mark_buffer_uptodate2 (bh);
						error = bwrite (bh);
						if ( error != 0 )
						{
							/* check if block is marked as bad. If there is no 'badblocks'
							list or the block is marked OK, then print the error. */
							if (rfs->fs_badblocks_bm == NULL)
							{
								ret_wfs = WFS_BLKWR;
								break;
							}
							else if (reiserfs_bitmap_test_bit (
								rfs->fs_badblocks_bm,
								(unsigned int)(blk_no & 0x0FFFFFFFF)) == 0)
							{
								ret_wfs = WFS_BLKWR;
								break;
							}
						}
						/* No need to flush the last writing of a given block. *
						if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
						{
							error = wfs_reiser_flush_fs (wfs_fs);
						}*/
					}
				}
			}
			if (bh->b_count != 0)
			{
				brelse (bh);
			}
			curr_sector++;
			wfs_show_progress (WFS_PROGRESS_WFS, (unsigned int)((curr_sector * 100)
				/ get_sb_block_count (rfs->fs_ondisk_sb)), &prev_percent);
		}	/* for block */
	}
	wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
	free (buf);
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return ret_wfs;
}
#endif /* WFS_WANT_WFS */

/* ======================================================================== */

#ifdef WFS_WANT_UNRM
/**
 * Starts recursive directory search for deleted inodes
 *	and undelete data on the given ReiserFS filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_reiser_wipe_unrm (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	struct key elem_key, *next_key;
	struct buffer_head * bh;
	struct path elem_path;
	struct item_head *head;
	int i;
	unsigned int count;
	unsigned char * buf;
	unsigned long int j;
	int selected[WFS_NPAT] = {0};
	struct reiserfs_de_head * deh;
	unsigned long int blk_no;
	unsigned int prev_percent = 0;
	unsigned long int curr_direlem = 0;
# if (defined HAVE_CLOSE)
	int journ_fd;
# endif
	wfs_errcode_t error = 0;
	reiserfs_filsys_t * rfs;
	wfs_errcode_t * error_ret;
	size_t fs_block_size;

	rfs = (reiserfs_filsys_t *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( rfs == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	fs_block_size = wfs_reiser_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	WFS_SET_ERRNO (0);
	buf = (unsigned char *) malloc ( fs_block_size );
	if ( buf == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (ENOMEM);
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	/* wipe journal */

	if ( reiserfs_open_journal (rfs, NULL, 0) == 0 )
	{
# if (defined HAVE_CLOSE)
		journ_fd = rfs->fs_journal_dev;
# endif
		reiserfs_flush_journal (rfs);
		reiserfs_close_journal (rfs);
# if (defined HAVE_CLOSE)
		/* clean up what reiserfs_close_journal() does not do */
		if ( journ_fd >= 0 )
		{
			close (journ_fd);
		}
# endif
		for ( blk_no = get_jp_journal_1st_block (sb_jp (rfs->fs_ondisk_sb));
			(blk_no < get_jp_journal_1st_block (sb_jp (rfs->fs_ondisk_sb))
				+ get_jp_journal_size (&(rfs->fs_ondisk_sb->s_v1.sb_journal)))
			&& (sig_recvd == 0);
			blk_no++ )
		{
			/*
			if ( block_of_journal ( &(rfs), blk_no ) == 0
				|| blk_no <= get_jp_journal_1st_block (sb_jp (rfs.fs_ondisk_sb))
				)
			{
				curr_direlem++;
				wfs_show_progress (WFS_PROGRESS_UNRM, (unsigned int) ((curr_direlem*50)
					/ get_jp_journal_size (&(rfs->fs_ondisk_sb->s_v1.sb_journal))),
					&prev_percent);
				continue;
			}
			*/
			/* read the block just to fill the structure */
			bh = bread (rfs->fs_dev, blk_no, fs_block_size);
			if ( bh == NULL )
			{
				curr_direlem++;
				wfs_show_progress (WFS_PROGRESS_UNRM, (unsigned int) ((curr_direlem*50)
					/ get_jp_journal_size (&(rfs->fs_ondisk_sb->s_v1.sb_journal))),
					&prev_percent);
				continue;
			}

			/* write the block here. */
			for (j = 0; (j < wfs_fs.npasses+1) && (sig_recvd == 0)
				/*&& (ret_wfs == WFS_SUCCESS)*/; j++)
			{
				/* Last pass has to be with zeros */
				if ( j == wfs_fs.npasses )
				{
					WFS_MEMSET ( bh->b_data, 0, fs_block_size );
				}
				else
				{
					if ( wfs_fs.no_wipe_zero_blocks != 0 )
					{
						if ( wfs_is_block_zero ((unsigned char *)bh->b_data,
							fs_block_size) != 0 )
						{
							/* this block is all-zeros - don't wipe, as requested */
							j = wfs_fs.npasses * 2;
							break;
						}
					}

					wfs_fill_buffer ( j, (unsigned char *) bh->b_data,
						fs_block_size, selected, wfs_fs );
				}
				if ( sig_recvd != 0 )
				{
					ret_wfs = WFS_SIGNAL;
					break;
				}
				mark_buffer_dirty2 (bh);
				mark_buffer_uptodate2 (bh);
				error = bwrite (bh);
				if ( error != 0 )
				{
					/* check if block is marked as bad. If there is no 'badblocks'
					   list or the block is marked OK, then print the error. */
					if (rfs->fs_badblocks_bm == NULL)
					{
						ret_wfs = WFS_BLKWR;
						break;
					}
					else if (reiserfs_bitmap_test_bit
						(rfs->fs_badblocks_bm, (unsigned int)(blk_no & 0x0FFFFFFFF)) == 0)
					{
						ret_wfs = WFS_BLKWR;
						break;
					}
				}
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				   Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
				{
					error = wfs_reiser_flush_fs (wfs_fs);
				}
			}
			if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
			{
				if ( j != wfs_fs.npasses * 2 )
				{
					/* last pass with zeros: */
					WFS_MEMSET ((unsigned char *) bh->b_data, 0, fs_block_size);
					if ( sig_recvd == 0 )
					{
						mark_buffer_dirty2 (bh);
						mark_buffer_uptodate2 (bh);
						error = bwrite (bh);
						if ( error != 0 )
						{
							/* check if block is marked as bad. If there is no
							'badblocks' list or the block is marked OK, then print
							the error. */
							if (rfs->fs_badblocks_bm == NULL)
							{
								ret_wfs = WFS_BLKWR;
								break;
							}
							else if (reiserfs_bitmap_test_bit
								(rfs->fs_badblocks_bm, (unsigned int)(blk_no & 0x0FFFFFFFF)) == 0)
							{
								ret_wfs = WFS_BLKWR;
								break;
							}
						}
						/* No need to flush the last writing of a given block. *
						if ( (wfs_fs.npasses > 1)
							&& (sig_recvd == 0) )
						{
							error = wfs_reiser_flush_fs (wfs_fs);
						}*/
					}
				}
			}
			if (bh->b_count != 0)
			{
				brelse (bh);
			}
			curr_direlem++;
			wfs_show_progress (WFS_PROGRESS_UNRM, (unsigned int) ((curr_direlem*50)
				/ get_jp_journal_size (&(rfs->fs_ondisk_sb->s_v1.sb_journal))),
				&prev_percent);
		}
		if ( sig_recvd != 0 )
		{
			ret_wfs = WFS_SIGNAL;
		}
	}	/* if reiserfs_open_journal */
	wfs_show_progress (WFS_PROGRESS_UNRM, 50, &prev_percent);

	elem_key = root_dir_key;
	elem_path.path_length = ILLEGAL_PATH_ELEMENT_OFFSET;

	while ( /*(ret_wfs == WFS_SUCCESS)
		&&*/ (reiserfs_search_by_key_4 ( rfs, &elem_key, &elem_path ) == ITEM_FOUND)
		&& (sig_recvd == 0)
	)
	{
        	bh = PATH_PLAST_BUFFER (&elem_path);
        	if ( bh == NULL )
        	{
			pathrelse (&elem_path);
        		break;
        	}

		if (       (not_data_block   ( rfs, bh->b_blocknr ) != 0)
			|| (block_of_bitmap  ( rfs, bh->b_blocknr ) != 0)
			|| (block_of_journal ( rfs, bh->b_blocknr ) != 0)
			)
		{
			/*pathrelse (&elem_path);*/
			while (bh->b_count != 0)
			{
				brelse (bh);
			}
			continue;
		}
		if ( sig_recvd != 0 )
		{
			pathrelse (&elem_path);
			while (bh->b_count != 0)
			{
				brelse (bh);
			}
			ret_wfs = WFS_SIGNAL;
	       		break;
		}

		head = get_ih (&elem_path);
		if ( head != NULL )
		{
			if ( get_key_dirid (&(head->ih_key)) == get_key_objectid (&root_dir_key) )
			{
				curr_direlem++;
				wfs_show_progress (WFS_PROGRESS_UNRM,
					(unsigned int)(50 + (curr_direlem * 50)
					/get_ih_entry_count (head)),
					&prev_percent);
			}
		}
		for (i = get_item_pos (&elem_path);
			(i < (int)B_NR_ITEMS (bh)) && (sig_recvd == 0) /*&& (ret_wfs == WFS_SUCCESS)*/;
			i++, head++)
		{
			if (ih_reachable (head) == 0)
			{
				PATH_LAST_POSITION (&elem_path) = i;
				deh = B_I_DEH ( get_bh (&elem_path), head )
					+ elem_path.pos_in_item;

				/* reiserfsck deletes the file here */
				next_key = reiserfs_next_key (&elem_path);
				if (next_key != NULL)
				{
					elem_key = *next_key;
				}
				else
				{
					WFS_MEMSET (&elem_key, 0xff, KEY_SIZE);
				}

				if ( (deh != NULL)
					&& (get_ih_entry_count (head) != 0xFFFF) )
				{
					bh->b_state = 0;
					for ( j = 0; (j < wfs_fs.npasses)
						&& (sig_recvd == 0)
						/*&& (ret_wfs == WFS_SUCCESS)*/; j++ )
					{
						for (count = elem_path.pos_in_item;
						     count < get_ih_entry_count (head);
							count++, deh++)
						{
							if ( name_in_entry_length (
								head, deh,
								(int)count) > 0 )
							{
								wfs_fill_buffer ( j,
									(unsigned char *)
									 name_in_entry (deh, (int)count),
									(size_t) name_in_entry_length
										(head, deh, (int)count),
									selected, wfs_fs );
							}
						}
						if ( sig_recvd != 0 )
						{
							ret_wfs = WFS_SIGNAL;
		       					break;
						}
						mark_buffer_dirty2 (bh);
						mark_buffer_uptodate2 (bh);
	 					error = bwrite (bh);
						if ( error != 0 )
						{
							/* check if block is marked as bad. If
							   there is no 'badblocks' list or the
							   block is marked OK,
							   then print the error. */
							if (rfs->fs_badblocks_bm == NULL)
							{
								ret_wfs = WFS_BLKWR;
								break;
							}
							else if (reiserfs_bitmap_test_bit
								(rfs->fs_badblocks_bm,
								(unsigned int)(bh->b_blocknr & 0x0FFFFFFFF)) == 0)
							{
								ret_wfs = WFS_BLKWR;
								break;
							}
						}
						/* Flush after each writing, if more than 1
						   overwriting needs to be done. Allow I/O
						   bufferring (efficiency), if just one
						   pass is needed. */
						if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
						{
							error =
								wfs_reiser_flush_fs (wfs_fs);
						}
						if ( sig_recvd != 0 )
						{
							ret_wfs = WFS_SIGNAL;
			       				break;
						}
					}
					if ( (wfs_fs.zero_pass != 0)
						&& (sig_recvd == 0) )
					{
						/* last pass with zeros: */
						for (count = elem_path.pos_in_item;
						     count < get_ih_entry_count (head);
							count++, deh++)
						{
							if ( name_in_entry_length (
								head, deh,
								(int)count) > 0 )
							{
								WFS_MEMSET ((unsigned char *)
									name_in_entry (deh, (int)count),
									0, (size_t) name_in_entry_length
									(head, deh, (int)count));
							}
						}
						if ( sig_recvd == 0 )
						{
							mark_buffer_dirty2 (bh);
							mark_buffer_uptodate2 (bh);
							error = bwrite (bh);
							if ( error != 0 )
							{
								/* check if block is marked as bad. If
								there is no 'badblocks' list or the
								block is marked OK,
								then print the error. */
								if (rfs->fs_badblocks_bm == NULL)
								{
									ret_wfs = WFS_BLKWR;
									break;
								}
								else if (reiserfs_bitmap_test_bit
									(rfs->fs_badblocks_bm,
									(unsigned int)(bh->b_blocknr & 0x0FFFFFFFF)) == 0)
								{
									ret_wfs = WFS_BLKWR;
									break;
								}
							}
							/* No need to flush the last writing of a given block. *
							if ( (wfs_fs.npasses > 1)
								&& (sig_recvd == 0) )
							{
								error =
									wfs_reiser_flush_fs (wfs_fs);
							} */
							if ( sig_recvd != 0 )
							{
								ret_wfs = WFS_SIGNAL;
								break;
							}
						}
					}
				}
			}	/* if (ih_reachable (head) == 0) */
		}	/* for i = get_item_pos (&elem_path) */
		if ( i < (int)B_NR_ITEMS (bh) )
		{
			while (bh->b_count != 0)
			{
				brelse (bh);
			}
			pathrelse (&elem_path);
			continue;
		}

		PATH_LAST_POSITION (&elem_path) = i - 1;
		next_key = reiserfs_next_key (&elem_path);
		if (next_key != NULL)
		{
			elem_key = *next_key;
		}
		else
		{
			WFS_MEMSET (&elem_key, 0xff, KEY_SIZE);
		}
		pathrelse (&elem_path);

		while (bh != NULL && bh->b_count != 0)
		{
			brelse (bh);	/* <<< */
		}
	}	/* while */
	wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);

	pathrelse (&elem_path);
	free (buf);
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return ret_wfs;
}
#endif /* WFS_WANT_UNRM */


/* ======================================================================== */

/**
 * Opens a ReiserFS filesystem on the given device.
 * \param dev_name Device name, like /dev/hdXY
 * \param wfs_fs Pointer to where the result will be put.
 * \param whichfs Pointer to an int saying which fs is curently in use.
 * \param data Pointer to wfs_fsdata_t structure containing information
 *	which may be needed to open the filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_reiser_open_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t * const wfs_fs,
	const wfs_fsdata_t * const data)
#else
	wfs_fs, data)
	wfs_fsid_t * const wfs_fs;
	const wfs_fsdata_t * const data;
#endif
{
	reiserfs_filsys_t * res;
	char * dev_name_copy;
	wfs_errcode_t error = 0;
	wfs_errcode_t * error_ret = NULL;
	int open_err;

	if ((wfs_fs == NULL) || (data == NULL))
	{
		return WFS_BADPARAM;
	}
	error_ret = (wfs_errcode_t *) wfs_fs->fs_error;
	if ( wfs_fs->fsname == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = WFS_BADPARAM;
		}
		return WFS_BADPARAM;
	}

	wfs_fs->whichfs = WFS_CURR_FS_NONE;
	wfs_fs->fs_backend = NULL;

	WFS_SET_ERRNO (0);
	dev_name_copy = WFS_STRDUP (wfs_fs->fsname);
	if ( dev_name_copy == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (ENOMEM);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	res = reiserfs_open (dev_name_copy, O_RDWR | O_EXCL
#ifdef O_BINARY
		| O_BINARY
#endif
		, &open_err, NULL, 1);
	error = (wfs_errcode_t)open_err;
	if ( (res == NULL) || (error != 0) )
	{
		free (dev_name_copy);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_OPENFS;
	}

	if ( no_reiserfs_found (res) != 0 )
	{
		error = WFS_OPENFS;
		/*reiserfs_close (res);*/
		free (dev_name_copy);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_OPENFS;
	}

	if ( reiserfs_open_ondisk_bitmap (res) != 0 )
	{
		error = WFS_BLBITMAPREAD;
		reiserfs_close (res);
		free (dev_name_copy);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BLBITMAPREAD;
	}

	if ( res->fs_bitmap2 == NULL )
	{
		error = WFS_BLBITMAPREAD;
		reiserfs_close (res);
		free (dev_name_copy);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BLBITMAPREAD;
	}

	wfs_fs->fs_backend = res;

	wfs_fs->whichfs = WFS_CURR_FS_REISERFS;
	free (dev_name_copy);

	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return WFS_SUCCESS;
}

/* ======================================================================== */

/**
 * Checks if the given ReiserFS filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_reiser_chk_mount (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
#endif
{
	return wfs_check_mounted (wfs_fs);
}

/* ======================================================================== */

/**
 * Closes the ReiserFS filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_reiser_close_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs;
#endif
{
#if (defined HAVE_CLOSE)
	int fd;
#endif
	reiserfs_filsys_t * rfs;

	rfs = (reiserfs_filsys_t *) wfs_fs.fs_backend;
	if ( rfs == NULL )
	{
		return WFS_BADPARAM;
	}
#if (defined HAVE_CLOSE)
	fd = rfs->fs_dev;
#endif
	reiserfs_close_ondisk_bitmap (rfs);
	reiserfs_close (rfs);
	/*reiserfs_free (rfs);*/
#if (defined HAVE_CLOSE)
	/* clean up what reiserfs_close() does not do */
	if ( fd >= 0 )
	{
		close (fd);
	}
#endif
	wfs_fs.fs_backend = NULL;
	return WFS_SUCCESS;
}

/* ======================================================================== */

/**
 * Checks if the ReiserFS filesystem has errors.
 * \param wfs_fs The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_reiser_check_err (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs )
#else
	wfs_fs )
	wfs_fsid_t wfs_fs;
#endif
{
	int state;
	int res;
	reiserfs_filsys_t * rfs;

	rfs = (reiserfs_filsys_t *) wfs_fs.fs_backend;
	if ( rfs == NULL )
	{
		return 1;
	}
	res = reiserfs_is_fs_consistent (rfs);
	if ( res == 0 )
	{
		res = 1;
	}
	else
	{
		res = 0;
	}

	state = get_sb_fs_state (rfs->fs_ondisk_sb);
	if ((state & FS_FATAL) == FS_FATAL)
	{
    		res++;
	}

	if ((state & FS_ERROR) == FS_ERROR)
	{
		res++;
	}

	if (state != FS_CONSISTENT)
	{
		res++;
	}

	return res;
}

/* ======================================================================== */

/**
 * Checks if the ReiserFS filesystem is dirty (has unsaved changes).
 * \param wfs_fs The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_reiser_is_dirty (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs )
#else
	wfs_fs )
	wfs_fsid_t wfs_fs;
#endif
{
	reiserfs_filsys_t * rfs;

	rfs = (reiserfs_filsys_t *) wfs_fs.fs_backend;
	if ( rfs == NULL )
	{
		return 1;
	}
	/* Declared, but not implemented and not used by anything in ReiserFSprogs...
	return filesystem_dirty (&(wfs_fs.rfs));
	*/
	return reiserfs_is_fs_consistent (rfs);
}

/* ======================================================================== */

/**
 * Flushes the ReiserFS filesystem.
 * \param wfs_fs The ReiserFS filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_reiser_flush_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs )
#else
	wfs_fs )
	wfs_fsid_t wfs_fs;
#endif
{
	reiserfs_filsys_t * rfs;

	rfs = (reiserfs_filsys_t *) wfs_fs.fs_backend;
	if ( rfs == NULL )
	{
		return WFS_BADPARAM;
	}
	reiserfs_flush (rfs);

#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_SYNC)
	sync ();
#endif
	return WFS_SUCCESS;
}

/* ======================================================================== */

/**
 * Print the version of the current library, if applicable.
 */
void wfs_reiser_print_version (WFS_VOID)
{
	printf ( "ReiserFSv3: <?>\n");
}

/* ======================================================================== */

/**
 * Get the preferred size of the error variable.
 * \return the preferred size of the error variable.
 */
size_t wfs_reiser_get_err_size (WFS_VOID)
{
	return sizeof (wfs_errcode_t);
}

/* ======================================================================== */

/**
 * Initialize the library.
 */
void wfs_reiser_init (WFS_VOID)
{
}

/* ======================================================================== */

/**
 * De-initialize the library.
 */
void wfs_reiser_deinit (WFS_VOID)
{
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
wfs_reiser_show_error (
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
	wfs_show_fs_error_gen (msg, extra, wfs_fs);
}
