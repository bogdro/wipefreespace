/*
 * A program for secure cleaning of free space on filesystems.
 *	-- ReiserFS file system-specific functions.
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#if (!defined MAJOR_IN_SYSMACROS) && (!defined MAJOR_IN_MKDEV)
# ifdef HAVE_SYS_SYSMACROS_H
#  define MAJOR_IN_SYSMACROS 1
#  define MAJOR_IN_MKDEV 0
#  include <sys/sysmacros.h>
# else
#  ifdef HAVE_SYS_MKDEV_H
#   define MAJOR_IN_SYSMACROS 0
#   define MAJOR_IN_MKDEV 1
#   include <sys/mkdev.h>
#  endif
# endif
#endif

#ifdef HAVE_ASM_TYPES_H
# include <asm/types.h>
#else
typedef unsigned int __u32;
typedef short int __u16;
#endif

#if (defined HAVE_REISERFS_LIB_H) && (defined HAVE_LIBCORE)
# include <reiserfs_lib.h>
# include <io.h>
#else
# error Something wrong. ReiserFS requested, but headers or library missing.
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

#ifdef HAVE_MNTENT_H
# include <mntent.h>
#endif

#ifdef HAVE_PATHS_H
# include <paths.h>
#endif

#ifndef _PATH_MOUNTED
# ifdef MNT_MNTTAB
#  define	_PATH_MOUNTED	MNT_MNTTAB
# else
#  define	_PATH_MOUNTED	"/etc/mtab"
# endif
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#define MNTBUFLEN 4096

#ifndef O_EXCL
# define O_EXCL		0200
#endif
#ifndef O_RDWR
# define O_RDWR		02
#endif

#include "wipefreespace.h"
#include "wfs_reiser.h"
#include "wfs_signal.h"

/* Fix the sizes. */
static const unsigned long long bh_dirty = BH_Dirty;
static const unsigned long long bh_up2date = BH_Uptodate;
#define mark_buffer_dirty2(bh)    misc_set_bit (bh_dirty,   &(bh)->b_state)
#define mark_buffer_uptodate2(bh) misc_set_bit (bh_up2date, &(bh)->b_state)

/**
 * Returns the buffer size needed to work on the
 *	smallest physical unit on a ReiserFS filesystem.
 * \param FS The filesystem.
 * \return Block size on the filesystem.
 */
static size_t WFS_ATTR ((warn_unused_result))
wfs_reiser_get_block_size ( const wfs_fsid_t FS )
{
	return FS.rfs->fs_blocksize;
}


/**
 * Wipes the free space in partially used blocks on the given ReiserFS filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_reiser_wipe_part ( wfs_fsid_t FS, error_type * const error )
{
	errcode_enum ret_part = WFS_SUCCESS;
	struct key elem_key, *next_key;
	struct buffer_head * bh;
	struct path elem_path;
	struct item_head *head;
	int i;
	unsigned char * buf;
	unsigned long j;
	int selected[NPAT];
	char * offset;
	int length;

	if ( error == NULL )
	{
		return WFS_BADPARAM;
	}

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	buf = (unsigned char *) malloc ( wfs_reiser_get_block_size (FS) );
	if ( buf == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		return WFS_MALLOC;
	}

	elem_key = root_dir_key;
	elem_path.path_length = ILLEGAL_PATH_ELEMENT_OFFSET;

	while ( (ret_part == WFS_SUCCESS)
		&& (reiserfs_search_by_key_4 ( FS.rfs, &elem_key, &elem_path ) == ITEM_FOUND)
		&& (sig_recvd == 0)
		)
	{
        	bh = PATH_PLAST_BUFFER (&elem_path);
        	if ( bh == NULL )
        	{
			pathrelse (&elem_path);
        		break;
        	}
		if (       (not_data_block   ( FS.rfs, bh->b_blocknr ) != 0)
			|| (block_of_bitmap  ( FS.rfs, bh->b_blocknr ) != 0)
			|| (block_of_journal ( FS.rfs, bh->b_blocknr ) != 0)
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
#ifdef HAVE_MEMSET
				memset (&elem_key, 0xff, KEY_SIZE);
#else
				for ( i=0; i < KEY_SIZE; i++ )
				{
					((char*)&elem_key)[i] = '\xff';
				}
#endif
			}

			pathrelse (&elem_path);
			if (bh->b_count != 0) brelse (bh);
			continue;
		}

		if ( sig_recvd != 0 )
		{
			pathrelse (&elem_path);
			if (bh->b_count != 0) brelse (bh);
			ret_part = WFS_SIGNAL;
	       		break;
		}

		for (i = get_item_pos (&elem_path), head = get_ih (&elem_path);
			(i < B_NR_ITEMS (bh)) && (sig_recvd == 0) && (ret_part == WFS_SUCCESS);
			i++, head++)
		{
			next_key = reiserfs_next_key (&elem_path);
			if (next_key != NULL)
			{
				elem_key = *next_key;
			}
			else
			{
#ifdef HAVE_MEMSET
				memset (&elem_key, 0xff, KEY_SIZE);
#else
				for ( j=0; j < KEY_SIZE; j++ )
				{
					((char*)&elem_key)[j] = '\xff';
				}
#endif
			}

			if ( head == NULL )
			{
				continue;
			}
			if ( (bh->b_data == NULL)
				|| (head->ih2_item_len >= wfs_reiser_get_block_size (FS))
				|| (head->ih2_item_location >= wfs_reiser_get_block_size (FS))
				|| (head->ih2_item_location+head->ih2_item_len >= wfs_reiser_get_block_size (FS))
				|| (head->ih2_item_location+head->ih2_item_len >= bh->b_size)
				)
			{
				continue;
			}
			offset = &(bh->b_data[head->ih2_item_location + head->ih2_item_len]);
			length = bh->b_size - (head->ih2_item_location + head->ih2_item_len);

			for ( j = 0; (j < npasses) && (sig_recvd == 0) && (ret_part == WFS_SUCCESS); j++ )
			{
				fill_buffer ( j, (unsigned char *) offset, (size_t) length, selected );

				if ( sig_recvd != 0 )
				{
					ret_part = WFS_SIGNAL;
       					break;
				}
				mark_buffer_dirty2 (bh);
				mark_buffer_uptodate2 (bh);

 				error->errcode.gerror = bwrite (bh);
				if ( error->errcode.gerror != 0 )
				{
					/* check if block is marked as bad. If there is no
					   'badblocks' list or the block is marked OK,
					   then print the error. */
					if (FS.rfs->fs_badblocks_bm == NULL)
					{
						show_error ( *error, err_msg_wrtblk, fsname );
						ret_part = WFS_BLKWR;
					}
					else if (reiserfs_bitmap_test_bit (FS.rfs->fs_badblocks_bm,
						bh->b_blocknr) == 0)
					{
						show_error ( *error, err_msg_wrtblk, fsname );
						ret_part = WFS_BLKWR;
					}
				}
				/* Flush after each writing, if more than 1 overwriting needs
				   to be done. Allow I/O bufferring (efficiency), if just one
				   pass is needed. */
				if ((npasses > 1) && (sig_recvd == 0) && (ret_part == WFS_SUCCESS))
				{
					error->errcode.gerror = wfs_reiser_flush_fs ( FS );
				}
				if ( sig_recvd != 0 )
				{
					ret_part = WFS_SIGNAL;
	       				break;
				}
			}
		}	/* for i = get_item_pos (&elem_path) */
		PATH_LAST_POSITION (&elem_path) = i - 1;
		if ( i < B_NR_ITEMS (bh) )
		{
			if (bh->b_count != 0) brelse (bh);
			continue;
		}

		next_key = reiserfs_next_key (&elem_path);
		if (next_key != NULL)
		{
			elem_key = *next_key;
		}
		else
		{
#ifdef HAVE_MEMSET
			memset (&elem_key, 0xff, KEY_SIZE);
#else
			for ( i=0; i < KEY_SIZE; i++ )
			{
				((char*)&elem_key)[i] = '\xff';
			}
#endif
		}

		pathrelse (&elem_path);
		if (bh->b_count != 0) brelse (bh);

	}	/* while reiserfs_search_by_key_4 */

	pathrelse (&elem_path);
	free (buf);

	return ret_part;
}

/**
 * Wipes the free space on the given ReiserFS filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_reiser_wipe_fs ( wfs_fsid_t FS, error_type * const error )
{
	errcode_enum ret_wfs = WFS_SUCCESS;
	unsigned long blk_no;
	struct buffer_head * bh;
	int selected[NPAT];
	unsigned char *buf;
	unsigned long int j;

	if ( error == NULL )
	{
		return WFS_BADPARAM;
	}

	if ( FS.rfs->fs_ondisk_sb->s_v1.sb_free_blocks == 0 )
	{
		/* nothing to do */
		return WFS_SUCCESS;
	}

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	buf = (unsigned char *) malloc ( wfs_reiser_get_block_size (FS) );
	if ( buf == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		return WFS_MALLOC;
	}

	/*blk_no < FS.rfs.fs_ondisk_sb->s_v1.sb_block_count*/
	for ( blk_no = 0; (blk_no < get_sb_block_count (FS.rfs->fs_ondisk_sb))
		&& (sig_recvd == 0) && (ret_wfs == WFS_SUCCESS); blk_no++ )
	{
		if (       (not_data_block   ( FS.rfs, blk_no ) != 0)
			|| (block_of_bitmap  ( FS.rfs, blk_no ) != 0)
			|| (block_of_journal ( FS.rfs, blk_no ) != 0)
			|| (reiserfs_bitmap_test_bit (FS.rfs->fs_bitmap2, blk_no) != 0)
		)
		{
			continue;
		}
		/* read the block just to fill the structure */
		bh = bread (FS.rfs->fs_dev, blk_no, wfs_reiser_get_block_size (FS));
		if ( bh == NULL )
		{
			continue;
		}

		/* write the block here. */
		for ( j = 0; (j < npasses) && (sig_recvd == 0) && (ret_wfs == WFS_SUCCESS); j++ )
		{

			fill_buffer ( j, (unsigned char *) bh->b_data,
				wfs_reiser_get_block_size (FS), selected );
			if ( sig_recvd != 0 )
			{
				ret_wfs = WFS_SIGNAL;
		       		break;
			}
			mark_buffer_dirty2 (bh);
			mark_buffer_uptodate2 (bh);
			error->errcode.gerror = bwrite (bh);
			if ( error->errcode.gerror != 0 )
			{
				/* check if block is marked as bad. If there is no 'badblocks' list
				   or the block is marked OK, then print the error. */
				if (FS.rfs->fs_badblocks_bm == NULL)
				{
					show_error ( *error, err_msg_wrtblk, fsname );
					ret_wfs = WFS_BLKWR;
				}
				else if (reiserfs_bitmap_test_bit (FS.rfs->fs_badblocks_bm, blk_no) == 0)
				{
					show_error ( *error, err_msg_wrtblk, fsname );
					ret_wfs = WFS_BLKWR;
				}
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			   Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (npasses > 1) && (sig_recvd == 0) && (ret_wfs == WFS_SUCCESS) )
			{
				error->errcode.gerror = wfs_reiser_flush_fs ( FS );
			}
		}
		if (bh->b_count != 0) brelse (bh);
	}	/* for block */

	free (buf);

	return ret_wfs;
}

/**
 * Starts recursive directory search for deleted inodes
 *	and undelete data on the given ReiserFS filesystem.
 * \param FS The filesystem.
 * \param node Filesystem element at which to start.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_reiser_wipe_unrm ( wfs_fsid_t FS, const fselem_t node, error_type * const error )
{
	errcode_enum ret_wfs = WFS_SUCCESS;
	struct key elem_key, *next_key;
	struct buffer_head * bh;
	struct path elem_path;
	struct item_head *head;
	int i;
	__u16 count;
	unsigned char * buf;
	unsigned long j;
	int selected[NPAT];
	struct reiserfs_de_head * deh;
	unsigned long blk_no;

	if ( error == NULL )
	{
		return WFS_BADPARAM;
	}

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	buf = (unsigned char *) malloc ( wfs_reiser_get_block_size (FS) );
	if ( buf == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		return WFS_MALLOC;
	}

	/* wipe journal */

	if ( reiserfs_open_journal (FS.rfs, NULL, 0) == 0 )
	{
		reiserfs_flush_journal (FS.rfs);
		reiserfs_close_journal (FS.rfs);
		for ( blk_no = get_jp_journal_1st_block (sb_jp (FS.rfs->fs_ondisk_sb));
			(blk_no < get_jp_journal_1st_block (sb_jp (FS.rfs->fs_ondisk_sb))
				+ get_jp_journal_size (&(FS.rfs->fs_ondisk_sb->s_v1.sb_journal)))
			&& (sig_recvd == 0);
			blk_no++ )
		{
			/*
			if ( block_of_journal ( &(FS.rfs), blk_no ) == 0
				|| blk_no <= get_jp_journal_1st_block (sb_jp (FS.rfs.fs_ondisk_sb))
				)
			{
				continue;
			}
			*/
			/* read the block just to fill the structure */
			bh = bread (FS.rfs->fs_dev, blk_no, wfs_reiser_get_block_size (FS));
			if ( bh == NULL )
			{
				continue;
			}

			/* write the block here. */
			for (j = 0; (j < npasses+1) && (sig_recvd == 0) && (ret_wfs == WFS_SUCCESS); j++)
			{
				/* Last pass has to be with zeros */
				if ( j == npasses )
				{
#ifdef HAVE_MEMSET
					memset ( bh->b_data, 0, wfs_reiser_get_block_size (FS) );
#else
					for ( i=0; i < wfs_reiser_get_block_size (FS); i++ )
					{
						bh->b_data[i] = '\0';
					}
#endif
				}
				else
				{
					fill_buffer ( j, (unsigned char *) bh->b_data,
						wfs_reiser_get_block_size (FS), selected );
				}
				if ( sig_recvd != 0 )
				{
					ret_wfs = WFS_SIGNAL;
					break;
				}
				mark_buffer_dirty2 (bh);
				mark_buffer_uptodate2 (bh);
				error->errcode.gerror = bwrite (bh);
				if ( error->errcode.gerror != 0 )
				{
					/* check if block is marked as bad. If there is no 'badblocks'
					   list or the block is marked OK, then print the error. */
					if (FS.rfs->fs_badblocks_bm == NULL)
					{
						show_error ( *error, err_msg_wrtblk, fsname );
						ret_wfs = WFS_BLKWR;
					}
					else if (reiserfs_bitmap_test_bit (FS.rfs->fs_badblocks_bm, blk_no) == 0)
					{
						show_error ( *error, err_msg_wrtblk, fsname );
						ret_wfs = WFS_BLKWR;
					}
				}
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				   Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( (npasses > 1) && (sig_recvd == 0) && (ret_wfs == WFS_SUCCESS) )
				{
					error->errcode.gerror = wfs_reiser_flush_fs ( FS );
				}
			}
			if (bh->b_count != 0) brelse (bh);
		}
		if ( sig_recvd != 0 )
		{
			ret_wfs = WFS_SIGNAL;
		}
	}	/* if reiserfs_open_journal */

	elem_key = node.rfs_elem;
	elem_path.path_length = ILLEGAL_PATH_ELEMENT_OFFSET;

	while ( (ret_wfs == WFS_SUCCESS)
		&& (reiserfs_search_by_key_4 ( FS.rfs, &elem_key, &elem_path ) == ITEM_FOUND)
		&& (sig_recvd == 0)
	)
	{
        	bh = PATH_PLAST_BUFFER (&elem_path);
        	if ( bh == NULL )
        	{
			pathrelse (&elem_path);
        		break;
        	}

		if (       (not_data_block   ( FS.rfs, bh->b_blocknr ) != 0)
			|| (block_of_bitmap  ( FS.rfs, bh->b_blocknr ) != 0)
			|| (block_of_journal ( FS.rfs, bh->b_blocknr ) != 0)
			)
		{
			/*pathrelse (&elem_path);*/
			while (bh->b_count != 0) brelse (bh);
			continue;
		}
		if ( sig_recvd != 0 )
		{
			pathrelse (&elem_path);
			while (bh->b_count != 0) brelse (bh);
			ret_wfs = WFS_SIGNAL;
	       		break;
		}

		for (i = get_item_pos (&elem_path), head = get_ih (&elem_path);
			(i < B_NR_ITEMS (bh)) && (sig_recvd == 0) && (ret_wfs == WFS_SUCCESS);
			i++, head++)
		{
			if (ih_reachable (head) == 0)
			{
				PATH_LAST_POSITION (&elem_path) = i;
				deh = B_I_DEH ( get_bh (&elem_path), head ) + elem_path.pos_in_item;

				/* reiserfsck deletes the file here */
				next_key = reiserfs_next_key (&elem_path);
				if (next_key != NULL)
				{
					elem_key = *next_key;
				}
				else
				{
#ifdef HAVE_MEMSET
					memset (&elem_key, 0xff, KEY_SIZE);
#else
					for ( j=0; j < KEY_SIZE; j++ )
					{
						((char*)&elem_key)[j] = '\xff';
					}
#endif
				}

				if ( (deh != NULL) && (get_ih_entry_count (head) != 0xFFFF) )
				{
					bh->b_state = 0;
					for ( j = 0; (j < npasses) && (sig_recvd == 0)
						&& (ret_wfs == WFS_SUCCESS); j++ )
					{
						for (count = elem_path.pos_in_item;
						     count < get_ih_entry_count (head); count ++, deh ++)
						{
							if ( name_in_entry_length (head, deh, count) > 0 )
							{
								fill_buffer ( j,
									(unsigned char *) name_in_entry (deh, count),
									(size_t) name_in_entry_length (head, deh, count),
									selected );
							}
						}
						if ( sig_recvd != 0 )
						{
							ret_wfs = WFS_SIGNAL;
		       					break;
						}
						mark_buffer_dirty2 (bh);
						mark_buffer_uptodate2 (bh);
	 					error->errcode.gerror = bwrite (bh);
						if ( error->errcode.gerror != 0 )
						{
							/* check if block is marked as bad. If there is no
							   'badblocks' list or the block is marked OK,
							   then print the error. */
							if (FS.rfs->fs_badblocks_bm == NULL)
							{
								show_error ( *error, err_msg_wrtblk, fsname );
								ret_wfs = WFS_BLKWR;
							}
							else if (reiserfs_bitmap_test_bit (FS.rfs->fs_badblocks_bm,
								bh->b_blocknr) == 0)
							{
								show_error ( *error, err_msg_wrtblk, fsname );
								ret_wfs = WFS_BLKWR;
							}
						}
						/* Flush after each writing, if more than 1 overwriting needs
						   to be done. Allow I/O bufferring (efficiency), if just one
						   pass is needed. */
						if ((npasses > 1) && (sig_recvd == 0) && (ret_wfs == WFS_SUCCESS))
						{
							error->errcode.gerror = wfs_reiser_flush_fs ( FS );
						}
						if ( sig_recvd != 0 )
						{
							ret_wfs = WFS_SIGNAL;
			       				break;
						}
					}
				}
			}	/* if (ih_reachable (head) == 0) */
		}	/* for i = get_item_pos (&elem_path) */
		if ( i < B_NR_ITEMS (bh) )
		{
			while (bh->b_count != 0) brelse (bh);
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
#ifdef HAVE_MEMSET
			memset (&elem_key, 0xff, KEY_SIZE);
#else
			for ( i=0; i < KEY_SIZE; i++ )
			{
				((char*)&elem_key)[i] = '\xff';
			}
#endif
		}

		pathrelse (&elem_path);

		while (bh != NULL && bh->b_count != 0) brelse (bh);	/* <<< */
	}	/* while */

	pathrelse (&elem_path);
	free (buf);
	return ret_wfs;
}



/**
 * Opens a ReiserFS filesystem on the given device.
 * \param dev_name Device name, like /dev/hdXY
 * \param FS Pointer to where the result will be put.
 * \param whichfs Pointer to an int saying which fs is curently in use.
 * \param data Pointer to fsdata structure containing information
 *	which may be needed to open the filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_reiser_open_fs ( const char * const dev_name, wfs_fsid_t * const FS, CURR_FS * const whichfs,
	const fsdata * const data, error_type * const error )
{
	errcode_enum ret = WFS_SUCCESS;
	reiserfs_filsys_t * res;
	char * dev_name_copy;
#if (!defined HAVE_MEMSET) || (!defined HAVE_MEMCPY)
	unsigned int i;
#endif

	if ((dev_name == NULL) || (FS == NULL) || (whichfs == NULL) || (data == NULL) || (error == NULL))
	{
		return WFS_BADPARAM;
	}

	*whichfs = CURR_NONE;

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	dev_name_copy = (char *) malloc ( strlen (dev_name) + 1 );
	if ( dev_name_copy == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		return WFS_MALLOC;
	}

#ifdef HAVE_MEMCPY
	memcpy ( dev_name_copy, dev_name, strlen (dev_name) + 1 );
#else
	for ( i=0; i < strlen (dev_name) + 1; i++ )
	{
		dev_name_copy[i] = dev_name[i];
	}
#endif

	res = reiserfs_open (dev_name_copy, O_RDWR | O_EXCL, &(error->errcode.gerror), NULL, 1);
	if ( (res == NULL) || (error->errcode.gerror != 0) )
	{
		free (dev_name_copy);
		return WFS_OPENFS;
	}

	FS->rfs = res;

	if (no_reiserfs_found (FS->rfs) != 0)
	{
		/*reiserfs_close ( &(FS->rfs) );*/
		free (dev_name_copy);
		return WFS_OPENFS;
	}

	/* TODO: how to read the badblock bitmap?
	   reiserfslib.c: void badblock_list(reiserfs_filsys_t * fs, badblock_func_t action, void *data)
	*/
	if ( reiserfs_open_ondisk_bitmap ( FS->rfs ) != 0 )
	{
		free (dev_name_copy);
		FS->rfs = NULL;
		return WFS_BLBITMAPREAD;
	}
	if ( FS->rfs->fs_bitmap2 == NULL )
	{
		free (dev_name_copy);
		FS->rfs = NULL;
		return WFS_BLBITMAPREAD;
	}

	*whichfs = CURR_REISERFS;
	free (dev_name_copy);

	return ret;
}

/**
 * Checks if the given ReiserFS filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_reiser_chk_mount ( const char * const dev_name, error_type * const error )
{
	int res;
	char * new_name;

        if ( dev_name == NULL ) return WFS_BADPARAM;

        new_name = (char *) malloc ( strlen (dev_name) + 1 );
        if ( new_name == NULL )
        {
		if ( error != NULL )
		{
			error->errcode.gerror = 1L;
		}
        	return WFS_MALLOC;
        }
        strncpy (new_name, dev_name, strlen (dev_name)+1 );

	res = misc_device_mounted (new_name);
	if ( (res == MF_NOT_MOUNTED) || (res == MF_RO) )
	{
		if ( error != NULL )
		{
			error->errcode.gerror = 0L;
		}
		free (new_name);
		return WFS_SUCCESS;
	}
	if ( error != NULL )
	{
		error->errcode.gerror = 1L;
	}
	free (new_name);
	return WFS_MNTRW;
}

/**
 * Closes the ReiserFS filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((nonnull))
wfs_reiser_close_fs ( wfs_fsid_t FS, error_type * const error WFS_ATTR ((unused)) )
{
	reiserfs_close_ondisk_bitmap ( FS.rfs );
	reiserfs_close ( FS.rfs );
	return WFS_SUCCESS;
}

/**
 * Checks if the ReiserFS filesystem has errors.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_reiser_check_err ( wfs_fsid_t FS )
{
	int state;
	int res;

	res = reiserfs_is_fs_consistent (FS.rfs);
	if ( res == 0 ) res = 1;
	else res = 0;

	state = get_sb_fs_state (FS.rfs->fs_ondisk_sb);
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

/**
 * Checks if the ReiserFS filesystem is dirty (has unsaved changes).
 * \param FS The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_reiser_is_dirty ( wfs_fsid_t FS )
{
	/* Declared, but not implemented and not used by anything in ReiserFSprogs...
	return filesystem_dirty (&(FS.rfs));
	*/
	return reiserfs_is_fs_consistent (FS.rfs);
}

/**
 * Flushes the ReiserFS filesystem.
 * \param FS The ReiserFS filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((nonnull))
wfs_reiser_flush_fs ( wfs_fsid_t FS )
{
	reiserfs_flush (FS.rfs);

#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_SYNC)
	sync ();
#endif
	return WFS_SUCCESS;
}

