/*
 * A program for secure cleaning of free space on filesystems.
 *	-- ReiserFSv4 file system-specific functions.
 *
 * Copyright (C) 2007-2019 Bogdan Drozdowski, bogdandr (at) op.pl
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

#include <stdio.h>

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

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* sync() */
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

/* this must be here, as it defines blk_t: */
#include "wipefreespace.h"

#if (defined HAVE_INT64_T) &&	\
	(! defined __int8_t_defined)	/* defined in stdint.h in older glibc */
/* workaround for a problem between libaal and newer glibc libraries - we
 * have int64_t defined, so don't re-define: */
# define __int8_t_defined 1
/*#define int64_t reiser4_int64_t */
#endif

/* Avoid some Reiser4 header files' name conflicts: */
#define div reiser4_div
#define index reiser4_index

/* we're not using these headers, so let's pretend they're already included,
   to avoid warnings caused by them. */
#define AAL_EXCEPTION_H 1
#define AAL_DEBUG_H 1
#define AAL_BITOPS_H 1
#define REISER4_FAKE_H 1

#if (defined HAVE_REISER4_LIBREISER4_H) && (defined HAVE_LIBREISER4)	\
	/*&& (defined HAVE_LIBREISER4MISC)*/ && (defined HAVE_LIBAAL)
# include <reiser4/libreiser4.h>
#else
# error Something wrong. Reiser4 requested, but headers or libraries missing.
#endif

#ifndef O_EXCL
# define O_EXCL		0200
#endif
#ifndef O_RDWR
# define O_RDWR		02
#endif

#include "wfs_reiser4.h"
#include "wfs_util.h"
#include "wfs_signal.h"
#include "wfs_wiping.h"

struct wfs_r4_block_data
{
	uint64_t block_number;
	wfs_fsid_t wfs_fs;
	reiser4_object_t * obj;
};

/* ======================================================================== */

#if (defined WFS_WANT_WFS) || (defined WFS_WANT_UNRM)
# ifndef WFS_ANSIC
static size_t GCC_WARN_UNUSED_RESULT wfs_r4_get_block_size WFS_PARAMS((const wfs_fsid_t wfs_fs));
# endif

/**
 * Returns the buffer size needed to work on the
 *	smallest physical unit on a Reiser4 filesystem.
 * \param wfs_fs The filesystem.
 * \return Block size on the filesystem.
 */
static size_t GCC_WARN_UNUSED_RESULT
wfs_r4_get_block_size (
# ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs )
# else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
# endif
{
	reiser4_fs_t * r4;

	r4 = (reiser4_fs_t *) wfs_fs.fs_backend;
	if ( r4 == NULL )
	{
		return 0;
	}
	if ( r4->status == NULL )
	{
		return 0;
	}
	/* This returns the correct detected block size on the filesystem */
	return r4->status->blksize;
	/* This returns the "temporary" block size used in aal_device_open()
	return r4->device->blksize;*/
}
#endif /* (defined WFS_WANT_WFS) || (defined WFS_WANT_UNRM) */

/* ================================== */
#ifdef WFS_REISER4_UNSHARED_BLOCKS

# ifndef WFS_ANSIC
static errno_t GCC_WARN_UNUSED_RESULT wfs_r4_wipe_last_block WFS_PARAMS ((
	uint64_t start, uint64_t len, void * data));
# endif

static errno_t GCC_WARN_UNUSED_RESULT
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_r4_wipe_last_block (
# ifdef WFS_ANSIC
	uint64_t start, uint64_t len, void * data)
# else
	start, len, data)
	uint64_t start;
	uint64_t len;
	void * data;
# endif
{
	struct wfs_r4_block_data * const bd = (struct wfs_r4_block_data *) data;
	errno_t ret_part = WFS_SUCCESS;
	int selected[WFS_NPAT] = {0};
	unsigned long int j;
	aal_block_t * block;
	unsigned int to_wipe, to_skip;
	reiser4_fs_t * r4;
	errno_t * error_ret;
	errno_t r4error = 0;
	size_t fs_block_size;

	if ( bd == NULL )
	{
		return WFS_BADPARAM;
	}
	r4 = (reiser4_fs_t *) bd->wfs_fs.fs_backend;
	error_ret = (errno_t *) bd->wfs_fs.fs_error;
	if ( (bd->obj == NULL) || (r4 == NULL) )
	{
		return WFS_BADPARAM;
	}
	if ( r4->device == NULL )
	{
		return WFS_BADPARAM;
	}
	fs_block_size = wfs_r4_get_block_size (bd->wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	if ( (bd->block_number + len) * fs_block_size
		< reiser4_object_size (bd->obj) )
	{
		bd->block_number += len;
		return ret_part;
	}
	/* find the last block number */
	j = 0;
	while ( (bd->block_number + j) * fs_block_size
		< reiser4_object_size (bd->obj) )
	{
		j++;
	}

	block = aal_block_load (r4->device,
		fs_block_size, start + j);
	if ( block == NULL )
	{
		return WFS_BLKITER;
	}
	to_skip = (unsigned int)((reiser4_object_size (bd->obj)
		% fs_block_size) & 0xFFFFFFFF);
	to_wipe = fs_block_size - to_skip;
	if ( to_wipe == 0 )
	{
		return WFS_SUCCESS;
	}
	/* wipe the last part of the last block */
	for ( j = 0; (j < bd->wfs_fs.npasses) && (sig_recvd == 0)
		/*&& (ret_part == WFS_SUCCESS)*/; j++ )
	{
		if ( bd->wfs_fs.no_wipe_zero_blocks != 0 )
		{
			r4error = aal_block_read (block);
			if ( r4error != 0 )
			{
				ret_part = WFS_BLKRD;
				break;
			}
			if ( wfs_is_block_zero (block->data, fs_block_size) != 0 )
			{
				/* this block is all-zeros - don't wipe, as requested */
				j = bd->wfs_fs.npasses * 2;
				break;
			}
		}
		fill_buffer ( j, (unsigned char *) &(((char *)(block->data))[to_skip]),
			to_wipe, selected, bd->wfs_fs );
		if ( sig_recvd != 0 )
		{
			ret_part = WFS_SIGNAL;
			break;
		}
		r4error = aal_block_write (block);
		if ( r4error != 0 )
		{
			ret_part = WFS_BLKWR;
			break;
		}
		/* Flush after each writing, if more than 1 overwriting needs to be done.
		   Allow I/O bufferring (efficiency), if just one pass is needed. */
		if ( WFS_IS_SYNC_NEEDED(bd->wfs_fs) )
		{
			r4error = wfs_r4_flush_fs (bd->wfs_fs);
		}
	}
	if ( (bd->wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
	{
		if ( j != bd->wfs_fs.npasses * 2 )
		{
			/* last pass with zeros: */
# ifdef HAVE_MEMSET
			memset ( (unsigned char *) &(((char *)(block->data))[to_skip]),
				0, to_wipe );
# else
			for ( j=0; j < to_wipe; j++ )
			{
				((unsigned char *) &(((char *)(block->data))[to_skip]))[j]
					= '\0';
			}
# endif
			if ( sig_recvd == 0 )
			{
				r4error = aal_block_write (block);
				if ( r4error != 0 )
				{
					ret_part = WFS_BLKWR;
				}
				/* No need to flush the last writing of a given block. *
				if ( (bd->wfs_fs.npasses > 1) && (sig_recvd == 0)
					&& (ret_part == WFS_SUCCESS) )
				{
					r4error = wfs_r4_flush_fs (bd->wfs_fs);
				} */
			}
		}
	}
	if ( error_ret != NULL )
	{
		*error_ret = r4error;
	}
	aal_block_free (block);
	return ret_part;
}

/* ======================================================================== */

# ifdef WFS_WANT_PART
#  ifndef WFS_ANSIC
static wfs_errcode_t GCC_WARN_UNUSED_RESULT wfs_r4_wipe_part_work WFS_PARAMS ((
	wfs_fsid_t wfs_fs, reiser4_tree_t * const tree,
	reiser4_object_t * const dir));
#  endif

/**
 * This is the function that actually does the wiping of the free space
 *	in partially used blocks on the given Reiser4 filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
static wfs_errcode_t GCC_WARN_UNUSED_RESULT
#  ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#  endif
wfs_r4_wipe_part_work (
#  ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs, reiser4_tree_t * const tree,
	reiser4_object_t * const dir)
#  else
	wfs_fs, tree, dir)
	wfs_fsid_t wfs_fs;
	reiser4_tree_t * const tree;
	reiser4_object_t * const dir;
#  endif
{
	wfs_errcode_t ret_part = WFS_SUCCESS;
	entry_hint_t entry;
	reiser4_object_t * child;
	wfs_errcode_t ret_temp;
	uint64_t obj_size;
	uint64_t to_wipe;
	int selected[WFS_NPAT] = {0};
	unsigned char *buf;
	unsigned long int j;
	uint64_t written;
	errno_t layout_res;
	struct wfs_r4_block_data bd;
	unsigned int prev_percent = 0;
	unsigned int curr_direlem = 0;
	reiser4_object_t * rootdir;
	uint64_t direlems;
	errno_t r4error = 0;
	reiser4_fs_t * r4;
	errno_t * error_ret;
	size_t fs_block_size;

	r4 = (reiser4_fs_t *) wfs_fs.fs_backend;
	error_ret = (errno_t *) wfs_fs.fs_error;
	if ( r4 == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = r4error;
		}
		return WFS_BADPARAM;
	}
	if ( r4->tree == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = r4error;
		}
		return WFS_BADPARAM;
	}
	rootdir = reiser4_object_obtain (r4->tree, NULL, &(r4->tree->key));
	if ( (tree == NULL) || (dir == NULL) )
	{
		if ( dir == rootdir )
		{
			wfs_show_progress (WFS_PROGRESS_PART, 100,
				&prev_percent);
		}
		if ( error_ret != NULL )
		{
			*error_ret = r4error;
		}
		return WFS_BADPARAM;
	}
	fs_block_size = wfs_r4_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	/* if file, wipe the free part of the last block: */
	if ( (reiser4_psobj (dir))->readdir == NULL )
	{
		obj_size = reiser4_object_size (dir);
		to_wipe = fs_block_size
			- obj_size % fs_block_size;
		if ( to_wipe == 0 )
		{
			if ( dir == rootdir )
			{
				wfs_show_progress (WFS_PROGRESS_PART,
					100, &prev_percent);
			}
			if ( error_ret != NULL )
			{
				*error_ret = r4error;
			}
			return WFS_SUCCESS;
		}
		/* we can only seek to 2^32, but the object's size may
		   be greater, so iterate over the blocks in that case. */
		if ( obj_size > 0xFFFFFFFF )
		{
			bd.wfs_fs = wfs_fs;
			bd.obj = dir;
			layout_res = reiser4_object_layout (dir,
				wfs_r4_wipe_last_block, &bd);
			if ( layout_res == 0 )
			{
				if ( dir == rootdir )
				{
					wfs_show_progress (WFS_PROGRESS_PART,
						100, &prev_percent);
				}
				if ( error_ret != NULL )
				{
					*error_ret = r4error;
				}
				return WFS_SUCCESS;
			}
			else
			{
				if ( dir == rootdir )
				{
					wfs_show_progress (WFS_PROGRESS_PART,
						100, &prev_percent);
				}
				if ( error_ret != NULL )
				{
					*error_ret = r4error;
				}
				return WFS_SEEKERR;
			}
		}
#  ifdef HAVE_ERRNO_H
		errno = 0;
#  endif
		buf = (unsigned char *) malloc (fs_block_size);
		if ( buf == NULL )
		{
#  ifdef HAVE_ERRNO_H
			r4error = errno;
#  else
			r4error = 12L;	/* ENOMEM */
#  endif
			if ( dir == rootdir )
			{
				wfs_show_progress (WFS_PROGRESS_PART,
					100, &prev_percent);
			}
			if ( error_ret != NULL )
			{
				*error_ret = r4error;
			}
			return WFS_MALLOC;
		}

		r4error = reiser4_object_seek
			(dir, (unsigned int)(obj_size & 0xFFFFFFFF));
		if ( r4error != 0 )
		{
			if ( dir == rootdir )
			{
				wfs_show_progress (WFS_PROGRESS_PART,
					100, &prev_percent);
			}
			free (buf);
			if ( error_ret != NULL )
			{
				*error_ret = r4error;
			}
			return WFS_SEEKERR;
		}

		for ( j = 0; (j < wfs_fs.npasses) && (sig_recvd == 0)
			/*&& (ret_part == WFS_SUCCESS)*/; j++ )
		{
			fill_buffer ( j, buf, fs_block_size,
				selected, wfs_fs );
			if ( sig_recvd != 0 )
			{
				ret_part = WFS_SIGNAL;
	       			break;
			}
			written = reiser4_object_write (dir, buf, (uint64_t)to_wipe);
			r4error = reiser4_object_seek
				(dir, (unsigned int)(obj_size & 0xFFFFFFFF));
			if ( (written != to_wipe) || (r4error != 0) )
			{
				ret_part = WFS_BLKWR;
				break;
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			   Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
			{
				r4error = wfs_r4_flush_fs (wfs_fs);
			}
		}
		if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
		{
			/* last pass with zeros: */
#  ifdef HAVE_MEMSET
			memset ( buf, 0, fs_block_size );
#  else
			for ( j=0; j < fs_block_size; j++ )
			{
				buf[j] = '\0';
			}
#  endif
			if ( sig_recvd == 0 )
			{
				written = reiser4_object_write (dir, buf, (uint64_t)to_wipe);
				r4error = reiser4_object_seek
					(dir, (unsigned int)(obj_size & 0xFFFFFFFF));
				if ( (written != to_wipe) || (r4error != 0) )
				{
					ret_part = WFS_BLKWR;
				}
				/* No need to flush the last writing of a given block. *
				if ( (wfs_fs.npasses > 1) && (sig_recvd == 0)
					&& (ret_part == WFS_SUCCESS) )
				{
					r4error = wfs_r4_flush_fs (wfs_fs);
				} */
			}
		}
		free (buf);
		reiser4_object_truncate (dir, obj_size);
	}
	/* if directory, dive into it: */
	else
	{
		r4error = reiser4_object_readdir (dir, &entry);
		direlems = 0;
		while ( r4error > 0 )
		{
			/* open child, recurse, close child */
			child = reiser4_object_open (tree, dir,
				&(entry.place));
			if ( child == NULL )
			{
				/* No errors. A dir can have no children */
				break;
			}
			direlems++;
			reiser4_object_close (child);
			/* read next entry: */
			r4error = reiser4_object_readdir (dir, &entry);
		}
		reiser4_object_reset (dir);
		while ( r4error > 0 )
		{
			/* open child, recurse, close child */
			child = reiser4_object_open (tree, dir,
				&(entry.place));
			if ( child == NULL )
			{
				/* No errors. A dir can have no children */
				break;
			}
			ret_temp = wfs_r4_wipe_part_work (wfs_fs,
				tree, child);
			if ( ret_part == WFS_SUCCESS )
			{
				ret_part = ret_temp;
			}
			reiser4_object_close (child);

			/* read next entry: */
			r4error = reiser4_object_readdir (dir, &entry);
			if ( (dir == rootdir) && (direlems > 0) )
			{
				curr_direlem++;
				wfs_show_progress (WFS_PROGRESS_PART,
					(unsigned int) (curr_direlem/direlems),
					&prev_percent);
			}
		}
	}
	if ( dir == rootdir )
	{
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
	}
	if ( error_ret != NULL )
	{
		*error_ret = r4error;
	}
	return ret_part;
}
# endif /* WFS_WANT_PART */
#endif	/* WFS_REISER4_UNSHARED_BLOCKS */

/* ======================================================================== */

#ifdef WFS_WANT_PART
/**
 * Wipes the free space in partially used blocks on the given Reiser4 filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_r4_wipe_part (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs
#  ifndef  WFS_REISER4_UNSHARED_BLOCKS
		WFS_ATTR ((unused))
#  endif
	 )
# else
	wfs_fs)
	wfs_fsid_t wfs_fs
#  ifndef  WFS_REISER4_UNSHARED_BLOCKS
		WFS_ATTR ((unused))
#  endif
	;
# endif
{
	wfs_errcode_t ret_part = WFS_SUCCESS;
	unsigned int prev_percent = 0;
# ifdef WFS_REISER4_UNSHARED_BLOCKS
	reiser4_object_t * root;
	reiser4_fs_t * r4;

	r4 = (reiser4_fs_t *) wfs_fs.fs_backend;
	if ( r4 == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		return WFS_BADPARAM;
	}
	if ( r4->tree == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		return WFS_BADPARAM;
	}

	root = reiser4_object_obtain (r4->tree, NULL, &(r4->tree->key));
	if ( root == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		return WFS_INOREAD;
	}

	ret_part = wfs_r4_wipe_part_work (wfs_fs, r4->tree, root);
	reiser4_object_close (root);
# endif	/* WFS_REISER4_UNSHARED_BLOCKS */
	wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
	return ret_part;
}
#endif /* WFS_WANT_PART */

/* ======================================================================== */

#ifdef WFS_WANT_WFS
/**
 * Wipes the free space on the given Reiser4 filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_r4_wipe_fs (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	count_t number_of_blocks;
	blk_t blk_no;
	const count_t one = 1;
	int selected[WFS_NPAT] = {0};
	unsigned long int j;
	aal_block_t * block;
	int had_to_open_alloc = 0;
	unsigned int prev_percent = 0;
	count_t curr_sector = 0;
	errno_t error = 0;
	reiser4_fs_t * r4;
	errno_t * error_ret;
	size_t fs_block_size;

	r4 = (reiser4_fs_t *) wfs_fs.fs_backend;
	error_ret = (errno_t *) wfs_fs.fs_error;
	if ( r4 == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	if ( r4->device == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	fs_block_size = wfs_r4_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	/*number_of_blocks = aal_device_len (wfs_fs.r4->device);*/
	number_of_blocks = reiser4_format_len (r4->device,
		(uint32_t)(fs_block_size & 0x0FFFFFFFF));
	if ( number_of_blocks == INVAL_BLK )
	{
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BLBITMAPREAD;
	}

	if ( r4->alloc == NULL )
	{
		r4->alloc = reiser4_alloc_open (r4, number_of_blocks);
		had_to_open_alloc = 1;
	}
	if ( r4->alloc == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BLBITMAPREAD;
	}
	for ( blk_no = REISER4_FS_MIN_SIZE (fs_block_size);
		(blk_no < number_of_blocks) && (sig_recvd == 0)
		/*&& (ret_wfs == WFS_SUCCESS)*/; blk_no++ )
	{
		if ( reiser4_alloc_available (r4->alloc, blk_no, one) != 0 )
		{
			/* block is unallocated, wipe it */
			block = aal_block_load (r4->device,
				(uint32_t)(fs_block_size & 0x0FFFFFFFF),
				blk_no);
			if ( block == NULL )
			{
				ret_wfs = WFS_BLKITER;
				curr_sector++;
				wfs_show_progress (WFS_PROGRESS_WFS,
					(unsigned int)((curr_sector * 100)/number_of_blocks),
					&prev_percent);
				continue;
			}
			for ( j = 0; (j < wfs_fs.npasses) && (sig_recvd == 0)
				/*&& (ret_wfs == WFS_SUCCESS)*/; j++ )
			{
				if ( wfs_fs.no_wipe_zero_blocks != 0 )
				{
					if ( wfs_is_block_zero (block->data, fs_block_size) != 0 )
					{
						/* this block is all-zeros - don't wipe, as requested */
						j = wfs_fs.npasses * 2;
						break;
					}
				}
				fill_buffer ( j, (unsigned char *) block->data,
					fs_block_size, selected, wfs_fs );
				if ( sig_recvd != 0 )
				{
					ret_wfs = WFS_SIGNAL;
		       			break;
				}
				error = aal_block_write (block);
				if ( error != 0 )
				{
					ret_wfs = WFS_BLKWR;
					break;
				}
				/* Flush after each writing, if more than 1
				   overwriting needs to be done. Allow I/O bufferring
				   (efficiency), if just one pass is needed. */
				if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
				{
					error = wfs_r4_flush_fs (wfs_fs);
				}
			}
			if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
			{
				if ( j != wfs_fs.npasses * 2 )
				{
					/* last pass with zeros: */
# ifdef HAVE_MEMSET
					memset ( (unsigned char *) block->data, 0,
						fs_block_size );
# else
					for ( j=0; j < fs_block_size; j++ )
					{
						((unsigned char *) block->data)[j]
							= '\0';
					}
# endif
					if ( sig_recvd == 0 )
					{
						error = aal_block_write (block);
						if ( error != 0 )
						{
							ret_wfs = WFS_BLKWR;
							/*break; free the block first */
						}
						/* No need to flush the last
						 * writing of a given block. *
						if ( (wfs_fs.npasses > 1)
							&& (sig_recvd == 0) )
						{
							error = wfs_r4_flush_fs (
								wfs_fs);
						} */
					}
				}
			}
			aal_block_free (block);
		}
		curr_sector++;
		wfs_show_progress (WFS_PROGRESS_WFS,
			(unsigned int)((curr_sector * 100)/number_of_blocks),
			&prev_percent);
	}
	wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
	if ( had_to_open_alloc != 0 )
	{
		reiser4_alloc_close (r4->alloc);
	}
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}

	return ret_wfs;
}
#endif /* WFS_WANT_WFS */

/* ======================================================================== */

#ifdef WFS_WANT_UNRM
# ifndef WFS_ANSIC
static errno_t GCC_WARN_UNUSED_RESULT wfs_r4_wipe_journal WFS_PARAMS ((
	uint64_t start, uint64_t len, void * data));
# endif

static errno_t GCC_WARN_UNUSED_RESULT
/*# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif*/
wfs_r4_wipe_journal (
# ifdef WFS_ANSIC
	uint64_t start, uint64_t len, void * data)
# else
	start, len, data)
	uint64_t start;
	uint64_t len;
	void * data;
# endif
{
	struct wfs_r4_block_data * const bd = (struct wfs_r4_block_data *) data;
	errno_t ret_journ = WFS_SUCCESS;
        uint64_t blk_no;
	int selected[WFS_NPAT] = {0};
	unsigned long int j;
	aal_block_t * block;
# if (!defined HAVE_MEMSET)
	unsigned int i;
# endif
	unsigned int prev_percent = 0;
	uint64_t curr_sector = 0;
	reiser4_fs_t * r4;
	errno_t * error_ret;
	errno_t r4error = 0;
	size_t fs_block_size;

	if ( bd == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_UNRM, 50, &prev_percent);
		return WFS_BADPARAM;
	}
	r4 = (reiser4_fs_t *) bd->wfs_fs.fs_backend;
	error_ret = (errno_t *) bd->wfs_fs.fs_error;
	if ( r4 == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_UNRM, 50, &prev_percent);
		return WFS_BADPARAM;
	}
	if ( r4->device == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_UNRM, 50, &prev_percent);
		return WFS_BADPARAM;
	}
	fs_block_size = wfs_r4_get_block_size (bd->wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	/* wipe the journal. */
	for ( blk_no = start; (blk_no < start+len) && (sig_recvd == 0)
		/*&& (ret_journ == WFS_SUCCESS)*/; blk_no++ )
	{
		block = aal_block_load (r4->device,
			(uint32_t)(fs_block_size & 0x0FFFFFFFF), blk_no);
		if ( block == NULL )
		{
			curr_sector++;
			wfs_show_progress (WFS_PROGRESS_UNRM,
				(unsigned int) ((curr_sector*50)/len), &prev_percent);
			continue;
		}
		for ( j = 0; (j < bd->wfs_fs.npasses) && (sig_recvd == 0)
			/*&& (ret_journ == WFS_SUCCESS)*/; j++ )
		{
			if ( bd->wfs_fs.no_wipe_zero_blocks != 0 )
			{
				if ( wfs_is_block_zero (block->data, fs_block_size) != 0 )
				{
					/* this block is all-zeros - don't wipe, as requested */
					j = bd->wfs_fs.npasses * 2;
					break;
				}
			}
			fill_buffer ( j, (unsigned char *) block->data,
				fs_block_size, selected, bd->wfs_fs );
			if ( sig_recvd != 0 )
			{
				ret_journ = WFS_SIGNAL;
				break;
			}
			r4error = aal_block_write (block);
			if ( r4error != 0 )
			{
				ret_journ = WFS_BLKWR;
				break;
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			   Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( WFS_IS_SYNC_NEEDED(bd->wfs_fs) )
			{
				r4error = wfs_r4_flush_fs (bd->wfs_fs);
			}
		}
		/* zero-out the first 2 blocks */
		if ( (bd->block_number == 0) || (bd->block_number == 1) )
		{
			if ( j != bd->wfs_fs.npasses * 2 )
			{
# ifdef HAVE_MEMSET
				memset ( block->data, 0, fs_block_size );
# else
				for ( i = 0; i < fs_block_size; i++ )
				{
					((char *)block->data)[i] = '\0';
				}
# endif
				r4error = aal_block_write (block);
				if ( r4error != 0 )
				{
					ret_journ = WFS_BLKWR;
				}
			}
		}
		else
		{
			if ( j != bd->wfs_fs.npasses * 2 )
			{
				if ( (bd->wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
				{
					/* last pass with zeros: */
# ifdef HAVE_MEMSET
					memset ((unsigned char *) block->data, 0,
						fs_block_size);
# else
					for ( j=0; j < fs_block_size;
						j++ )
					{
						((unsigned char *) block->data)[j] = '\0';
					}
# endif
					if ( sig_recvd == 0 )
					{
						r4error = aal_block_write (block);
						if ( r4error != 0 )
						{
							ret_journ = WFS_BLKWR;
							/*break; free the block first */
						}
						/* No need to flush the last
						 * writing of a given block. *
						if ( (bd->wfs_fs.npasses > 1)
							&& (sig_recvd == 0) )
						{
							r4error = wfs_r4_flush_fs (
								bd->wfs_fs);
						} */
					}
				}
			}
		}
		aal_block_free (block);
		/* increase the block number for future iterations and calls */
		bd->block_number++;
		curr_sector++;
		wfs_show_progress (WFS_PROGRESS_UNRM,
			(unsigned int) ((curr_sector*50)/len), &prev_percent);
	}
	wfs_show_progress (WFS_PROGRESS_UNRM, 50, &prev_percent);
	if ( error_ret != NULL )
	{
		*error_ret = r4error;
	}
	return ret_journ;
}


/* ======================================================================== */

# ifndef WFS_ANSIC
static errno_t GCC_WARN_UNUSED_RESULT wfs_r4_wipe_object WFS_PARAMS ((
	uint64_t start, uint64_t len, void * data));
# endif

static errno_t GCC_WARN_UNUSED_RESULT
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_r4_wipe_object (
# ifdef WFS_ANSIC
	uint64_t start, uint64_t len, void * data)
# else
	start, len, data)
	uint64_t start;
	uint64_t len;
	void * data;
# endif
{
	errno_t ret_obj = WFS_SUCCESS;
	struct wfs_r4_block_data * const bd = (struct wfs_r4_block_data *) data;
        uint64_t blk_no;
	int selected[WFS_NPAT] = {0};
	unsigned long int j;
	aal_block_t * block;
	reiser4_fs_t * r4;
	errno_t * error_ret;
	errno_t r4error = 0;
	size_t fs_block_size;

	if ( bd == NULL )
	{
		return WFS_BADPARAM;
	}
	r4 = (reiser4_fs_t *) bd->wfs_fs.fs_backend;
	error_ret = (errno_t *) bd->wfs_fs.fs_error;
	if ( (bd->obj == NULL) || (r4 == NULL) )
	{
		return WFS_BADPARAM;
	}
	if ( r4->device == NULL )
	{
		return WFS_BADPARAM;
	}
	fs_block_size = wfs_r4_get_block_size (bd->wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	/* wipe the object. */
	for ( blk_no = start; (blk_no < start+len) && (sig_recvd == 0)
		/*&& (ret_obj == WFS_SUCCESS)*/; blk_no++ )
	{
		block = aal_block_load (r4->device,
			(uint32_t)(fs_block_size & 0x0FFFFFFFF), blk_no);
		if ( block == NULL )
		{
			continue;
		}
		for ( j = 0; (j < bd->wfs_fs.npasses) && (sig_recvd == 0)
			/*&& (ret_obj == WFS_SUCCESS)*/; j++ )
		{
			if ( bd->wfs_fs.no_wipe_zero_blocks != 0 )
			{
				if ( wfs_is_block_zero (block->data, fs_block_size) != 0 )
				{
					/* this block is all-zeros - don't wipe, as requested */
					j = bd->wfs_fs.npasses * 2;
					break;
				}
			}
			if ( (bd->block_number + blk_no)
				* fs_block_size
				< reiser4_object_size (bd->obj) )
			{
				fill_buffer ( j, (unsigned char *) block->data,
					(size_t)((fs_block_size
						- (reiser4_object_size (bd->obj)
						% fs_block_size)) & 0xFFFFFFFF),
					selected, bd->wfs_fs );
			}
			else
			{
				fill_buffer ( j, (unsigned char *) block->data,
					fs_block_size,
					selected, bd->wfs_fs );
			}
			if ( sig_recvd != 0 )
			{
				ret_obj = WFS_SIGNAL;
				break;
			}
			r4error = aal_block_write (block);
			if ( r4error != 0 )
			{
				ret_obj = WFS_BLKWR;
				break;
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			   Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( WFS_IS_SYNC_NEEDED(bd->wfs_fs) )
			{
				r4error = wfs_r4_flush_fs (bd->wfs_fs);
			}
		}
		if ( (bd->wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
		{
			if ( j != bd->wfs_fs.npasses * 2 )
			{
				/* last pass with zeros: */
# ifdef HAVE_MEMSET
				memset ( (unsigned char *) block->data, 0,
					fs_block_size );
# else
				for ( j=0; j < fs_block_size; j++ )
				{
					((unsigned char *) block->data)[j] = '\0';
				}
# endif
				if ( sig_recvd == 0 )
				{
					r4error = aal_block_write (block);
					if ( r4error != 0 )
					{
						ret_obj = WFS_BLKWR;
						/*break; free the block first */
					}
					/* No need to flush the last writing
					 * of a given block. *
					if ( (bd->wfs_fs.npasses > 1)
						&& (sig_recvd == 0) )
					{
						r4error = wfs_r4_flush_fs (bd->wfs_fs);
					} */
				}
			}
		}
		aal_block_free (block);
		/* increase the block number for future iterations and calls */
		bd->block_number++;
	}
	if ( error_ret != NULL )
	{
		*error_ret = r4error;
	}
	return ret_obj;
}

/* ======================================================================== */

# ifndef WFS_ANSIC
static wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_r4_wipe_unrm_work WFS_PARAMS ((wfs_fsid_t wfs_fs, reiser4_node_t * r4node));
# endif

/**
 * The worker function for recursive directory search for deleted inodes
 *	and undelete data on the given Reiser4 filesystem.
 * \param wfs_fs The filesystem.
 * \param r4node Filesystem element at which to start.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
static wfs_errcode_t GCC_WARN_UNUSED_RESULT
/*# ifdef WFS_ANSIC
WFS_ATTR ((nonnull)) NEVER enable this - r4node can be NULL
# endif*/
wfs_r4_wipe_unrm_work (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs, reiser4_node_t * r4node)
# else
	wfs_fs, r4node)
	wfs_fsid_t wfs_fs;
	reiser4_node_t * r4node;
# endif
{
	wfs_errcode_t ret_unrm = WFS_SUCCESS, ret_temp;
	struct wfs_r4_block_data bd;
	uint32_t i, j;
	blk_t blk_no;
	reiser4_node_t *child;
	reiser4_place_t place;
	reiser4_key_t key_copy;
	reiser4_object_t * to_wipe;
	lookup_hint_t for_search;
	lookup_t search_res;
	errno_t e;
	unsigned int prev_percent = 50;
	uint64_t curr_direlem = 0;
	errno_t error = 0;
	reiser4_fs_t * r4;
	errno_t * error_ret;
	uint32_t r4node_items;
	uint32_t place_units;

	r4 = (reiser4_fs_t *) wfs_fs.fs_backend;
	error_ret = (errno_t *) wfs_fs.fs_error;
	if ( r4 == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	bd.wfs_fs = wfs_fs;

	/* wipe the journal */
	if ( r4->journal == NULL )
	{
		r4->journal = reiser4_journal_open (r4, r4->device);
	}

	if ( r4->journal != NULL )
	{
		reiser4_journal_sync (r4->journal);
		bd.block_number = 0;
		bd.obj = NULL;
		error = reiser4_journal_layout (r4->journal,
			wfs_r4_wipe_journal, &bd);
		if ( error != 0 )
		{
			ret_unrm = WFS_BLKITER;
		}
	}

	if ( (r4node == NULL) && (r4->tree != NULL) )
	{
		reiser4_tree_load_root (r4->tree);
		r4node = r4->tree->root;
	}

	if ( (r4->tree == NULL) || (r4node == NULL) )
	{
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return ret_unrm;
	}

	r4node_items = reiser4_node_items (r4node);
	/* wipe undelete data - actually, wipe damaged/unused keys. */
	for ( i = 0; i < r4node_items; i++)
	{
		reiser4_place_assign (&place, r4node, i, MAX_UINT32);
		e = reiser4_place_fetch (&place);
		if ( e != 0 )
		{
			/* could not fetch place data - move on to the next item */
			curr_direlem++;
			wfs_show_progress (WFS_PROGRESS_UNRM,
				(unsigned int)(50 + (curr_direlem * 50)
				/reiser4_node_items (r4node)), &prev_percent);
			continue;
		}

		/* if not branch node, check correctness and wipe if damaged/unused */
		if ( reiser4_item_branch (place.plug) == 0 )
		{
# ifdef HAVE_MEMCPY
			memcpy (&key_copy, &(place.key),
				sizeof (reiser4_key_t));
# else
			for ( i = 0; i < sizeof (reiser4_key_t); i++ )
			{
				((char*)&key_copy)[i]
					= ((char*)&(place.key))[i];
			}
# endif
			if ( key_copy.plug->check_struct == NULL )
			{
				curr_direlem++;
				wfs_show_progress (WFS_PROGRESS_UNRM,
					(unsigned int)(50 + (curr_direlem * 50)
					/reiser4_node_items (r4node)), &prev_percent);
				continue;
			}
			e = key_copy.plug->check_struct (&key_copy);
			if ( e < 0 )
			{
				curr_direlem++;
				wfs_show_progress (WFS_PROGRESS_UNRM,
					(unsigned int)(50 + (curr_direlem * 50)
					/reiser4_node_items (r4node)), &prev_percent);
				continue;
			}
			if ( e != 0 )
			{
				/* damaged key. wipe it. */
				for_search.key = &(place.key);
				for_search.level = LEAF_LEVEL;
				for_search.collision = NULL;
                                search_res = reiser4_tree_lookup (r4->tree,
					&for_search,
                                	FIND_EXACT, &place);
                                if ( search_res == PRESENT )
                                {
					to_wipe = reiser4_object_open (r4->tree,
						NULL, &place);
					if ( to_wipe == NULL )
					{
						to_wipe = reiser4_object_obtain (
							r4->tree,
							NULL, &(place.key));
					}
					if ( to_wipe != NULL )
					{
						bd.block_number = 0;
						bd.obj = to_wipe;
						reiser4_object_layout
							(to_wipe,
							wfs_r4_wipe_object,
							&bd);
						reiser4_object_close (to_wipe);
					}
				}
				/* change the key type and hash to something meaningless */
				reiser4_key_set_type (&(place.key), KEY_ATTRNAME_TYPE);
				reiser4_key_set_hash (&(place.key), MAX_UINT64);
				reiser4_node_mkdirty (r4node);
				reiser4_node_sync (r4node);
				aal_block_write (r4node->block);
			}
			curr_direlem++;
			wfs_show_progress (WFS_PROGRESS_UNRM,
				(unsigned int)(50 + (curr_direlem * 50)
				/reiser4_node_items (r4node)), &prev_percent);
			continue;
		}
		/* if branch node, recurse */
		else
		{
			place_units = reiser4_item_units (&place);
			for ( j=0; j < place_units; j++ )
			{
				/* select unit */
				place.pos.unit = j;
				/* get block number */
				blk_no = reiser4_item_down_link (&place);
				/* get child node */
				child = reiser4_tree_lookup_node (r4->tree, blk_no);
				if ( child == NULL )
				{
					continue;
				}
				ret_temp = wfs_r4_wipe_unrm_work (wfs_fs, child);
				if ( ret_unrm == WFS_SUCCESS )
				{
					ret_unrm = ret_temp;
				}
				/* NOTE: probably better NOT release "child" here */
			}
		}
		curr_direlem++;
		wfs_show_progress (WFS_PROGRESS_UNRM,
			(unsigned int)(50 + (curr_direlem * 50)
			/reiser4_node_items (r4node)), &prev_percent);
	}
	wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return ret_unrm;
}

/* ======================================================================== */

/**
 * Starts recursive directory search for deleted inodes
 *	and undelete data on the given Reiser4 filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_r4_wipe_unrm (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
# endif
{
	reiser4_node_t * r4node = NULL;
	reiser4_fs_t * r4;

	r4 = (reiser4_fs_t *) wfs_fs.fs_backend;
	if ( r4 != NULL )
	{
		if ( r4->tree != NULL )
		{
			r4node = r4->tree->root;
		}
	}

	return wfs_r4_wipe_unrm_work (wfs_fs, r4node);
}
#endif /* WFS_WANT_UNRM */

/* ======================================================================== */

/**
 * Opens a Reiser4 filesystem on the given device.
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
wfs_r4_open_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t * const wfs_fs,
	const wfs_fsdata_t * const data WFS_ATTR ((unused)))
#else
	wfs_fs, data)
	wfs_fsid_t * const wfs_fs;
	const wfs_fsdata_t * const data WFS_ATTR ((unused));
#endif
{
	aal_device_t * dev;
	char * dev_name_copy;
	size_t namelen;
	errno_t error = 0;
	reiser4_fs_t * r4;
	errno_t * error_ret = NULL;

	if ( wfs_fs == NULL )
	{
		return WFS_BADPARAM;
	}
	error_ret = (errno_t *) wfs_fs->fs_error;
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
	namelen = strlen (wfs_fs->fsname);

	/* malloc a new array for dev_name */
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	dev_name_copy = (char *) malloc (namelen + 1);
	if ( dev_name_copy == NULL )
	{
#ifdef HAVE_ERRNO_H
		error = errno;
#else
		error = 12L;	/* ENOMEM */
#endif
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	strncpy (dev_name_copy, wfs_fs->fsname, namelen + 1);
	dev_name_copy[namelen] = '\0';

	if ( libreiser4_init () != 0 )
	{
		error = 100;
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		free (dev_name_copy);
		return WFS_OPENFS;
	}

	/* 512 is the default, just for opening. Later on we use the status
	   field to get the block size */
	dev = aal_device_open (&file_ops, dev_name_copy, 512, O_RDWR | O_EXCL
#ifdef O_BINARY
		| O_BINARY
#endif
		);
	if ( dev == NULL )
	{
		error = 101;
		free (dev_name_copy);
		libreiser4_fini ();
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_OPENFS;
	}

	r4 = reiser4_fs_open (dev, 1);
	if ( r4 == NULL )
	{
		error = 102;
		aal_device_close (dev);
		free (dev_name_copy);
		libreiser4_fini ();
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_OPENFS;
	}

	wfs_fs->whichfs = WFS_CURR_FS_REISER4;
	wfs_fs->fs_backend = r4;

	/*  dev_name_copy free()d upon close() */
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return WFS_SUCCESS;
}

/* ======================================================================== */

/**
 * Checks if the given Reiser4 filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_r4_chk_mount (
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
 * Closes the Reiser4 filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_r4_close_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs;
#endif
{
	aal_device_t * dev;
	reiser4_fs_t * r4;

	r4 = (reiser4_fs_t *) wfs_fs.fs_backend;
	if ( r4 == NULL )
	{
		return WFS_BADPARAM;
	}
	dev = r4->device;
	reiser4_fs_close (r4);
	if ( dev != NULL )
	{
		/* free device->person (malloced array for dev_name_copy on init) */
		if ( dev->person != NULL )
		{
			free (dev->person);
		}
		aal_device_close (dev);
	}
	libreiser4_fini ();
	return WFS_SUCCESS;
}

/* ======================================================================== */

/**
 * Checks if the Reiser4 filesystem has errors.
 * \param wfs_fs The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_r4_check_err (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs )
#else
	wfs_fs )
	wfs_fsid_t wfs_fs;
#endif
{
	int res = 0;
	reiser4_fs_t * r4;

	r4 = (reiser4_fs_t *) wfs_fs.fs_backend;
	if ( r4 == NULL )
	{
		return 1;
	}
	if ( r4->status != NULL )
	{
		if ( (r4->status->ent.ss_status & FS_CORRUPTED) != 0 )
		{
			res++;
		}
		if ( (r4->status->ent.ss_status & FS_DAMAGED) != 0 )
		{
			res++;
		}
		if ( (r4->status->ent.ss_status & FS_DESTROYED) != 0 )
		{
			res++;
		}
	}
	return res;
}

/* ======================================================================== */

/**
 * Checks if the Reiser4 filesystem is dirty (has unsaved changes).
 * \param wfs_fs The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_r4_is_dirty (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs )
#else
	wfs_fs )
	wfs_fsid_t wfs_fs;
#endif
{
	int res = 0;
	reiser4_fs_t * r4;

	r4 = (reiser4_fs_t *) wfs_fs.fs_backend;
	if ( r4 == NULL )
	{
		return 1;
	}
	if ( r4->status != NULL )
	{
		if ( r4->status->ent.ss_status != 0 )
		{
			res++;
		}
		if ( r4->status->dirty != 0 )
		{
			res++;
		}
	}
	else
	{
		res++;
	}
	if ( r4->master != NULL )
	{
		if ( r4->master->dirty != 0 )
		{
			res++;
		}
	}
	return res;
}

/* ======================================================================== */

/**
 * Flushes the Reiser4 filesystem.
 * \param wfs_fs The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_r4_flush_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs )
#else
	wfs_fs )
	wfs_fsid_t wfs_fs;
#endif
{
	reiser4_fs_t * r4;

	r4 = (reiser4_fs_t *) wfs_fs.fs_backend;
	if ( r4 == NULL )
	{
		return WFS_BADPARAM;
	}
	reiser4_fs_sync (r4);
	if ( r4->device != NULL )
	{
		aal_device_sync (r4->device);
	}
#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_SYNC)
	sync ();
#endif
	return WFS_SUCCESS;
}

/* ======================================================================== */

/**
 * Print the version of the current library, if applicable.
 */
void wfs_r4_print_version (
#ifdef WFS_ANSIC
	void
#endif
)
{
	const char *lib_ver = NULL;

	lib_ver = libreiser4_version ();
	printf ( "LibReiser4 %s\n",
		(lib_ver != NULL)? lib_ver : "<?>" );
}

/* ======================================================================== */

/**
 * Get the preferred size of the error variable.
 * \return the preferred size of the error variable.
 */
size_t wfs_r4_get_err_size (
#ifdef WFS_ANSIC
	void
#endif
)
{
	return sizeof (errno_t);
}

/* ======================================================================== */

/**
 * Initialize the library.
 */
void wfs_r4_init (
#ifdef WFS_ANSIC
	void
#endif
)
{
}

/* ======================================================================== */

/**
 * De-initialize the library.
 */
void wfs_r4_deinit (
#ifdef WFS_ANSIC
	void
#endif
)
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
wfs_r4_show_error (
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
