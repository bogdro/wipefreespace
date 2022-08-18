/*
 * A program for secure cleaning of free space on filesystems.
 *	-- ReiserFSv4 file system-specific functions.
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

/* redefine the inline sig function from hfsp, each time with a different name */
extern unsigned long int wfs_r4_sig(char c0, char c1, char c2, char c3);
#define sig(a,b,c,d) wfs_r4_sig(a,b,c,d)

/* this must be here, as it defines blk_t: */
#include "wipefreespace.h"

#if (defined HAVE_REISER4_LIBREISER4_H) && (defined HAVE_LIBREISER4)	\
	&& (defined HAVE_LIBREISER4MISC) && (defined HAVE_LIBAAL)
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
	wfs_fsid_t FS;
	wfs_error_type_t * error;
	reiser4_object_t * obj;
};

/* ======================================================================== */

#if (defined WFS_WANT_WFS) || (defined WFS_WANT_UNRM)
# ifndef WFS_ANSIC
static size_t WFS_ATTR ((warn_unused_result)) wfs_r4_get_block_size WFS_PARAMS((const wfs_fsid_t FS));
# endif

/**
 * Returns the buffer size needed to work on the
 *	smallest physical unit on a Reiser4 filesystem.
 * \param FS The filesystem.
 * \return Block size on the filesystem.
 */
static size_t WFS_ATTR ((warn_unused_result))
wfs_r4_get_block_size (
# ifdef WFS_ANSIC
	const wfs_fsid_t FS )
# else
	FS)
	const wfs_fsid_t FS;
# endif
{
	if ( FS.r4 == NULL )
	{
		return 0;
	}
	if ( FS.r4->status == NULL )
	{
		return 0;
	}
	/* This returns the correct detected block size on the filesystem */
	return FS.r4->status->blksize;
	/* This returns the "temporary" block size used in aal_device_open()
	return FS.r4->device->blksize;*/
}
#endif /* (defined WFS_WANT_WFS) || (defined WFS_WANT_UNRM) */

/* ================================== */
#ifdef WFS_REISER4_UNSHARED_BLOCKS

# ifndef WFS_ANSIC
static errno_t WFS_ATTR ((warn_unused_result)) wfs_r4_wipe_last_block WFS_PARAMS ((
	uint64_t start, uint64_t len, void * data));
# endif

static errno_t WFS_ATTR ((warn_unused_result))
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
	int selected[WFS_NPAT];
	unsigned long int j;
	aal_block_t * block;
	unsigned int to_wipe, to_skip;

	if ( bd == NULL )
	{
		return WFS_BADPARAM;
	}
	if ( (bd->error == NULL) || (bd->obj == NULL) || (bd->FS.r4 == NULL) )
	{
		return WFS_BADPARAM;
	}
	if ( bd->FS.r4->device == NULL )
	{
		return WFS_BADPARAM;
	}

	if ( (bd->block_number + len) * wfs_r4_get_block_size (bd->FS)
		< reiser4_object_size (bd->obj) )
	{
		bd->block_number += len;
		return ret_part;
	}
	/* find the last block number */
	j = 0;
	while ( (bd->block_number + j) * wfs_r4_get_block_size (bd->FS)
		< reiser4_object_size (bd->obj) )
	{
		j++;
	}

	block = aal_block_load (bd->FS.r4->device, wfs_r4_get_block_size (bd->FS), start + j);
	if ( block == NULL )
	{
		return WFS_BLKITER;
	}
	to_skip = (unsigned int)((reiser4_object_size (bd->obj)
		% wfs_r4_get_block_size (bd->FS)) & 0xFFFFFFFF);
	to_wipe = wfs_r4_get_block_size (bd->FS) - to_skip;
	if ( to_wipe == 0 )
	{
		return WFS_SUCCESS;
	}
	/* wipe the last part of the last block */
	for ( j = 0; (j < FS.npasses) && (sig_recvd == 0) /*&& (ret_part == WFS_SUCCESS)*/; j++ )
	{
		fill_buffer ( j, (unsigned char *) &(((char *)(block->data))[to_skip]),
			to_wipe, selected, bd->FS );
		if ( sig_recvd != 0 )
		{
			ret_part = WFS_SIGNAL;
			break;
		}
		bd->error->errcode.r4error = aal_block_write (block);
		if ( bd->error->errcode.r4error != 0 )
		{
			ret_part = WFS_BLKWR;
			break;
		}
		/* Flush after each writing, if more than 1 overwriting needs to be done.
		   Allow I/O bufferring (efficiency), if just one pass is needed. */
		if ( (FS.npasses > 1) && (sig_recvd == 0) )
		{
			bd->error->errcode.gerror = wfs_r4_flush_fs ( bd->FS );
		}
	}
	if ( (bd->FS.zero_pass != 0) && (sig_recvd == 0) )
	{
		/* last pass with zeros: */
# ifdef HAVE_MEMSET
		memset ( (unsigned char *) &(((char *)(block->data))[to_skip]), 0, to_wipe );
# else
		for ( j=0; j < to_wipe; j++ )
		{
			((unsigned char *) &(((char *)(block->data))[to_skip]))[j] = '\0';
		}
# endif
		if ( sig_recvd == 0 )
		{
			bd->error->errcode.r4error = aal_block_write (block);
			if ( bd->error->errcode.r4error != 0 )
			{
				ret_part = WFS_BLKWR;
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (FS.npasses > 1) && (sig_recvd == 0) && (ret_part == WFS_SUCCESS) )
			{
				bd->error->errcode.gerror = wfs_r4_flush_fs ( bd->FS );
			}
		}
	}
	return ret_part;
}

/* ======================================================================== */

# ifdef WFS_WANT_PART
#  ifndef WFS_ANSIC
static wfs_errcode_t WFS_ATTR ((warn_unused_result)) wfs_r4_wipe_part_work WFS_PARAMS ((
	wfs_fsid_t FS, reiser4_tree_t * const tree,
	reiser4_object_t * const dir, wfs_error_type_t * const error));
#  endif

/**
 * This is the function that actually does the wiping of the free space
 *	in partially used blocks on the given Reiser4 filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
static wfs_errcode_t WFS_ATTR ((warn_unused_result))
#  ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#  endif
wfs_r4_wipe_part_work (
#  ifdef WFS_ANSIC
	wfs_fsid_t FS, reiser4_tree_t * const tree,
	reiser4_object_t * const dir, wfs_error_type_t * const error_ret)
#  else
	FS, tree, dir, error_ret)
	wfs_fsid_t FS;
	reiser4_tree_t * const tree;
	reiser4_object_t * const dir;
	wfs_error_type_t * const error_ret;
#  endif
{
	wfs_errcode_t ret_part = WFS_SUCCESS;
	entry_hint_t entry;
	reiser4_object_t * child;
	wfs_errcode_t ret_temp;
	uint64_t obj_size;
	uint64_t to_wipe;
	int selected[WFS_NPAT];
	unsigned char *buf;
	unsigned long int j;
	uint64_t written;
	errno_t layout_res;
	struct wfs_r4_block_data bd;
	unsigned int prev_percent = 0;
	unsigned int curr_direlem = 0;
	reiser4_object_t * rootdir = FS.r4->tree->root;
	uint64_t direlems;
	wfs_error_type_t error = {CURR_REISER4, {0}};

	if ( (tree == NULL) || (dir == NULL) || (FS.r4 == NULL) )
	{
		if ( dir == rootdir )
		{
			show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		}
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	rootdir = reiser4_object_obtain (FS.r4->tree, NULL, &(FS.r4->tree->key));
	/* if file, wipe the free part of the last block: */
	if ( (reiser4_psobj (dir))->readdir == NULL )
	{
		obj_size = reiser4_object_size (dir);
		to_wipe = wfs_r4_get_block_size (FS) - obj_size % wfs_r4_get_block_size (FS);
		if ( to_wipe == 0 )
		{
			if ( dir == rootdir )
			{
				show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
			}
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_SUCCESS;
		}
		/* we can only seek to 2^32, but the object's size may
		   be greater, so iterate over the blocks in that case. */
		if ( obj_size > 0xFFFFFFFF )
		{
			bd.FS = FS;
			bd.error = error;
			bd.obj = dir;
			layout_res = reiser4_object_layout (dir, wfs_r4_wipe_last_block, &bd);
			if ( layout_res == 0 )
			{
				if ( dir == rootdir )
				{
					show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
				}
				if ( error_ret != NULL )
				{
					*error_ret = error;
				}
				return WFS_SUCCESS;
			}
			else
			{
				if ( dir == rootdir )
				{
					show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
				}
				if ( error_ret != NULL )
				{
					*error_ret = error;
				}
				return WFS_SEEKERR;
			}
		}
#  ifdef HAVE_ERRNO_H
		errno = 0;
#  endif
		buf = (unsigned char *) malloc (wfs_r4_get_block_size (FS));
		if ( buf == NULL )
		{
#  ifdef HAVE_ERRNO_H
			error.errcode.gerror = errno;
#  else
			error.errcode.gerror = 12L;	/* ENOMEM */
#  endif
			if ( dir == rootdir )
			{
				show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
			}
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_MALLOC;
		}

		error.errcode.r4error = reiser4_object_seek
			(dir, (unsigned int)(obj_size & 0xFFFFFFFF));
		if ( error.errcode.r4error != 0 )
		{
			if ( dir == rootdir )
			{
				show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
			}
			free (buf);
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_SEEKERR;
		}

		for ( j = 0; (j < FS.npasses) && (sig_recvd == 0) /*&& (ret_part == WFS_SUCCESS)*/; j++ )
		{
			fill_buffer ( j, buf, wfs_r4_get_block_size (FS), selected, FS );
			if ( sig_recvd != 0 )
			{
				ret_part = WFS_SIGNAL;
	       			break;
			}
			written = reiser4_object_write (dir, buf, to_wipe);
			error.errcode.r4error = reiser4_object_seek
				(dir, (unsigned int)(obj_size & 0xFFFFFFFF));
			if ( (written != to_wipe) || (error.errcode.r4error != 0) )
			{
				ret_part = WFS_BLKWR;
				break;
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			   Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (FS.npasses > 1) && (sig_recvd == 0) )
			{
				error.errcode.gerror = wfs_r4_flush_fs ( FS );
			}
		}
		if ( (FS.zero_pass != 0) && (sig_recvd == 0) )
		{
			/* last pass with zeros: */
#  ifdef HAVE_MEMSET
			memset ( buf, 0, wfs_r4_get_block_size (FS) );
#  else
			for ( j=0; j < wfs_r4_get_block_size (FS); j++ )
			{
				buf[j] = '\0';
			}
#  endif
			if ( sig_recvd == 0 )
			{
				written = reiser4_object_write (dir, buf, to_wipe);
				error.errcode.r4error = reiser4_object_seek
					(dir, (unsigned int)(obj_size & 0xFFFFFFFF));
				if ( (written != to_wipe) || (error.errcode.r4error != 0) )
				{
					ret_part = WFS_BLKWR;
				}
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( (FS.npasses > 1) && (sig_recvd == 0) && (ret_part == WFS_SUCCESS) )
				{
					error.errcode.gerror = wfs_r4_flush_fs ( FS );
				}
			}
		}
		free (buf);
		reiser4_object_truncate (dir, obj_size);
	}
	/* if directory, dive into it: */
	else
	{
		error.errcode.r4error = reiser4_object_readdir (dir, &entry);
		direlems = 0;
		while ( error.errcode.r4error > 0 )
		{
			/* open child, recurse, close child */
			child = reiser4_object_open (tree, dir, &(entry.place));
			if ( child == NULL )
			{
				/* No errors. A dir can have no children */
				break;
			}
			direlems++;
			reiser4_object_close (child);
			/* read next entry: */
			error.errcode.r4error = reiser4_object_readdir (dir, &entry);
		}
		reiser4_object_reset (dir);
		while ( error.errcode.r4error > 0 )
		{
			/* open child, recurse, close child */
			child = reiser4_object_open (tree, dir, &(entry.place));
			if ( child == NULL )
			{
				/* No errors. A dir can have no children */
				break;
			}
			ret_temp = wfs_r4_wipe_part_work (FS, tree, child, error);
			if ( ret_part == WFS_SUCCESS )
			{
				ret_part = ret_temp;
			}
			reiser4_object_close (child);

			/* read next entry: */
			error.errcode.r4error = reiser4_object_readdir (dir, &entry);
			if ( dir == rootdir && direlems > 0 )
			{
				curr_direlem++;
				show_progress (WFS_PROGRESS_PART, (unsigned int) (curr_direlem/direlems),
					&prev_percent);
			}
		}
	}
	if ( dir == rootdir )
	{
		show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
	}
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return ret_part;
}
# endif /* WFS_WANT_PART */
#endif	/* WFS_REISER4_UNSHARED_BLOCKS */

/* ======================================================================== */

#ifdef WFS_WANT_PART
/**
 * Wipes the free space in partially used blocks on the given Reiser4 filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_r4_wipe_part (
# ifdef WFS_ANSIC
	wfs_fsid_t FS
#  ifndef  WFS_REISER4_UNSHARED_BLOCKS
		WFS_ATTR ((unused))
#  endif
	, wfs_error_type_t * const error
#  ifndef  WFS_REISER4_UNSHARED_BLOCKS
		WFS_ATTR ((unused))
#  endif
	 )
# else
	FS, error)
	wfs_fsid_t FS
#  ifndef  WFS_REISER4_UNSHARED_BLOCKS
		WFS_ATTR ((unused))
#  endif
	;
	wfs_error_type_t * const error
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

	if ( FS.r4 == NULL )
	{
		show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		return WFS_BADPARAM;
	}
	if ( FS.r4->tree == NULL )
	{
		show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		return WFS_BADPARAM;
	}

	root = reiser4_object_obtain (FS.r4->tree, NULL, &(FS.r4->tree->key));
	if ( root == NULL )
	{
		show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		return WFS_INOREAD;
	}

	ret_part = wfs_r4_wipe_part_work (FS, FS.r4->tree, root, error);
	reiser4_object_close (root);
# endif	/* WFS_REISER4_UNSHARED_BLOCKS */
	show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
	return ret_part;
}
#endif /* WFS_WANT_PART */

/* ======================================================================== */

#ifdef WFS_WANT_WFS
/**
 * Wipes the free space on the given Reiser4 filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_r4_wipe_fs (
# ifdef WFS_ANSIC
	wfs_fsid_t FS, wfs_error_type_t * const error_ret )
# else
	FS, error_ret )
	wfs_fsid_t FS;
	wfs_error_type_t * const error_ret;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	count_t number_of_blocks;
	blk_t blk_no;
	const count_t one = 1;
	int selected[WFS_NPAT];
	unsigned long int j;
	aal_block_t * block;
	int had_to_open_alloc = 0;
	unsigned int prev_percent = 0;
	count_t curr_sector = 0;
	wfs_error_type_t error = {CURR_REISER4, {0}};

	if ( FS.r4 == NULL )
	{
		show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	if ( FS.r4->device == NULL )
	{
		show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	/*number_of_blocks = aal_device_len (FS.r4->device);*/
	number_of_blocks = reiser4_format_len (FS.r4->device, wfs_r4_get_block_size (FS));
	if ( number_of_blocks == INVAL_BLK )
	{
		show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BLBITMAPREAD;
	}

	if ( FS.r4->alloc == NULL )
	{
		FS.r4->alloc = reiser4_alloc_open (FS.r4, number_of_blocks);
		had_to_open_alloc = 1;
	}
	if ( FS.r4->alloc == NULL )
	{
		show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BLBITMAPREAD;
	}
	for ( blk_no = REISER4_FS_MIN_SIZE (wfs_r4_get_block_size (FS));
		(blk_no < number_of_blocks) && (sig_recvd == 0)
		/*&& (ret_wfs == WFS_SUCCESS)*/; blk_no++ )
	{
		if ( reiser4_alloc_available (FS.r4->alloc, blk_no, one) != 0 )
		{
			/* block is unallocated, wipe it */
			block = aal_block_load (FS.r4->device, wfs_r4_get_block_size (FS), blk_no);
			if ( block == NULL )
			{
				ret_wfs = WFS_BLKITER;
				continue;
			}
			for ( j = 0; (j < FS.npasses) && (sig_recvd == 0)
				/*&& (ret_wfs == WFS_SUCCESS)*/; j++ )
			{
				fill_buffer ( j, (unsigned char *) block->data,
					wfs_r4_get_block_size (FS), selected, FS );
				if ( sig_recvd != 0 )
				{
					ret_wfs = WFS_SIGNAL;
		       			break;
				}
				error.errcode.r4error = aal_block_write (block);
				if ( error.errcode.r4error != 0 )
				{
					ret_wfs = WFS_BLKWR;
					break;
				}
				/* Flush after each writing, if more than 1
				   overwriting needs to be done. Allow I/O bufferring
				   (efficiency), if just one pass is needed. */
				if ( (FS.npasses > 1) && (sig_recvd == 0) )
				{
					error.errcode.gerror = wfs_r4_flush_fs ( FS );
				}
			}
			if ( (FS.zero_pass != 0) && (sig_recvd == 0) )
			{
				/* last pass with zeros: */
# ifdef HAVE_MEMSET
				memset ( (unsigned char *) block->data, 0, wfs_r4_get_block_size (FS) );
# else
				for ( j=0; j < wfs_r4_get_block_size (FS); j++ )
				{
					((unsigned char *) block->data)[j] = '\0';
				}
# endif
				if ( sig_recvd == 0 )
				{
					error.errcode.r4error = aal_block_write (block);
					if ( error.errcode.r4error != 0 )
					{
						ret_wfs = WFS_BLKWR;
						break;
					}
					/* Flush after each writing, if more than 1
					overwriting needs to be done. Allow I/O bufferring
					(efficiency), if just one pass is needed. */
					if ( (FS.npasses > 1) && (sig_recvd == 0) )
					{
						error.errcode.gerror = wfs_r4_flush_fs ( FS );
					}
				}
			}
		}
		curr_sector++;
		show_progress (WFS_PROGRESS_WFS, (unsigned int)((curr_sector * 100)/number_of_blocks),
			&prev_percent);
	}
	show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
	if ( had_to_open_alloc != 0 )
	{
		reiser4_alloc_close (FS.r4->alloc);
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
static errno_t WFS_ATTR ((warn_unused_result)) wfs_r4_wipe_journal WFS_PARAMS ((
	uint64_t start, uint64_t len, void * data));
# endif

static errno_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
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
	int selected[WFS_NPAT];
	unsigned long int j;
	aal_block_t * block;
# if (!defined HAVE_MEMSET)
	unsigned int i;
# endif
	unsigned int prev_percent = 0;
	uint64_t curr_sector = 0;

	if ( bd == NULL )
	{
		show_progress (WFS_PROGRESS_UNRM, 50, &prev_percent);
		return WFS_BADPARAM;
	}
	if ( (bd->error == NULL) || (bd->obj == NULL) || (bd->FS.r4 == NULL) )
	{
		show_progress (WFS_PROGRESS_UNRM, 50, &prev_percent);
		return WFS_BADPARAM;
	}
	if ( bd->FS.r4->device == NULL )
	{
		show_progress (WFS_PROGRESS_UNRM, 50, &prev_percent);
		return WFS_BADPARAM;
	}

	/* wipe the journal. */
	for ( blk_no = start; (blk_no < start+len) && (sig_recvd == 0)
		/*&& (ret_journ == WFS_SUCCESS)*/; blk_no++ )
	{
		block = aal_block_load (bd->FS.r4->device, wfs_r4_get_block_size (bd->FS), blk_no);
		if ( block == NULL )
		{
			continue;
		}
		for ( j = 0; (j < bd->FS.npasses) && (sig_recvd == 0) /*&& (ret_journ == WFS_SUCCESS)*/; j++ )
		{
			fill_buffer ( j, (unsigned char *) block->data,
				wfs_r4_get_block_size (bd->FS), selected, bd->FS );
			if ( sig_recvd != 0 )
			{
				ret_journ = WFS_SIGNAL;
				break;
			}
			bd->error->errcode.r4error = aal_block_write (block);
			if ( bd->error->errcode.r4error != 0 )
			{
				ret_journ = WFS_BLKWR;
				break;
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			   Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (bd->FS.npasses > 1) && (sig_recvd == 0) )
			{
				bd->error->errcode.gerror = wfs_r4_flush_fs ( bd->FS );
			}
		}
		/* zero-out the first 2 blocks */
		if ( (bd->block_number == 0) || (bd->block_number == 1) )
		{
# ifdef HAVE_MEMSET
			memset ( block->data, 0, wfs_r4_get_block_size (bd->FS) );
# else
			for ( i=0; i < wfs_r4_get_block_size (bd->FS); i++ )
			{
				((char *)block->data)[i] = '\0';
			}
# endif
			bd->error->errcode.r4error = aal_block_write (block);
			if ( bd->error->errcode.r4error != 0 )
			{
				ret_journ = WFS_BLKWR;
			}
		}
		else
		{
			if ( (bd->FS.zero_pass != 0) && (sig_recvd == 0) )
			{
				/* last pass with zeros: */
# ifdef HAVE_MEMSET
				memset ((unsigned char *) block->data, 0, wfs_r4_get_block_size (bd->FS));
# else
				for ( j=0; j < wfs_r4_get_block_size (bd->FS); j++ )
				{
					((unsigned char *) block->data)[j] = '\0';
				}
# endif
				if ( sig_recvd == 0 )
				{
					bd->error->errcode.r4error = aal_block_write (block);
					if ( bd->error->errcode.r4error != 0 )
					{
						ret_journ = WFS_BLKWR;
						break;
					}
					/* Flush after each writing, if more than 1 overwriting needs
					 to be done.
					Allow I/O bufferring (efficiency), if just one pass is needed. */
					if ( (bd->FS.npasses > 1) && (sig_recvd == 0) )
					{
						bd->error->errcode.gerror = wfs_r4_flush_fs ( bd->FS );
					}
				}
			}
		}
		/* increase the block number for future iterations and calls */
		bd->block_number++;
		curr_sector++;
		show_progress (WFS_PROGRESS_UNRM, (unsigned int) ((curr_sector*50)/len), &prev_percent);
	}
	show_progress (WFS_PROGRESS_UNRM, 50, &prev_percent);
	return ret_journ;
}


/* ======================================================================== */

# ifndef WFS_ANSIC
static errno_t WFS_ATTR ((warn_unused_result)) wfs_r4_wipe_object WFS_PARAMS ((
	uint64_t start, uint64_t len, void * data));
# endif

static errno_t WFS_ATTR ((warn_unused_result))
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
	int selected[WFS_NPAT];
	unsigned long int j;
	aal_block_t * block;

	if ( bd == NULL )
	{
		return WFS_BADPARAM;
	}
	if ( (bd->error == NULL) || (bd->obj == NULL) || (bd->FS.r4 == NULL) )
	{
		return WFS_BADPARAM;
	}
	if ( bd->FS.r4->device == NULL )
	{
		return WFS_BADPARAM;
	}

	/* wipe the object. */
	for ( blk_no = start; (blk_no < start+len) && (sig_recvd == 0)
		/*&& (ret_obj == WFS_SUCCESS)*/; blk_no++ )
	{
		block = aal_block_load (bd->FS.r4->device, wfs_r4_get_block_size (bd->FS), blk_no);
		if ( block == NULL )
		{
			continue;
		}
		for ( j = 0; (j < bd->FS.npasses) && (sig_recvd == 0) /*&& (ret_obj == WFS_SUCCESS)*/; j++ )
		{
			if ( (bd->block_number + blk_no) * wfs_r4_get_block_size (bd->FS)
				< reiser4_object_size (bd->obj) )
			{
				fill_buffer ( j, (unsigned char *) block->data,
					(size_t)((wfs_r4_get_block_size (bd->FS)
						- (reiser4_object_size (bd->obj)
						% wfs_r4_get_block_size (bd->FS))) & 0xFFFFFFFF),
					selected, bd->FS );
			}
			else
			{
				fill_buffer ( j, (unsigned char *) block->data,
					wfs_r4_get_block_size (bd->FS), selected, bd->FS );
			}
			if ( sig_recvd != 0 )
			{
				ret_obj = WFS_SIGNAL;
				break;
			}
			bd->error->errcode.r4error = aal_block_write (block);
			if ( bd->error->errcode.r4error != 0 )
			{
				ret_obj = WFS_BLKWR;
				break;
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			   Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (bd->FS.npasses > 1) && (sig_recvd == 0) )
			{
				bd->error->errcode.gerror = wfs_r4_flush_fs ( bd->FS );
			}
		}
		if ( (bd->FS.zero_pass != 0) && (sig_recvd == 0) )
		{
			/* last pass with zeros: */
# ifdef HAVE_MEMSET
			memset ( (unsigned char *) block->data, 0, wfs_r4_get_block_size (bd->FS) );
# else
			for ( j=0; j < wfs_r4_get_block_size (bd->FS); j++ )
			{
				((unsigned char *) block->data)[j] = '\0';
			}
# endif
			if ( sig_recvd == 0 )
			{
				bd->error->errcode.r4error = aal_block_write (block);
				if ( bd->error->errcode.r4error != 0 )
				{
					ret_obj = WFS_BLKWR;
					break;
				}
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( (bd->FS.npasses > 1) && (sig_recvd == 0) )
				{
					bd->error->errcode.gerror = wfs_r4_flush_fs ( bd->FS );
				}
			}
		}
		/* increase the block number for future iterations and calls */
		bd->block_number++;
	}
	return ret_obj;
}

/* ======================================================================== */

/**
 * Starts recursive directory search for deleted inodes
 *	and undelete data on the given Reiser4 filesystem.
 * \param FS The filesystem.
 * \param node Filesystem element at which to start.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_r4_wipe_unrm (
# ifdef WFS_ANSIC
	wfs_fsid_t FS, wfs_fselem_t node, wfs_error_type_t * const error_ret )
# else
	FS, node, error_ret )
	wfs_fsid_t FS;
	wfs_fselem_t node;
	wfs_error_type_t * const error_ret;
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
	wfs_fselem_t new_elem;

	unsigned int prev_percent = 50;
	uint64_t curr_direlem = 0;
	wfs_error_type_t error = {CURR_REISER4, {0}};

	if ( FS.r4 == NULL )
	{
		show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	bd.FS = FS;
	bd.error = &error;

	/* wipe the journal */
	if ( FS.r4->journal == NULL )
	{
		FS.r4->journal = reiser4_journal_open (FS.r4, FS.r4->device);
	}
	if ( FS.r4->journal != NULL )
	{
		reiser4_journal_sync (FS.r4->journal);
		bd.block_number = 0;
		error.errcode.r4error = reiser4_journal_layout (FS.r4->journal,
			wfs_r4_wipe_journal, &bd);
		if ( error.errcode.r4error != 0 )
		{
			ret_unrm = WFS_BLKITER;
		}
	}
	/* wipe undelete data - actually, wipe damaged/unused keys. */
	if ( (node.r4node == NULL) && (FS.r4->tree != NULL) )
	{
		reiser4_tree_load_root (FS.r4->tree);
		node.r4node = FS.r4->tree->root;
	}
	if ( (FS.r4->tree == NULL) || (node.r4node == NULL) )
	{
		show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return ret_unrm;
	}
	for ( i = 0; i < reiser4_node_items (node.r4node); i++)
	{
		reiser4_place_assign (&place, node.r4node, i, MAX_UINT32);
		e = reiser4_place_fetch (&place);
		if ( e != 0 )
		{
			/* could not fetch place data - move on to the next item */
			continue;
		}

		/* if not branch node, check correctness and wipe if damaged/unused */
		if ( reiser4_item_branch (place.plug) == 0 )
		{
# ifdef HAVE_MEMCPY
			memcpy ( &key_copy, &(place.key), sizeof (reiser4_key_t) );
# else
			for ( i = 0; i < sizeof (reiser4_key_t); i++ )
			{
				((char*)&key_copy)[i] = ((char*)&(place.key))[i];
			}
# endif
			if ( key_copy.plug->check_struct == NULL )
			{
				continue;
			}
			e = key_copy.plug->check_struct (&key_copy);
			if ( e < 0 )
			{
				continue;
			}
			if ( e != 0 )
			{
				/* damaged key. wipe it. */
				for_search.key = &(place.key);
				for_search.level = LEAF_LEVEL;
				for_search.collision = NULL;
                                search_res = reiser4_tree_lookup (FS.r4->tree, &for_search,
                                	FIND_EXACT, &place);
                                if ( search_res == PRESENT )
                                {
					to_wipe = reiser4_object_open (FS.r4->tree,
						NULL, &place);
					if ( to_wipe == NULL )
					{
						to_wipe = reiser4_object_obtain (FS.r4->tree,
							NULL, &(place.key));
					}
					if ( to_wipe != NULL )
					{
						bd.block_number = 0;
						bd.obj = to_wipe;
						reiser4_object_layout
							(to_wipe, wfs_r4_wipe_object, &bd);
						reiser4_object_close (to_wipe);
					}
				}
				/* change the key type and hash to something meaningless */
				reiser4_key_set_type (&(place.key), KEY_ATTRNAME_TYPE);
				reiser4_key_set_hash (&(place.key), MAX_UINT64);
				reiser4_node_mkdirty (node.r4node);
				reiser4_node_sync (node.r4node);
				aal_block_write (node.r4node->block);
			}
			continue;
		}
		/* if branch node, recurse */
		else
		{
			for ( j=0; j < reiser4_item_units (&place); j++ )
			{
				/* select unit */
				place.pos.unit = j;
				/* get block number */
				blk_no = reiser4_item_down_link (&place);
				/* get child node */
				child = reiser4_tree_lookup_node (FS.r4->tree, blk_no);
				if ( child == NULL )
				{
					continue;
				}
				new_elem.r4node = child;
				ret_temp = wfs_r4_wipe_unrm (FS, new_elem, &error);
				if ( ret_unrm == WFS_SUCCESS )
				{
					ret_unrm = ret_temp;
				}
				/* NOTE: probably better NOT release "child" here */
			}
		}
		curr_direlem++;
		show_progress (WFS_PROGRESS_UNRM, (unsigned int)(50 + (curr_direlem * 50)
			/reiser4_node_items (node.r4node)), &prev_percent);
	}
	show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return ret_unrm;
}
#endif /* WFS_WANT_UNRM */

/* ======================================================================== */

/**
 * Opens a Reiser4 filesystem on the given device.
 * \param dev_name Device name, like /dev/hdXY
 * \param FS Pointer to where the result will be put.
 * \param whichfs Pointer to an int saying which fs is curently in use.
 * \param data Pointer to wfs_fsdata_t structure containing information
 *	which may be needed to open the filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_r4_open_fs (
#ifdef WFS_ANSIC
	const char * const dev_name, wfs_fsid_t * const FS, wfs_curr_fs_t * const whichfs,
	const wfs_fsdata_t * const data WFS_ATTR ((unused)), wfs_error_type_t * const error_ret )
#else
	dev_name, FS, whichfs, data, error_ret )
	const char * const dev_name;
	wfs_fsid_t * const FS;
	wfs_curr_fs_t * const whichfs;
	const wfs_fsdata_t * const data WFS_ATTR ((unused));
	wfs_error_type_t * const error_ret;
#endif
{
	aal_device_t * dev;
	char * dev_name_copy;
	size_t namelen;
	wfs_error_type_t error = {CURR_REISER4, {0}};

	if ((dev_name == NULL) || (FS == NULL) || (whichfs == NULL))
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}

	*whichfs = CURR_NONE;
	FS->r4 = NULL;
	namelen = strlen (dev_name);

	/* malloc a new array for dev_name */
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	dev_name_copy = (char *) malloc (namelen + 1);
	if ( dev_name_copy == NULL )
	{
#ifdef HAVE_ERRNO_H
		error.errcode.gerror = errno;
#else
		error.errcode.gerror = 12L;	/* ENOMEM */
#endif
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	strncpy ( dev_name_copy, dev_name, namelen + 1 );
	dev_name_copy[namelen] = '\0';

	if ( libreiser4_init () != 0 )
	{
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
		free (dev_name_copy);
		libreiser4_fini ();
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_OPENFS;
	}

	FS->r4 = reiser4_fs_open (dev, 1);
	if ( FS->r4 == NULL )
	{
		aal_device_close (dev);
		free (dev_name_copy);
		libreiser4_fini ();
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_OPENFS;
	}

	*whichfs = CURR_REISER4;

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
wfs_errcode_t WFS_ATTR ((warn_unused_result))
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_r4_chk_mount (
#ifdef WFS_ANSIC
	const char * const dev_name, wfs_error_type_t * const error )
#else
	dev_name, error )
	const char * const dev_name;
	wfs_error_type_t * const error;
#endif
{
	return wfs_check_mounted (dev_name, error);
}

/* ======================================================================== */

/**
 * Closes the Reiser4 filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_r4_close_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t FS, wfs_error_type_t * const error WFS_ATTR ((unused)) )
#else
	FS, error )
	wfs_fsid_t FS;
	wfs_error_type_t * const error WFS_ATTR ((unused));
#endif
{
	aal_device_t * dev;

	if ( FS.r4 == NULL )
	{
		return WFS_BADPARAM;
	}
	dev = FS.r4->device;
	reiser4_fs_close (FS.r4);
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
	FS.r4 = NULL;
	return WFS_SUCCESS;
}

/* ======================================================================== */

/**
 * Checks if the Reiser4 filesystem has errors.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_r4_check_err (
#ifdef WFS_ANSIC
	wfs_fsid_t FS )
#else
	FS )
	wfs_fsid_t FS;
#endif
{
	int res = 0;
	if ( FS.r4 == NULL )
	{
		return 1;
	}
	if ( FS.r4->status != NULL )
	{
		if ( (FS.r4->status->ent.ss_status & FS_CORRUPTED) != 0 )
		{
			res++;
		}
		if ( (FS.r4->status->ent.ss_status & FS_DAMAGED) != 0 )
		{
			res++;
		}
		if ( (FS.r4->status->ent.ss_status & FS_DESTROYED) != 0 )
		{
			res++;
		}
	}
	return res;
}

/* ======================================================================== */

/**
 * Checks if the Reiser4 filesystem is dirty (has unsaved changes).
 * \param FS The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_r4_is_dirty (
#ifdef WFS_ANSIC
	wfs_fsid_t FS )
#else
	FS )
	wfs_fsid_t FS;
#endif
{
	int res = 0;
	if ( FS.r4 == NULL )
	{
		return 1;
	}
	if ( FS.r4->status != NULL )
	{
		if ( FS.r4->status->ent.ss_status != 0 )
		{
			res++;
		}
		if ( FS.r4->status->dirty != 0 )
		{
			res++;
		}
	}
	else
	{
		res++;
	}
	if ( FS.r4->master != NULL )
	{
		if ( FS.r4->master->dirty != 0 )
		{
			res++;
		}
	}
	return res;
}

/* ======================================================================== */

/**
 * Flushes the Reiser4 filesystem.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_r4_flush_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t FS )
#else
	FS )
	wfs_fsid_t FS;
#endif
{
	if ( FS.r4 == NULL )
	{
		return WFS_BADPARAM;
	}
	reiser4_fs_sync (FS.r4);
	if ( FS.r4->device != NULL )
	{
		aal_device_sync (FS.r4->device);
	}
#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_SYNC)
	sync ();
#endif
	return WFS_SUCCESS;
}
