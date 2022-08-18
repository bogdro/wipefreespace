/*
 * A program for secure cleaning of free space on filesystems.
 *	-- MinixFS file system-specific functions.
 *
 * Copyright (C) 2009-2012 Bogdan Drozdowski, bogdandr (at) op.pl
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
 *
 */

#include "wfs_cfg.h"

/* we're not using these headers, so let's pretend they're already included,
   to avoid warnings caused by them. */
#define REISER4_TREE_H 1
/*#define REISER4_PLUGIN_H 1 - required for reiser4/types.h */

/* redefine the inline sig function from hfsp, each time with a different name */
extern unsigned long int wfs_minix_sig(char c0, char c1, char c2, char c3);
#define sig(a,b,c,d) wfs_minix_sig(a,b,c,d)

#include "wipefreespace.h"

#include <stdio.h>

#if (defined HAVE_MINIX_FS_H) && (defined HAVE_LIBMINIXFS)
/*# include <minix_fs.h> can't include this one twice - no protection */
# include <protos.h>
#else
# error Something wrong. MinixFS requested, but minix_fs.h or libminixfs missing.
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* sync() */
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
# if ((!defined STDC_HEADERS) || (!STDC_HEADERS)) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#include "wfs_minixfs.h"
#include "wfs_signal.h"
#include "wfs_util.h"
#include "wfs_wiping.h"

/* ======================================================================== */

int opt_squash = 0;	/* global symbol used by the libminixfs library, has to be present */

#ifdef WFS_WANT_WFS
# ifndef WFS_ANSIC
static long int WFS_ATTR ((warn_unused_result)) wfs_minixfs_get_free_bit WFS_PARAMS ((
	const u8 * const bmap, const int bitmap_size_in_blocks, const long int start_position));
# endif

static long int WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_minixfs_get_free_bit (
# ifdef WFS_ANSIC
	const u8 * const bmap, const int bitmap_size_in_blocks, const long int start_position)
# else
	bmap, bitmap_size_in_blocks, start_position)
	const u8 * const bmap;
	const int bitmap_size_in_blocks;
	const long int start_position;
# endif
{
	long int i, j;
	if ( (bmap == NULL) || (bitmap_size_in_blocks == 0) )
	{
		return -1L;
	}

	for (i = 0; i < bitmap_size_in_blocks * BLOCK_SIZE && (sig_recvd == 0); i++)
	{
		if (bmap[i] != 0xff)
		{
			for (j = 0; j < 8; j++)
			{
				if ( ((bmap[i] & (1<<j)) == 0) && ((i<<3) + j >= start_position) )
				{
					return (i<<3) + j;
				}
			}
		}
	}
	return -1L;
}
#endif /* WFS_WANT_WFS */

/* ======================================================================== */

#ifndef WFS_ANSIC
static size_t WFS_ATTR ((warn_unused_result)) wfs_minixfs_get_block_size WFS_PARAMS ((
	const wfs_fsid_t FS WFS_ATTR ((unused)) ));
#endif

/**
 * Returns the buffer size needed to work on the smallest physical unit on a Minix filesystem.
 * \param FS The filesystem.
 * \return Block size on the filesystem.
 */
static size_t WFS_ATTR ((warn_unused_result))
wfs_minixfs_get_block_size (
#ifdef WFS_ANSIC
	const wfs_fsid_t FS WFS_ATTR ((unused)) )
#else
	FS )
	const wfs_fsid_t FS WFS_ATTR ((unused));
#endif
{
	return BLOCK_SIZE;
}

/* ======================================================================== */

#if (defined WFS_WANT_UNRM) || (defined WFS_WANT_PART)
# ifndef WFS_ANSIC
static wfs_errcode_t WFS_ATTR ((warn_unused_result)) wfs_minixfs_wipe_dir WFS_PARAMS ((
	wfs_fsid_t FS, wfs_error_type_t * const error_ret, const int dir_ino,
	unsigned int * const prev_percent, unsigned char * buf, const int wipe_part ));
# endif

/**
 * Wipes the free space in partially used blocks in files in the given directory i-node.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \param dir_ino Directory i-node number.
 * \param prev_percent Pointer to previous progress percentage.
 * \param buf The buffer to use.
 * \param wipe_part non-zero means wiping partially used blocks, 0 means wiping undelete data.
 * \return 0 in case of no errors, other values otherwise.
 */
static wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_minixfs_wipe_dir (
# ifdef WFS_ANSIC
	wfs_fsid_t FS, wfs_error_type_t * const error_ret, const int dir_ino,
	unsigned int * const prev_percent, unsigned char * buf, const int wipe_part )
# else
	FS, error_ret, dir_ino, prev_percent, buf, wipe_part )
	wfs_fsid_t FS;
	wfs_error_type_t * const error_ret;
	const int dir_ino;
	unsigned int * const prev_percent;
	unsigned char * buf;
	const int wipe_part;
# endif
{
	wfs_errcode_t ret_part = WFS_SUCCESS;
	unsigned long int j;
	int selected[WFS_NPAT];
	struct minix_inode *ino;
	struct minix2_inode *ino2;
	unsigned int inode_size;
	unsigned int root_count = 0;
	unsigned int mode;
	unsigned int i, k;
	unsigned int direntsize;
	u16 fino;
	int bsz;
	u8 blk[BLOCK_SIZE];
	int was_read;
	wfs_error_type_t error = {CURR_MINIXFS, {0}};

	if ( FS.minix == NULL )
	{
		if ( wipe_part != 0 )
		{
			show_progress (WFS_PROGRESS_PART, 100, prev_percent);
		}
		else
		{
			show_progress (WFS_PROGRESS_UNRM, 100, prev_percent);
		}
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	if ( (dir_ino == -1) || (dir_ino > INODES (FS.minix)) )
	{
		if ( wipe_part != 0 )
		{
			show_progress (WFS_PROGRESS_PART, 100, prev_percent);
		}
		else
		{
			show_progress (WFS_PROGRESS_UNRM, 100, prev_percent);
		}
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	direntsize = DIRSIZE (FS.minix);	/* after the check for FS.minix == NULL */

	if ( VERSION_2 (FS.minix) )
	{
		ino2 = INODE2 (FS.minix, dir_ino);
		inode_size = ino2->i_size;
		mode = ino2->i_mode;
	}
	else
	{
		ino = INODE (FS.minix, dir_ino);
		inode_size = ino->i_size;
		mode = ino->i_mode;
	}
	if ( (dir_ino == MINIX_ROOT_INO) && (S_ISDIR (mode)) )
	{
		/* count elements in the root directory: */
		for (i = 0; i < inode_size && (sig_recvd == 0); i += BLOCK_SIZE)
		{
			bsz = read_inoblk (FS.minix, dir_ino, i / BLOCK_SIZE, blk);
			if ( bsz < 0 )
			{
				continue;
			}
			for (j = 0; j < (unsigned int)bsz && (sig_recvd == 0); j+= direntsize)
			{
				fino = *((u16 *)(blk+j));
				if ( fino == 0 )
				{
					continue;
				}
				if (blk[j+2] == '.' && blk[j+3] == '\0')
				{
					continue;
				}
				if (blk[j+2] == '.' && blk[j+3] == '.' && blk[j+4] == '\0')
				{
					continue;
				}
				root_count++;
			}
		}
	}
	if ( S_ISDIR (mode) )
	{
		/* recursive wiping */
		for (i = 0; i < inode_size && (sig_recvd == 0); i += BLOCK_SIZE)
		{
			bsz = read_inoblk (FS.minix, dir_ino, i / BLOCK_SIZE, blk);
			if ( bsz < 0 )
			{
				continue;
			}
			for (j = 0; j < (unsigned int)bsz && (sig_recvd == 0); j += direntsize)
			{
				fino = *((u16 *)(blk+j));
				if ( wipe_part != 0 )
				{
					if ( fino == 0 )
					{
						continue;
					}
					/* wiping partially used blocks */
					if (blk[j+2] == '.' && blk[j+3] == '\0')
					{
						continue;
					}
					if (blk[j+2] == '.' && blk[j+3] == '.'
						&& blk[j+4] == '\0')
					{
						continue;
					}
					ret_part = wfs_minixfs_wipe_dir (FS, &error,
						fino, prev_percent, buf, wipe_part);
				}
				else
				{
					if ( fino != 0 )
					{
						continue;
					}
					/* wiping undelete data (unused entries in the directory) */
					for ( k = 0; (k < FS.npasses) && (sig_recvd == 0); k++ )
					{
						fill_buffer ( k, &blk[j+2], direntsize-2, selected, FS );
						if ( sig_recvd != 0 )
						{
							ret_part = WFS_SIGNAL;
							break;
						}
						error.errcode.gerror = 0;
						write_inoblk (FS.minix, dir_ino,
							i / BLOCK_SIZE, blk); /* void */
						/* Flush after each writing, if more than 1
						   overwriting needs to be done.
						   Allow I/O bufferring (efficiency), if just one
						   pass is needed. */
						if ( (FS.npasses > 1) && (sig_recvd == 0) )
						{
							error.errcode.gerror =
								wfs_minixfs_flush_fs (FS, &error);
						}
					}
					if ( (FS.zero_pass != 0) && (sig_recvd == 0) )
					{
						/* last pass with zeros: */
# ifdef HAVE_MEMSET
						memset ( &blk[j+2], 0, direntsize-2);
# else
						for ( k=0; k < direntsize-2 && (sig_recvd == 0); k++ )
						{
							blk[j+2+k] = '\0';
						}
# endif
						if ( sig_recvd == 0 )
						{
							error.errcode.gerror = 0;
							write_inoblk (FS.minix, dir_ino,
								i / BLOCK_SIZE, blk); /* void */
							/* Flush after each writing, if more than
							   1 overwriting needs to be done.
							   Allow I/O bufferring (efficiency), if just
							   one pass is needed. */
							if ( (FS.npasses > 1) && (sig_recvd == 0) )
							{
								error.errcode.gerror =
									wfs_minixfs_flush_fs (FS, &error);
							}
						}
					}
				}
			}
			/* update progress, if main directory */
			if ( root_count != 0 )
			{
				if ( wipe_part != 0 )
				{
					show_progress (WFS_PROGRESS_PART, (i*100)/root_count, prev_percent);
				}
				else
				{
					show_progress (WFS_PROGRESS_UNRM, (i*100)/root_count, prev_percent);
				}
			}
		}
	}
	else if ( wipe_part != 0 )
	{
		/* read file data first */
		was_read = read_inoblk (FS.minix, dir_ino, inode_size / BLOCK_SIZE, buf);
		if ( was_read < 0 )
		{
			was_read = 0;
		}
		/* wipe file tail */
		for ( j = 0; (j < FS.npasses) && (sig_recvd == 0); j++ )
		{
			fill_buffer ( j, &buf[was_read],
				(unsigned int)(wfs_minixfs_get_block_size (FS) - (size_t)was_read),
				selected, FS );
			if ( sig_recvd != 0 )
			{
				ret_part = WFS_SIGNAL;
				break;
			}
			write_inoblk (FS.minix, dir_ino, inode_size / BLOCK_SIZE, buf); /* void */
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (FS.npasses > 1) && (sig_recvd == 0) )
			{
				error.errcode.gerror = wfs_minixfs_flush_fs ( FS, &error );
			}
		}
		if ( (FS.zero_pass != 0) && (sig_recvd == 0) )
		{
			/* last pass with zeros: */
# ifdef HAVE_MEMSET
			memset ( &buf[was_read], 0,
				(unsigned int)(wfs_minixfs_get_block_size (FS) - (size_t)was_read) );
# else
			for ( j=0; j < (unsigned int)(wfs_minixfs_get_block_size (FS) - (size_t)was_read); j++ )
			{
				buf[was_read+j] = '\0';
			}
# endif
			if ( sig_recvd == 0 )
			{
				error.errcode.gerror = 0;
				write_inoblk (FS.minix, dir_ino, inode_size / BLOCK_SIZE, buf); /* void */
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( (FS.npasses > 1) && (sig_recvd == 0) )
				{
					error.errcode.gerror = wfs_minixfs_flush_fs ( FS, &error );
				}
			}
		}
		trunc_inode (FS.minix, dir_ino, inode_size);
	}

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
#endif /* (defined WFS_WANT_UNRM) || (defined WFS_WANT_PART) */

/* ======================================================================== */

#ifdef WFS_WANT_PART
/**
 * Wipes the free space in partially used blocks on the given Minix filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_minixfs_wipe_part (
# ifdef WFS_ANSIC
	wfs_fsid_t FS, wfs_error_type_t * const error_ret )
# else
	FS, error_ret )
	wfs_fsid_t FS;
	wfs_error_type_t * const error_ret;
# endif
{
	unsigned int prev_percent = 0;
	unsigned char * buf;
	wfs_errcode_t ret_part;
	wfs_error_type_t error = {CURR_MINIXFS, {0}};

	if ( FS.minix == NULL )
	{
		return WFS_BADPARAM;
	}
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	buf = (unsigned char *) malloc ( wfs_minixfs_get_block_size (FS) );
	if ( buf == NULL )
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

	ret_part = wfs_minixfs_wipe_dir (FS, &error, MINIX_ROOT_INO, &prev_percent, buf, 1);
	free (buf);
	show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
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
 * Wipes the free space on the given Minix filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_minixfs_wipe_fs (
# ifdef WFS_ANSIC
	const wfs_fsid_t FS, wfs_error_type_t * const error_ret )
# else
	FS, error_ret )
	const wfs_fsid_t FS;
	wfs_error_type_t * const error_ret;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	long int start_pos = 0;
	long int current_block = 0;
	size_t written;
	unsigned long int j;
	int selected[WFS_NPAT];
	unsigned int prev_percent = 0;
	unsigned char * buf;
	wfs_error_type_t error = {CURR_MINIXFS, {0}};

	if ( FS.minix == NULL )
	{
		show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	buf = (unsigned char *) malloc ( wfs_minixfs_get_block_size (FS) );
	if ( buf == NULL )
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

	do
	{
		current_block = wfs_minixfs_get_free_bit (FS.minix->zone_bmap,
			ZMAPS (FS.minix), start_pos);
		if ( current_block == -1L )
		{
			break;
		}
		start_pos = current_block + 1;
		current_block += FIRSTZONE (FS.minix)-1;
		if ( (unsigned long int)current_block > BLOCKS (FS.minix) )
		{
			break;
		}
		for ( j = 0; (j < FS.npasses) && (sig_recvd == 0); j++ )
		{
			fill_buffer ( j, buf, wfs_minixfs_get_block_size (FS), selected, FS );
			if ( sig_recvd != 0 )
			{
				ret_wfs = WFS_SIGNAL;
				break;
			}
			error.errcode.gerror = 0;
# ifdef HAVE_ERRNO_H
			errno = 0;
# endif
			written = fwrite (buf, 1, wfs_minixfs_get_block_size (FS),
				goto_blk (FS.minix->fp, current_block));
			if ( written != wfs_minixfs_get_block_size (FS) )
			{
# ifdef HAVE_ERRNO_H
				error.errcode.gerror = errno;
# endif
				ret_wfs = WFS_BLKWR;
				break;
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (FS.npasses > 1) && (sig_recvd == 0) )
			{
				error.errcode.gerror = wfs_minixfs_flush_fs ( FS, &error );
			}
		}
		if ( (FS.zero_pass != 0) && (sig_recvd == 0) )
		{
			/* last pass with zeros: */
# ifdef HAVE_MEMSET
			memset ( buf, 0, wfs_minixfs_get_block_size (FS) );
# else
			for ( j=0; j < wfs_minixfs_get_block_size (FS); j++ )
			{
				buf[j] = '\0';
			}
# endif
			if ( sig_recvd != 0 )
			{
				ret_wfs = WFS_SIGNAL;
				break;
			}
			error.errcode.gerror = 0;
# ifdef HAVE_ERRNO_H
			errno = 0;
# endif
			written = fwrite (buf, 1, wfs_minixfs_get_block_size (FS),
				goto_blk (FS.minix->fp, current_block));
			if ( written != wfs_minixfs_get_block_size (FS) )
			{
# ifdef HAVE_ERRNO_H
				error.errcode.gerror = errno;
# endif
				ret_wfs = WFS_BLKWR;
				break;
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (FS.npasses > 1) && (sig_recvd == 0) )
			{
				error.errcode.gerror = wfs_minixfs_flush_fs ( FS, &error );
			}
		}
		show_progress (WFS_PROGRESS_WFS, ((unsigned long int)current_block * 100)/(BLOCKS (FS.minix)),
			&prev_percent);
	}
	while ( (current_block != -1L) && (sig_recvd == 0) );

	show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
	free (buf);
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
/**
 * Starts recursive directory search for deleted files and undelete data on the given Minix fs.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_minixfs_wipe_unrm (
# ifdef WFS_ANSIC
	const wfs_fsid_t FS, wfs_error_type_t * const error_ret )
# else
	FS, error_ret )
	const wfs_fsid_t FS;
	wfs_error_type_t * const error_ret;
# endif
{
	wfs_errcode_t ret_unrm = WFS_SUCCESS;
	unsigned int prev_percent = 0;
	unsigned char * buf;
	wfs_error_type_t error = {CURR_MINIXFS, {0}};

	if ( FS.minix == NULL )
	{
		return 	WFS_BADPARAM;
	}
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	buf = (unsigned char *) malloc ( wfs_minixfs_get_block_size (FS) );
	if ( buf == NULL )
	{
# ifdef HAVE_ERRNO_H
		error.errcode.gerror = errno;
# else
		error.errcode.gerror = 12L;	/* ENOMEM */
# endif
		show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		return WFS_MALLOC;
	}

	ret_unrm = wfs_minixfs_wipe_dir (FS, &error, MINIX_ROOT_INO, &prev_percent, buf, 0);
	free (buf);
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
 * Opens a Minix filesystem on the given device.
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
wfs_minixfs_open_fs (
#ifdef WFS_ANSIC
	const char * const dev_name, wfs_fsid_t * const FS, wfs_curr_fs_t * const whichfs,
	const wfs_fsdata_t * const data WFS_ATTR ((unused)), wfs_error_type_t * const error_ret )
#else
	dev_name, FS, whichfs, data, error_ret)
	const char * const dev_name;
	wfs_fsid_t * const FS;
	wfs_curr_fs_t * const whichfs;
	const wfs_fsdata_t * const data WFS_ATTR ((unused));
	wfs_error_type_t * const error_ret;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	wfs_error_type_t error = {CURR_MINIXFS, {0}};

	if ((dev_name == NULL) || (FS == NULL) || (whichfs == NULL))
	{
		return WFS_BADPARAM;
	}

	*whichfs = CURR_NONE;

	/* Open the filesystem our way, because open_fs() calls exit() and closes the
	   process, so if this filesystem is not MinixFS, filesystems checked after
	   MinixFS will not have a chance to get tried. */
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	FS->minix = malloc (sizeof (struct minix_fs_dat));
	if ( FS->minix == NULL )
	{
#ifdef HAVE_ERRNO_H
		error.errcode.gerror = errno;
#else
		error.errcode.gerror = 12; /* ENOMEM */
#endif
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_OPENFS;
	}
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	FS->minix->fp = fopen (dev_name, "r+b");
	if ( FS->minix->fp == NULL )
	{
#ifdef HAVE_ERRNO_H
		error.errcode.gerror = errno;
#else
		error.errcode.gerror = 9; /* EBADF */
#endif
		free (FS->minix);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_OPENFS;
	}
	rewind (FS->minix->fp);

	dofread (goto_blk (FS->minix->fp, MINIX_SUPER_BLOCK),
		&(FS->minix->msb), sizeof (struct minix_super_block));

	fclose (FS->minix->fp);	/* will be reopened in open_fs() below. */
	if ( (FSMAGIC (FS->minix) != MINIX_SUPER_MAGIC)
		&& (FSMAGIC (FS->minix) != MINIX_SUPER_MAGIC2)
		&& (FSMAGIC (FS->minix) != MINIX2_SUPER_MAGIC)
		&& (FSMAGIC (FS->minix) != MINIX2_SUPER_MAGIC2) )
	{
		free (FS->minix);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_OPENFS;
	}

	free (FS->minix);
	FS->minix = open_fs ( dev_name, 0 /* don't perform checks - they call exit() */ );
	if ( FS->minix == NULL )
	{
		ret = WFS_OPENFS;
	}
	else
	{
		*whichfs = CURR_MINIXFS;
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
 * Checks if the given Minix filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_minixfs_chk_mount (
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
 * Closes the Minix filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_minixfs_close_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t FS, wfs_error_type_t * const error_ret )
#else
	FS, error_ret )
	wfs_fsid_t FS;
	wfs_error_type_t * const error_ret;
#endif
{
	wfs_error_type_t error = {CURR_MINIXFS, {0}};

	if ( FS.minix == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	close_fs (FS.minix);
	/* close_fs does NOT close the file descriptor, but once it might, so check here */
	if ( FS.minix->fp != NULL )
	{
		if ( fflush (FS.minix->fp) != 0 )
		{
			/* the file descriptor has been close by close_fs */
			FS.minix = NULL;
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_SUCCESS;
		}
		else
		{
#ifdef HAVE_ERRNO_H
			errno = 0;
#endif
			if ( fclose (FS.minix->fp) != 0 )
			{
#ifdef HAVE_ERRNO_H
				error.errcode.gerror = errno;
#else
				error.errcode.gerror = 9; /* EBADF */
#endif
				if ( error_ret != NULL )
				{
					*error_ret = error;
				}
				return WFS_FSCLOSE;
			}
		}
	}

	if ( FS.minix->inode_bmap != NULL )
	{
		free (FS.minix->inode_bmap);
	}
	if ( FS.minix->zone_bmap != NULL )
	{
		free (FS.minix->zone_bmap);
	}
	if ( FS.minix->ino.v1 != NULL )
	{
		free (FS.minix->ino.v1);
	}
	free (FS.minix);

	FS.minix = NULL;
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return WFS_SUCCESS;
}

/* ======================================================================== */

/**
 * Checks if the Minix filesystem has errors.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_minixfs_check_err (
#ifdef WFS_ANSIC
	const wfs_fsid_t FS )
#else
	FS )
	const wfs_fsid_t FS;
#endif
{
	if ( FS.minix == NULL )
	{
		return WFS_BADPARAM;
	}
	if ( FS.minix->msb.s_state != MINIX_VALID_FS )
	{
		return 1;
	}
	return 0;
}


/* ======================================================================== */

/**
 * Checks if the Minix filesystem is dirty (has unsaved changes).
 * \param FS The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_minixfs_is_dirty (
#ifdef WFS_ANSIC
	const wfs_fsid_t FS )
#else
	FS )
	const wfs_fsid_t FS;
#endif
{
	if ( FS.minix == NULL )
	{
		return WFS_BADPARAM;
	}
	if ( FS.minix->msb.s_state != MINIX_VALID_FS )
	{
		return 1;
	}
	return 0;
}

/* ======================================================================== */

/**
 * Flushes the Minix filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_minixfs_flush_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t FS, wfs_error_type_t * const error
# if (!defined HAVE_ERRNO_H)
		WFS_ATTR ((unused))
# endif
	)
#else
	FS , error)
	wfs_fsid_t FS;
	wfs_error_type_t * const error
# if (!defined HAVE_ERRNO_H)
		WFS_ATTR ((unused))
# endif
	;
#endif
{
	if ( FS.minix == NULL )
	{
		return WFS_BADPARAM;
	}
	if ( FS.minix->fp == NULL )
	{
		return WFS_BADPARAM;
	}
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	if ( fflush (FS.minix->fp) != 0 )
	{
#ifdef HAVE_ERRNO_H
		if ( error != NULL )
		{
			error->errcode.gerror = errno;
		}
#endif
		return WFS_FLUSHFS;
	}
#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_SYNC)
	sync ();
#endif
	return WFS_SUCCESS;
}
