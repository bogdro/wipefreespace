/*
 * A program for secure cleaning of free space on filesystems.
 *	-- MinixFS file system-specific functions.
 *
 * Copyright (C) 2009-2022 Bogdan Drozdowski, bogdro (at) users.sourceforge.net
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

#include "wipefreespace.h"

#include <stdio.h>

#if (defined HAVE_MINIX_FS_H) && (defined HAVE_LIBMINIXFS)
# include <minix_fs.h>
# include <protos.h>
#else
# error Something wrong. MinixFS requested, but minix_fs.h or libminixfs missing.
/* make a syntax error, because not all compilers treat #error as an error */
Something wrong. MinixFS requested, but minix_fs.h or libminixfs missing.
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

#ifdef TEST_COMPILE
# undef WFS_ANSIC
#endif

/* ======================================================================== */

int opt_squash = 0;	/* global symbol used by the libminixfs library, has to be present */

#ifdef WFS_WANT_WFS
# ifndef WFS_ANSIC
static long int GCC_WARN_UNUSED_RESULT wfs_minixfs_get_free_bit WFS_PARAMS ((
	const u8 * const bmap, const int bitmap_size_in_blocks, const long int start_position));
# endif

static long int GCC_WARN_UNUSED_RESULT
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

	for (i = 0; i < bitmap_size_in_blocks * BLOCK_SIZE
		&& (sig_recvd == 0); i++)
	{
		if (bmap[i] != 0xff)
		{
			for (j = 0; j < 8; j++)
			{
				if ( ((bmap[i] & (1<<j)) == 0)
					&& ((i<<3) + j >= start_position) )
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
static size_t GCC_WARN_UNUSED_RESULT wfs_minixfs_get_block_size WFS_PARAMS ((
	const wfs_fsid_t wfs_fs WFS_ATTR ((unused)) ));
#endif

/**
 * Returns the buffer size needed to work on the smallest physical unit on a Minix filesystem.
 * \param wfs_fs The filesystem.
 * \return Block size on the filesystem.
 */
static size_t GCC_WARN_UNUSED_RESULT
wfs_minixfs_get_block_size (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs WFS_ATTR ((unused)) )
#else
	wfs_fs )
	const wfs_fsid_t wfs_fs WFS_ATTR ((unused));
#endif
{
	return BLOCK_SIZE;
}

/* ======================================================================== */

#if (defined WFS_WANT_UNRM) || (defined WFS_WANT_PART)
# ifndef WFS_ANSIC
static wfs_errcode_t GCC_WARN_UNUSED_RESULT wfs_minixfs_wipe_dir WFS_PARAMS ((
	wfs_fsid_t wfs_fs, const int dir_ino,
	unsigned int * const prev_percent, unsigned char * buf,
	const int wipe_part ));
# endif

/**
 * Wipes the free space in partially used blocks in files in the given directory i-node.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \param dir_ino Directory i-node number.
 * \param prev_percent Pointer to previous progress percentage.
 * \param buf The buffer to use.
 * \param wipe_part non-zero means wiping partially used blocks, 0 means wiping undelete data.
 * \return 0 in case of no errors, other values otherwise.
 */
static wfs_errcode_t GCC_WARN_UNUSED_RESULT
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_minixfs_wipe_dir (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs, const int dir_ino,
	unsigned int * const prev_percent, unsigned char * buf,
	const int wipe_part )
# else
	wfs_fs, dir_ino, prev_percent, buf, wipe_part )
	wfs_fsid_t wfs_fs;
	const int dir_ino;
	unsigned int * const prev_percent;
	unsigned char * buf;
	const int wipe_part;
# endif
{
	wfs_errcode_t ret_part = WFS_SUCCESS;
	unsigned long int j;
	int selected[WFS_NPAT] = {0};
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
	wfs_errcode_t error = 0;
	struct minix_fs_dat * minix;
	wfs_errcode_t * error_ret;
	size_t fs_block_size;

	minix = (struct minix_fs_dat *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( minix == NULL )
	{
		if ( wipe_part != 0 )
		{
			wfs_show_progress (WFS_PROGRESS_PART, 100, prev_percent);
		}
		else
		{
			wfs_show_progress (WFS_PROGRESS_UNRM, 100, prev_percent);
		}
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	fs_block_size = wfs_minixfs_get_block_size (wfs_fs);

	if ( (dir_ino == -1) || (dir_ino > (int)INODES (minix)) )
	{
		if ( wipe_part != 0 )
		{
			wfs_show_progress (WFS_PROGRESS_PART, 100, prev_percent);
		}
		else
		{
			wfs_show_progress (WFS_PROGRESS_UNRM, 100, prev_percent);
		}
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	direntsize = DIRSIZE (minix);	/* after the check for wfs_fs.minix == NULL */

	if ( VERSION_2 (minix) )
	{
		ino2 = INODE2 (minix, dir_ino);
		inode_size = ino2->i_size;
		mode = ino2->i_mode;
	}
	else
	{
		ino = INODE (minix, dir_ino);
		inode_size = ino->i_size;
		mode = ino->i_mode;
	}
	if ( (dir_ino == MINIX_ROOT_INO) && (S_ISDIR (mode)) )
	{
		/* count elements in the root directory: */
		for (i = 0; i < inode_size && (sig_recvd == 0); i += BLOCK_SIZE)
		{
			bsz = read_inoblk (minix, dir_ino, i / BLOCK_SIZE, blk);
			if ( bsz < 0 )
			{
				continue;
			}
			for (j = 0; (j < (unsigned int)bsz)
				&& (sig_recvd == 0); j+= direntsize)
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
				if (blk[j+2] == '.' && blk[j+3] == '.'
					&& blk[j+4] == '\0')
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
			bsz = read_inoblk (minix, dir_ino, i / BLOCK_SIZE, blk);
			if ( bsz < 0 )
			{
				if ( wipe_part != 0 )
				{
					wfs_show_progress (WFS_PROGRESS_PART, (i*100)/root_count, prev_percent);
				}
				else
				{
					wfs_show_progress (WFS_PROGRESS_UNRM, (i*100)/root_count, prev_percent);
				}
				continue;
			}
			for (j = 0; (j < (unsigned int)bsz)
				&& (sig_recvd == 0); j += direntsize)
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
					ret_part = wfs_minixfs_wipe_dir (wfs_fs,
						fino, prev_percent, buf, wipe_part);
				}
				else
				{
					if ( fino != 0 )
					{
						continue;
					}
					/* wiping undelete data (unused entries in the directory) */
					for ( k = 0; (k < wfs_fs.npasses)
						&& (sig_recvd == 0); k++ )
					{
						fill_buffer ( k, &blk[j+2],
							direntsize-2,
							selected, wfs_fs );
						if ( sig_recvd != 0 )
						{
							ret_part = WFS_SIGNAL;
							break;
						}
						error = 0;
						write_inoblk (minix, dir_ino,
							i / BLOCK_SIZE, blk); /* void */
						/* Flush after each writing, if more than 1
						   overwriting needs to be done.
						   Allow I/O bufferring (efficiency), if just one
						   pass is needed. */
						if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
						{
							error = wfs_minixfs_flush_fs (wfs_fs);
						}
					}
					if ( (wfs_fs.zero_pass != 0)
						&& (sig_recvd == 0) )
					{
						/* last pass with zeros: */
						WFS_MEMSET ( &blk[j+2], 0, direntsize-2);
						if ( sig_recvd == 0 )
						{
							error = 0;
							write_inoblk (minix, dir_ino,
								i / BLOCK_SIZE, blk); /* void */
							/* No need to flush the last writing of a given block. *
							if ( (wfs_fs.npasses > 1)
								&& (sig_recvd == 0) )
							{
								error = wfs_minixfs_flush_fs (wfs_fs);
							}*/
						}
					}
				}
			}
			/* update progress, if main directory */
			if ( root_count != 0 )
			{
				if ( wipe_part != 0 )
				{
					wfs_show_progress (WFS_PROGRESS_PART, (i*100)/root_count, prev_percent);
				}
				else
				{
					wfs_show_progress (WFS_PROGRESS_UNRM, (i*100)/root_count, prev_percent);
				}
			}
		}
	}
	else if ( wipe_part != 0 )
	{
		/* read file data first */
		was_read = read_inoblk (minix, dir_ino,
			inode_size / BLOCK_SIZE, buf);
		if ( was_read < 0 )
		{
			was_read = 0;
		}
		/* wipe file tail */
		for ( j = 0; (j < wfs_fs.npasses) && (sig_recvd == 0); j++ )
		{
			if ( wfs_fs.no_wipe_zero_blocks != 0 )
			{
				if ( wfs_is_block_zero (buf, fs_block_size) != 0 )
				{
					/* this block is all-zeros - don't wipe, as requested */
					j = wfs_fs.npasses * 2;
					break;
				}
			}
			fill_buffer ( j, &buf[was_read],
				(unsigned int)(fs_block_size - (size_t)was_read),
				selected, wfs_fs );
			if ( sig_recvd != 0 )
			{
				ret_part = WFS_SIGNAL;
				break;
			}
			write_inoblk (minix, dir_ino, inode_size / BLOCK_SIZE, buf); /* void */
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
			{
				error = wfs_minixfs_flush_fs (wfs_fs);
			}
		}
		if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
		{
			/* last pass with zeros: */
			if ( j != wfs_fs.npasses * 2 )
			{
				WFS_MEMSET ( &buf[was_read], 0,
					(unsigned int)(fs_block_size
					- (size_t)was_read) );
				if ( sig_recvd == 0 )
				{
					error = 0;
					write_inoblk (minix, dir_ino, inode_size / BLOCK_SIZE, buf); /* void */
					/* No need to flush the last writing of a given block. *
					if ( (wfs_fs.npasses > 1)
						&& (sig_recvd == 0) )
					{
						error = wfs_minixfs_flush_fs (wfs_fs);
					}*/
				}
			}
		}
		trunc_inode (minix, dir_ino, inode_size);
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
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_minixfs_wipe_part (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
# endif
{
	unsigned int prev_percent = 0;
	unsigned char * buf;
	wfs_errcode_t ret_part;
	wfs_errcode_t error = 0;
	struct minix_fs_dat * minix;
	wfs_errcode_t * error_ret;
	size_t fs_block_size;

	minix = (struct minix_fs_dat *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( minix == NULL )
	{
		return WFS_BADPARAM;
	}
	fs_block_size = wfs_minixfs_get_block_size (wfs_fs);

	WFS_SET_ERRNO (0);
	buf = (unsigned char *) malloc ( fs_block_size );
	if ( buf == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	ret_part = wfs_minixfs_wipe_dir (wfs_fs, MINIX_ROOT_INO,
		&prev_percent, buf, 1);
	free (buf);
	wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
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
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_minixfs_wipe_fs (
# ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	long int start_pos = 0;
	long int current_block = 0;
	size_t written;
	size_t was_read;
	unsigned long int j;
	int selected[WFS_NPAT] = {0};
	unsigned int prev_percent = 0;
	unsigned char * buf;
	wfs_errcode_t error = 0;
	struct minix_fs_dat * minix;
	wfs_errcode_t * error_ret;
	size_t fs_block_size;

	minix = (struct minix_fs_dat *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( minix == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	fs_block_size = wfs_minixfs_get_block_size (wfs_fs);

	WFS_SET_ERRNO (0);
	buf = (unsigned char *) malloc ( fs_block_size );
	if ( buf == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	do
	{
		current_block = wfs_minixfs_get_free_bit (minix->zone_bmap,
			ZMAPS (minix), start_pos);
		if ( current_block == -1L )
		{
			break;
		}
		start_pos = current_block + 1;
		current_block += FIRSTZONE (minix)-1;
		if ( (unsigned long int)current_block > BLOCKS (minix) )
		{
			break;
		}
		for ( j = 0; (j < wfs_fs.npasses) && (sig_recvd == 0); j++ )
		{
			if ( wfs_fs.no_wipe_zero_blocks != 0 )
			{
				was_read = fread (buf, 1,
					fs_block_size,
					goto_blk (minix->fp, (int)(current_block & 0x0FFFFFFFF)));
				if ( (was_read == fs_block_size)
					&& (wfs_is_block_zero (buf,
					fs_block_size) != 0) )
				{
					/* this block is all-zeros - don't wipe, as requested */
					j = wfs_fs.npasses * 2;
					break;
				}
			}
			fill_buffer ( j, buf, fs_block_size, selected, wfs_fs );
			if ( sig_recvd != 0 )
			{
				ret_wfs = WFS_SIGNAL;
				break;
			}
			error = 0;
			WFS_SET_ERRNO (0);
			written = fwrite (buf, 1, fs_block_size,
				goto_blk (minix->fp, (int)(current_block & 0x0FFFFFFFF)));
			if ( written != fs_block_size )
			{
# ifdef HAVE_ERRNO_H
				error = errno;
# endif
				ret_wfs = WFS_BLKWR;
				break;
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
			{
				error = wfs_minixfs_flush_fs (wfs_fs);
			}
		}
		if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
		{
			/* last pass with zeros: */
			if ( j != wfs_fs.npasses * 2 )
			{
				WFS_MEMSET ( buf, 0, fs_block_size );
				if ( sig_recvd != 0 )
				{
					ret_wfs = WFS_SIGNAL;
					break;
				}
				error = 0;
				WFS_SET_ERRNO (0);
				written = fwrite (buf, 1, fs_block_size,
					goto_blk (minix->fp, (int)(current_block & 0x0FFFFFFFF)));
				if ( written != fs_block_size )
				{
# ifdef HAVE_ERRNO_H
					error = errno;
# endif
					ret_wfs = WFS_BLKWR;
					break;
				}
				/* No need to flush the last writing of a given block. *
				if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
				{
					error = wfs_minixfs_flush_fs (wfs_fs);
				}*/
			}
		}
		wfs_show_progress (WFS_PROGRESS_WFS,
			(unsigned int)((current_block * 100)/(BLOCKS (minix))),
			&prev_percent);
	}
	while ( (current_block != -1L) && (sig_recvd == 0) );

	wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
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
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_minixfs_wipe_unrm (
# ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_unrm = WFS_SUCCESS;
	unsigned int prev_percent = 0;
	unsigned char * buf;
	wfs_errcode_t error = 0;
	struct minix_fs_dat * minix;
	wfs_errcode_t * error_ret;
	size_t fs_block_size;

	minix = (struct minix_fs_dat *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( minix == NULL )
	{
		return WFS_BADPARAM;
	}
	fs_block_size = wfs_minixfs_get_block_size (wfs_fs);

	WFS_SET_ERRNO (0);
	buf = (unsigned char *) malloc ( fs_block_size );
	if ( buf == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		return WFS_MALLOC;
	}

	ret_unrm = wfs_minixfs_wipe_dir (wfs_fs, MINIX_ROOT_INO,
		&prev_percent, buf, 0);
	free (buf);
	wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
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
wfs_minixfs_open_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t * const wfs_fs,
	const wfs_fsdata_t * const data WFS_ATTR ((unused)))
#else
	wfs_fs, data)
	wfs_fsid_t * const wfs_fs;
	const wfs_fsdata_t * const data WFS_ATTR ((unused));
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	struct minix_fs_dat * minix;
	wfs_errcode_t * error_ret;

	if ( wfs_fs == NULL )
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

	/* fseek fails badly when given a loop device that is not
	   backed by anything. Check this here: */
	if ( wfs_check_loop_mounted (wfs_fs->fsname) == 0 )
	{
		if ( error_ret != NULL )
		{
			*error_ret = WFS_OPENFS;
		}
		return WFS_OPENFS;
	}

	/* Open the filesystem our way, because open_fs() calls exit() and closes the
	   process, so if this filesystem is not MinixFS, filesystems checked after
	   MinixFS will not have a chance to get tried. */
	WFS_SET_ERRNO (0);
	minix = (struct minix_fs_dat *) malloc (sizeof (struct minix_fs_dat));
	if ( minix == NULL )
	{
		ret = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		if ( error_ret != NULL )
		{
			*error_ret = ret;
		}
		return WFS_OPENFS;
	}
	WFS_SET_ERRNO (0);
	minix->fp = fopen (wfs_fs->fsname, "r+b");
	if ( minix->fp == NULL )
	{
		ret = WFS_GET_ERRNO_OR_DEFAULT (9); /* EBADF */
		free (minix);
		if ( error_ret != NULL )
		{
			*error_ret = ret;
		}
		return WFS_OPENFS;
	}
	rewind (minix->fp);

	dofread (goto_blk (minix->fp, MINIX_SUPER_BLOCK),
		&(minix->msb), sizeof (struct minix_super_block));

	fclose (minix->fp);	/* will be reopened in open_fs() below. */
	if ( (FSMAGIC (minix) != MINIX_SUPER_MAGIC)
		&& (FSMAGIC (minix) != MINIX_SUPER_MAGIC2)
		&& (FSMAGIC (minix) != MINIX2_SUPER_MAGIC)
		&& (FSMAGIC (minix) != MINIX2_SUPER_MAGIC2) )
	{
		ret = WFS_OPENFS;
		free (minix);
		if ( error_ret != NULL )
		{
			*error_ret = ret;
		}
		return WFS_OPENFS;
	}

	free (minix);
	minix = open_fs ( wfs_fs->fsname, 0 /* don't perform checks - they call exit() */ );
	if ( minix == NULL )
	{
		ret = WFS_OPENFS;
	}
	else
	{
		wfs_fs->whichfs = WFS_CURR_FS_MINIXFS;
		ret = WFS_SUCCESS;
		wfs_fs->fs_backend = minix;
	}
	if ( error_ret != NULL )
	{
		*error_ret = ret;
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
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_minixfs_chk_mount (
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
 * Closes the Minix filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_minixfs_close_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs;
#endif
{
	wfs_errcode_t error = 0;
	struct minix_fs_dat * minix;
	wfs_errcode_t * error_ret;

	minix = (struct minix_fs_dat *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( minix == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	close_fs (minix);
	/* close_fs does NOT close the file descriptor, but once it might, so check here */
	if ( minix->fp != NULL )
	{
		if ( fflush (minix->fp) != 0 )
		{
			/* the file descriptor has been close by close_fs */
			minix = NULL;
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_SUCCESS;
		}
		else
		{
			WFS_SET_ERRNO (0);
			if ( fclose (minix->fp) != 0 )
			{
				error = WFS_GET_ERRNO_OR_DEFAULT (9); /* EBADF */
				if ( error_ret != NULL )
				{
					*error_ret = error;
				}
				return WFS_FSCLOSE;
			}
		}
	}

	if ( minix->inode_bmap != NULL )
	{
		free (minix->inode_bmap);
	}
	if ( minix->zone_bmap != NULL )
	{
		free (minix->zone_bmap);
	}
	if ( minix->ino.v1 != NULL )
	{
		free (minix->ino.v1);
	}
	free (minix);

	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return WFS_SUCCESS;
}

/* ======================================================================== */

/**
 * Checks if the Minix filesystem has errors.
 * \param wfs_fs The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_minixfs_check_err (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs )
#else
	wfs_fs )
	const wfs_fsid_t wfs_fs;
#endif
{
	struct minix_fs_dat * minix;

	minix = (struct minix_fs_dat *) wfs_fs.fs_backend;
	if ( minix == NULL )
	{
		return WFS_BADPARAM;
	}
	if ( minix->msb.s_state != MINIX_VALID_FS )
	{
		return 1;
	}
	return 0;
}


/* ======================================================================== */

/**
 * Checks if the Minix filesystem is dirty (has unsaved changes).
 * \param wfs_fs The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_minixfs_is_dirty (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs )
#else
	wfs_fs )
	const wfs_fsid_t wfs_fs;
#endif
{
	struct minix_fs_dat * minix;

	minix = (struct minix_fs_dat *) wfs_fs.fs_backend;
	if ( minix == NULL )
	{
		return WFS_BADPARAM;
	}
	if ( minix->msb.s_state != MINIX_VALID_FS )
	{
		return 1;
	}
	return 0;
}

/* ======================================================================== */

/**
 * Flushes the Minix filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_minixfs_flush_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs;
#endif
{
	struct minix_fs_dat * minix;
	wfs_errcode_t * error_ret;

	minix = (struct minix_fs_dat *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( minix == NULL )
	{
		return WFS_BADPARAM;
	}
	if ( minix->fp == NULL )
	{
		return WFS_BADPARAM;
	}
	WFS_SET_ERRNO (0);
	if ( fflush (minix->fp) != 0 )
	{
#ifdef HAVE_ERRNO_H
		if ( error_ret != NULL )
		{
			*error_ret = (wfs_errcode_t)errno;
		}
#endif
		return WFS_FLUSHFS;
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
void wfs_minixfs_print_version (WFS_VOID)
{
	printf ( "MinixFS: <?>\n");
}

/* ======================================================================== */

/**
 * Get the preferred size of the error variable.
 * \return the preferred size of the error variable.
 */
size_t wfs_minixfs_get_err_size (WFS_VOID)
{
	return sizeof (wfs_errcode_t);
}

/* ======================================================================== */

/**
 * Initialize the library.
 */
void wfs_minixfs_init (WFS_VOID)
{
}

/* ======================================================================== */

/**
 * De-initialize the library.
 */
void wfs_minixfs_deinit (WFS_VOID)
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
wfs_minixfs_show_error (
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
