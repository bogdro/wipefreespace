/*
 * A program for secure cleaning of free space on filesystems.
 *	-- MinixFS file system-specific functions.
 *
 * Copyright (C) 2009 Bogdan Drozdowski, bogdandr (at) op.pl
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

#include "wfs_minixfs.h"
#include "wfs_signal.h"
#include "wfs_util.h"

int opt_squash = 0;	/* global symbol used by the libminixfs library, has to be present */

static long WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_minixfs_get_free_bit (const u8 * const bmap, const int bitmap_size_in_blocks,
	const long start_position)
{
	long i, j;
	if ( (bmap == NULL) || (bitmap_size_in_blocks == 0) ) return -1L;

	for (i = 0; i < bitmap_size_in_blocks * BLOCK_SIZE; i++)
	{
		if (bmap[i] != 0xff)
		{
			for (j = 0; j < 8; j++)
			{
				if ( ((bmap[i] & (1<<j)) == 0) && ((i<<3) + j >= start_position) )
					return (i<<3) + j;
			}
		}
	}
	return -1L;
}


/* ======================================================================== */

/**
 * Returns the buffer size needed to work on the smallest physical unit on a Minix filesystem.
 * \param FS The filesystem.
 * \return Block size on the filesystem.
 */
static size_t WFS_ATTR ((warn_unused_result))
wfs_minixfs_get_block_size (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	const wfs_fsid_t FS WFS_ATTR ((unused)) )
#else
	FS WFS_ATTR ((unused)) )
	const wfs_fsid_t FS;
#endif
{
	return BLOCK_SIZE;
}

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
static errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_minixfs_wipe_dir (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	wfs_fsid_t FS, error_type * const error, const int dir_ino,
	unsigned int * const prev_percent, unsigned char * buf, const int wipe_part )
#else
	FS, error, dir_ino, prev_percent, buf )
	wfs_fsid_t FS;
	error_type * const error;
	const int dir_ino;
	unsigned int * const prev_percent;
	unsigned char * buf;
#endif
{
	errcode_enum ret_part = WFS_SUCCESS;
	unsigned long int j;
	int selected[NPAT];
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

	if ( (error == NULL) || (FS.minix == NULL) )
	{
		show_progress (PROGRESS_PART, 100, prev_percent);
		return WFS_BADPARAM;
	}
	if ( (dir_ino == -1) || (dir_ino > INODES (FS.minix)) )
	{
		show_progress (PROGRESS_PART, 100, prev_percent);
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
		for (i = 0; i < inode_size; i += BLOCK_SIZE)
		{
			bsz = read_inoblk (FS.minix, dir_ino, i / BLOCK_SIZE, blk);
			if ( bsz < 0 ) continue;
			for (j = 0; j < (unsigned int)bsz; j+= direntsize)
			{
				fino = *((u16 *)(blk+j));
				if (fino == 0) continue;
				if (blk[j+2] == '.' && blk[j+3] == '\0') continue;
				if (blk[j+2] == '.' && blk[j+3] == '.' && blk[j+4] == '\0') continue;
				root_count++;
			}
		}
	}
	if ( S_ISDIR (mode) )
	{
		/* recursive wiping */
		for (i = 0; i < inode_size; i += BLOCK_SIZE)
		{
			bsz = read_inoblk (FS.minix, dir_ino, i / BLOCK_SIZE, blk);
			if ( bsz < 0 ) continue;
			for (j = 0; j < (unsigned int)bsz; j += direntsize)
			{
				fino = *((u16 *)(blk+j));
				if ( wipe_part != 0 )
				{
					if (fino == 0) continue;
					/* wiping partially used blocks */
					if (blk[j+2] == '.' && blk[j+3] == '\0') continue;
					if (blk[j+2] == '.' && blk[j+3] == '.'
						&& blk[j+4] == '\0') continue;
					ret_part = wfs_minixfs_wipe_dir (FS, error,
						fino, prev_percent, buf, wipe_part);
				}
				else
				{
					if (fino != 0) continue;
					/* wiping undelete data (unused entries in the directory) */
					for ( k = 0; (k < npasses) && (sig_recvd == 0); k++ )
					{
						fill_buffer ( k, &blk[j+2], direntsize-2, selected, FS );
						if ( sig_recvd != 0 )
						{
							ret_part = WFS_SIGNAL;
							break;
						}
						error->errcode.gerror = 0;
						write_inoblk (FS.minix, dir_ino,
							i / BLOCK_SIZE, blk); /* void */
						/* Flush after each writing, if more than 1
						   overwriting needs to be done.
						   Allow I/O bufferring (efficiency), if just one
						   pass is needed. */
						if ( (npasses > 1) && (sig_recvd == 0) )
						{
							error->errcode.gerror =
								wfs_minixfs_flush_fs (FS, error);
						}
					}
					if ( (FS.zero_pass != 0) && (sig_recvd == 0) )
					{
						/* last pass with zeros: */
#ifdef HAVE_MEMSET
						memset ( &blk[j+2], 0, direntsize-2);
#else
						for ( k=0; k < direntsize-2; k++ )
						{
							blk[j+2+k] = '\0';
						}
#endif
						if ( sig_recvd == 0 )
						{
							error->errcode.gerror = 0;
							write_inoblk (FS.minix, dir_ino,
								i / BLOCK_SIZE, blk); /* void */
							/* Flush after each writing, if more than
							   1 overwriting needs to be done.
							   Allow I/O bufferring (efficiency), if just
							   one pass is needed. */
							if ( (npasses > 1) && (sig_recvd == 0) )
							{
								error->errcode.gerror =
									wfs_minixfs_flush_fs (FS, error);
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
					show_progress (PROGRESS_PART, (i*100)/root_count, prev_percent);
				}
				else
				{
					show_progress (PROGRESS_UNRM, (i*100)/root_count, prev_percent);
				}
			}
		}
	}
	else if ( wipe_part != 0 )
	{
		/* read file data first */
		was_read = read_inoblk (FS.minix, dir_ino, inode_size / BLOCK_SIZE, buf);
		/* wipe file tail */
		for ( j = 0; (j < npasses) && (sig_recvd == 0); j++ )
		{
			fill_buffer ( j, &buf[was_read],
				(unsigned int)(wfs_minixfs_get_block_size (FS) - was_read),
				selected, FS );
			if ( sig_recvd != 0 )
			{
				ret_part = WFS_SIGNAL;
				break;
			}
			error->errcode.gerror = 0;
			write_inoblk (FS.minix, dir_ino, inode_size / BLOCK_SIZE, buf); /* void */
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (npasses > 1) && (sig_recvd == 0) )
			{
				error->errcode.gerror = wfs_minixfs_flush_fs ( FS, error );
			}
		}
		if ( (FS.zero_pass != 0) && (sig_recvd == 0) )
		{
			/* last pass with zeros: */
#ifdef HAVE_MEMSET
			memset ( &buf[was_read], 0,
				(unsigned int)(wfs_minixfs_get_block_size (FS) - was_read) );
#else
			for ( j=0; j < (unsigned int)(wfs_minixfs_get_block_size (FS) - was_read); j++ )
			{
				buf[was_read+j] = '\0';
			}
#endif
			if ( sig_recvd == 0 )
			{
				error->errcode.gerror = 0;
				write_inoblk (FS.minix, dir_ino, inode_size / BLOCK_SIZE, buf); /* void */
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( (npasses > 1) && (sig_recvd == 0) )
				{
					error->errcode.gerror = wfs_minixfs_flush_fs ( FS, error );
				}
			}
		}
		trunc_inode (FS.minix, dir_ino, inode_size);
	}

	if ( sig_recvd != 0 ) return WFS_SIGNAL;
	return ret_part;
}

/**
 * Wipes the free space in partially used blocks on the given Minix filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_minixfs_wipe_part (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	wfs_fsid_t FS, error_type * const error )
#else
	FS, error )
	wfs_fsid_t FS;
	error_type * const error;
#endif
{
	unsigned int prev_percent = 0;
	unsigned char * buf;
	errcode_enum ret_part;

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	buf = (unsigned char *) malloc ( wfs_minixfs_get_block_size (FS) );
	if ( buf == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		show_progress (PROGRESS_PART, 100, &prev_percent);
		return WFS_MALLOC;
	}

	ret_part = wfs_minixfs_wipe_dir (FS, error, MINIX_ROOT_INO, &prev_percent, buf, 1);
	free (buf);
	show_progress (PROGRESS_PART, 100, &prev_percent);
	return ret_part;
}

/**
 * Wipes the free space on the given Minix filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_minixfs_wipe_fs (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	const wfs_fsid_t FS, error_type * const error )
#else
	FS, error )
	const wfs_fsid_t FS;
	error_type * const error;
#endif
{
	errcode_enum ret_wfs = WFS_SUCCESS;
	long start_pos = 0;
	long current_block = 0;
	ssize_t written;
	unsigned long int j;
	int selected[NPAT];
	unsigned int prev_percent = 0;
	unsigned char * buf;

	if ( (error == NULL) || (FS.minix == NULL) )
	{
		show_progress (PROGRESS_WFS, 100, &prev_percent);
		return WFS_BADPARAM;
	}

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	buf = (unsigned char *) malloc ( wfs_minixfs_get_block_size (FS) );
	if ( buf == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		return WFS_MALLOC;
	}

	do
	{
		current_block = wfs_minixfs_get_free_bit (FS.minix->zone_bmap,
			ZMAPS (FS.minix), start_pos);
		if ( current_block == -1L ) break;
		start_pos = current_block + 1;
		current_block += FIRSTZONE (FS.minix)-1;
		if ( (unsigned long)current_block > BLOCKS (FS.minix) ) break;
		for ( j = 0; (j < npasses) && (sig_recvd == 0); j++ )
		{
			fill_buffer ( j, buf, wfs_minixfs_get_block_size (FS), selected, FS );
			if ( sig_recvd != 0 )
			{
				ret_wfs = WFS_SIGNAL;
				break;
			}
			error->errcode.gerror = 0;
			written = fwrite (buf, 1, wfs_minixfs_get_block_size (FS),
				goto_blk (FS.minix->fp, current_block));
			if ( written != (ssize_t) wfs_minixfs_get_block_size (FS) )
			{
#ifdef HAVE_ERRNO_H
				if ( error != NULL ) error->errcode.gerror = errno;
#endif
				show_error ( *error, err_msg_wrtblk, FS.fsname, FS );
				ret_wfs = WFS_BLKWR;
				break;
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (npasses > 1) && (sig_recvd == 0) )
			{
				error->errcode.gerror = wfs_minixfs_flush_fs ( FS, error );
			}
		}
		if ( (FS.zero_pass != 0) && (sig_recvd == 0) )
		{
			/* last pass with zeros: */
#ifdef HAVE_MEMSET
			memset ( buf, 0, wfs_minixfs_get_block_size (FS) );
#else
			for ( j=0; j < wfs_minixfs_get_block_size (FS); j++ )
			{
				buf[j] = '\0';
			}
#endif
			if ( sig_recvd != 0 )
			{
				ret_wfs = WFS_SIGNAL;
				break;
			}
			error->errcode.gerror = 0;
			written = fwrite (buf, 1, wfs_minixfs_get_block_size (FS),
				goto_blk (FS.minix->fp, current_block));
			if ( written != (ssize_t) wfs_minixfs_get_block_size (FS) )
			{
#ifdef HAVE_ERRNO_H
				if ( error != NULL ) error->errcode.gerror = errno;
#endif
				show_error ( *error, err_msg_wrtblk, FS.fsname, FS );
				ret_wfs = WFS_BLKWR;
				break;
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (npasses > 1) && (sig_recvd == 0) )
			{
				error->errcode.gerror = wfs_minixfs_flush_fs ( FS, error );
			}
		}
		show_progress (PROGRESS_WFS, (current_block * 100)/(BLOCKS (FS.minix)), &prev_percent);
	}
	while ( (current_block != -1L) && (sig_recvd == 0) );

	show_progress (PROGRESS_WFS, 100, &prev_percent);
	free (buf);
	if ( sig_recvd != 0 ) return WFS_SIGNAL;
	return ret_wfs;
}

/**
 * Starts recursive directory search for deleted files and undelete data on the given Minix fs.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_minixfs_wipe_unrm (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	const wfs_fsid_t FS, error_type * const error )
#else
	FS, error )
	const wfs_fsid_t FS;
	error_type * const error;
#endif
{
	errcode_enum ret_unrm = WFS_SUCCESS;
	unsigned int prev_percent = 0;
	unsigned char * buf;

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	buf = (unsigned char *) malloc ( wfs_minixfs_get_block_size (FS) );
	if ( buf == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		show_progress (PROGRESS_UNRM, 100, &prev_percent);
		return WFS_MALLOC;
	}

	ret_unrm = wfs_minixfs_wipe_dir (FS, error, MINIX_ROOT_INO, &prev_percent, buf, 0);
	free (buf);
	show_progress (PROGRESS_UNRM, 100, &prev_percent);
	return ret_unrm;
}

/**
 * Opens a Minix filesystem on the given device.
 * \param devname Device name, like /dev/hdXY
 * \param FS Pointer to where the result will be put.
 * \param whichfs Pointer to an int saying which fs is curently in use.
 * \param data Pointer to fsdata structure containing information which may be needed to
 *	open the filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_minixfs_open_fs (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	const char * const dev_name, wfs_fsid_t * const FS, CURR_FS * const whichfs,
	const fsdata * const data WFS_ATTR ((unused)), error_type * const error WFS_ATTR ((unused)) )
#else
	dev_name, FS, whichfs, data WFS_ATTR ((unused)), error WFS_ATTR ((unused)))
	const char * const dev_name;
	wfs_fsid_t * const FS;
	CURR_FS * const whichfs;
	const fsdata * const data;
	error_type * const error;
#endif
{
	errcode_enum ret = WFS_SUCCESS;
	if ((dev_name == NULL) || (FS == NULL) || (whichfs == NULL))
	{
		return WFS_BADPARAM;
	}

	*whichfs = CURR_NONE;

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
	return ret;
}

/**
 * Checks if the given Minix filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_minixfs_chk_mount (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	const char * const dev_name, error_type * const error )
#else
	dev_name, error )
	const char * const dev_name;
	error_type * const error;
#endif
{
	return wfs_check_mounted (dev_name, error);
}

/**
 * Closes the Minix filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((nonnull))
wfs_minixfs_close_fs (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	wfs_fsid_t FS, error_type * const error WFS_ATTR ((unused)) )
#else
	FS, error WFS_ATTR ((unused)) )
	wfs_fsid_t FS;
	error_type * const error;
#endif
{
	if ( FS.minix == NULL )
	{
		return WFS_BADPARAM;
	}
	close_fs (FS.minix);
	FS.minix = NULL;
	return WFS_SUCCESS;
}

/**
 * Checks if the Minix filesystem has errors.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_minixfs_check_err (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
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


/**
 * Checks if the Minix filesystem is dirty (has unsaved changes).
 * \param FS The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_minixfs_is_dirty (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
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

/**
 * Flushes the Minix filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((nonnull))
wfs_minixfs_flush_fs (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	wfs_fsid_t FS, error_type * const error
# if (!defined HAVE_ERRNO_H)
		WFS_ATTR ((unused))
# endif
	)
#else
	FS , error
# if (!defined HAVE_ERRNO_H)
		WFS_ATTR ((unused))
# endif
	)
	wfs_fsid_t FS;
	error_type * const error;
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
	if ( fflush (FS.minix->fp) != 0 )
	{
#ifdef HAVE_ERRNO_H
		if ( error != NULL ) error->errcode.gerror = errno;
#endif
		return WFS_FLUSHFS;
	}
#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_SYNC)
	sync ();
#endif
	return WFS_SUCCESS;
}
