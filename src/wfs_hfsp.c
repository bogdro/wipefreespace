/*
 * A program for secure cleaning of free space on filesystems.
 *	-- HFS+ file system-specific functions.
 *
 * Copyright (C) 2011-2021 Bogdan Drozdowski, bogdro (at) users.sourceforge.net
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

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* sync() */
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

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

/* add the missing prototype */
extern unsigned long int wfs_hfsp_sig(char c0, char c1, char c2, char c3);
/* redefine the inline sig function from hfsp, each time with a different name */
#define sig(a,b,c,d) wfs_hfsp_sig(a,b,c,d)

#include "wipefreespace.h"

#if (defined HAVE_HFSPLUS_LIBHFSP_H) && (defined HAVE_LIBHFSP)
# include <hfsplus/libhfsp.h>
# include <hfsplus/record.h>
# include <hfsplus/volume.h>
# include <hfsplus/blockiter.h>
#else
# if (defined HAVE_LIBHFSP_H) && (defined HAVE_LIBHFSP)
# include <libhfsp.h>
# include <record.h>
# include <volume.h>
# include <blockiter.h>
# else
#  error Something wrong. HFS+ requested, but libhfsp.h or libhfsp missing.
# endif
#endif

#ifndef STDIN_FILENO
# define STDIN_FILENO	0
#endif

extern int volume_writetobuf WFS_PARAMS ((volume * vol, void * buf, long int block));

#include "wfs_hfsp.h"
#include "wfs_signal.h"
#include "wfs_util.h"
#include "wfs_wiping.h"

#ifdef TEST_COMPILE
# undef WFS_ANSIC
#endif

/* ============================================================= */

#if (defined WFS_WANT_WFS) || (defined WFS_WANT_PART)
# ifndef WFS_ANSIC
static size_t GCC_WARN_UNUSED_RESULT wfs_hfsp_get_block_size WFS_PARAMS ((const wfs_fsid_t wfs_fs));
# endif

/**
 * Returns the buffer size needed to work on the
 *	smallest physical unit on a HFS+ filesystem.
 * \param wfs_fs The filesystem.
 * \return Block size on the filesystem.
 */
static size_t GCC_WARN_UNUSED_RESULT
wfs_hfsp_get_block_size (
# ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs )
# else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
# endif
{
	struct volume * hfsp_volume;

	hfsp_volume = (struct volume *) wfs_fs.fs_backend;
	if ( hfsp_volume == NULL )
	{
		return 0;
	}
	return hfsp_volume->vol.blocksize;
}
#endif /* (defined WFS_WANT_WFS) || (defined WFS_WANT_PART) */

/* ======================================================================== */

#ifdef WFS_WANT_PART
# ifndef WFS_ANSIC
static wfs_errcode_t GCC_WARN_UNUSED_RESULT
	wfs_hfsp_wipe_part_file WFS_PARAMS ((
		wfs_fsid_t wfs_fs, record * const file, unsigned char buf[],
		UInt32 * const curr_file, unsigned int * const prev_percent));
# endif

/**
 * Wipes the free space in partially used blocks in the given file.
 * \param wfs_fs The filesystem.
 * \param file The file to check.
 * \param buf The current buffer.
 * \param error Pointer to error variable.
 * \param curr_file_no Pointer to the number of files already checked.
 * \param prev_percent Pointer to previous progress.
 * \return 0 in case of no errors, other values otherwise.
 */
static wfs_errcode_t GCC_WARN_UNUSED_RESULT
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_hfsp_wipe_part_file (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs, record * const file, unsigned char buf[],
	UInt32 * const curr_file_no, unsigned int * const prev_percent)
# else
	wfs_fs, file, buf, curr_file_no, prev_percent)
	wfs_fsid_t wfs_fs;
	record * const file;
	unsigned char buf[];
	UInt32 * const curr_file_no;
	unsigned int * const prev_percent;
# endif
{
	wfs_errcode_t ret_part = WFS_SUCCESS;
	unsigned long int j;
	int selected[WFS_NPAT] = {0};
	blockiter iter;
	UInt32 last_block;
	int res;
	UInt64 remainder;
	wfs_errcode_t error = 0;
	struct volume * hfsp_volume;
	wfs_errcode_t * error_ret;
	size_t fs_block_size;

	hfsp_volume = (struct volume *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( (buf == NULL) || (file == NULL) || (hfsp_volume == NULL) )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	if ( file->record.type != HFSP_FILE )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_DIRITER;
	}
	fs_block_size = wfs_hfsp_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	remainder = file->record.u.file.data_fork.total_size % fs_block_size;
	if ( remainder == 0 )
	{
		if ( sig_recvd != 0 )
		{
			ret_part = WFS_SIGNAL;
		}
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return ret_part;
	}

	blockiter_init (&iter, hfsp_volume, &(file->record.u.file.data_fork),
		(UInt8)HFSP_EXTENT_DATA, file->record.u.file.id);
	/* skip the full blocks */
	if ( blockiter_skip (&iter,
		file->record.u.file.data_fork.total_blocks / fs_block_size) != 0 )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BLKITER;
	}
	/* read the last block here: */
	last_block = blockiter_curr (&iter);
	res = volume_readinbuf (hfsp_volume, buf, (long int)last_block);
	if ( res != 0 )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BLKRD;
	}
	/* wipe the fail tail here: */
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
		fill_buffer ( j, &buf[remainder], (size_t)(fs_block_size - remainder),
			selected, wfs_fs );
		error = volume_writetobuf (hfsp_volume,
			buf, (long int)last_block);
		if ( error != 0 )
		{
			ret_part = WFS_BLKWR;
			break;
		}
		/* Flush after each writing, if more than 1 overwriting needs to be done.
		Allow I/O bufferring (efficiency), if just one pass is needed. */
		if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
		{
			error = wfs_hfsp_flush_fs (wfs_fs);
		}
	}
	if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0)
		&& (ret_part == WFS_SUCCESS) )
	{
		/* perform last wipe with zeros */
		if ( j != wfs_fs.npasses * 2 )
		{
# ifdef HAVE_MEMSET
			memset ( &buf[remainder], 0,
				(size_t)(fs_block_size - remainder) );
# else
			for ( j=remainder; j < fs_block_size; j++ )
			{
				buf[j] = '\0';
			}
# endif
			error = volume_writetobuf (hfsp_volume,
				buf, (long int)last_block);
			if ( error != 0 )
			{
				ret_part = WFS_BLKWR;
				/* do NOT break here */
			}
			/* No need to flush the last writing of a given block. *
			if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
			{
				error = wfs_hfsp_flush_fs (wfs_fs);
			}*/
		}
	}

	if ( curr_file_no != NULL )
	{
		(*curr_file_no) ++;
		if ( (prev_percent != NULL) && (hfsp_volume->vol.file_count != 0) )
		{
			wfs_show_progress (WFS_PROGRESS_PART,
				(unsigned int)((*curr_file_no)/(hfsp_volume->vol.file_count)), prev_percent);
		}
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

/* ======================================================================== */

# ifndef WFS_ANSIC
static wfs_errcode_t GCC_WARN_UNUSED_RESULT
	wfs_hfsp_wipe_part_dir WFS_PARAMS ((
		wfs_fsid_t wfs_fs, record * const dir, unsigned char buf[],
		UInt32 * const curr_file_no, unsigned int * const prev_percent));
# endif

/**
 * Wipes the free space in partially used blocks in files in the given directory.
 * \param wfs_fs The filesystem.
 * \param dir The current directory.
 * \param buf The current buffer.
 * \param error Pointer to error variable.
 * \param curr_file_no Pointer to the number of files already checked.
 * \param prev_percent Pointer to previous progress.
 * \return 0 in case of no errors, other values otherwise.
 */
static wfs_errcode_t GCC_WARN_UNUSED_RESULT
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_hfsp_wipe_part_dir (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs, record * const dir, unsigned char buf[],
	UInt32 * const curr_file_no, unsigned int * const prev_percent)
# else
	wfs_fs, dir, buf, curr_file_no, prev_percent)
	wfs_fsid_t wfs_fs;
	record * const dir;
	unsigned char buf[];
	UInt32 * const curr_file_no;
	unsigned int * const prev_percent;
# endif
{
	wfs_errcode_t ret_part = WFS_SUCCESS;
	wfs_errcode_t ret_temp = WFS_SUCCESS;
	record curr_elem;
	wfs_errcode_t error = 0;
	struct volume * hfsp_volume;
	wfs_errcode_t * error_ret;

	hfsp_volume = (struct volume *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( (buf == NULL) || (dir == NULL) || (hfsp_volume == NULL) )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	/* the root directory can be marked as HFSP_FOLDER_THREAD (the current directory marker */
	if ( (dir->record.type != HFSP_FOLDER) && (dir->record.type != HFSP_FOLDER_THREAD) )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_DIRITER;
	}

	/* initialize the record to the first element: */
	if ( record_init_parent (&curr_elem, dir) != 0 )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_DIRITER;
	}

	/* iterate over the files and subdirectories here: */
	do
	{
		if ( curr_elem.record.type == HFSP_FOLDER_THREAD )
		{
			/* ignore the current directory marker (we're already doing this directory) */
			continue;
		}
		else if ( curr_elem.record.type == HFSP_FOLDER )
		{
			if ( ret_part == WFS_SUCCESS )
			{
				ret_part = wfs_hfsp_wipe_part_dir (wfs_fs,
					&curr_elem, buf,
					curr_file_no, prev_percent);
			}
			else
			{
				/* keep the current error */
				ret_temp = wfs_hfsp_wipe_part_dir (wfs_fs,
					&curr_elem, buf,
					curr_file_no, prev_percent);
			}
		}
		else if ( curr_elem.record.type == HFSP_FILE )
		{
			if ( ret_part == WFS_SUCCESS )
			{
				ret_part = wfs_hfsp_wipe_part_file (wfs_fs,
					&curr_elem, buf,
					curr_file_no, prev_percent);
			}
			else
			{
				/* keep the current error */
				ret_temp = wfs_hfsp_wipe_part_file (wfs_fs,
					&curr_elem, buf,
					curr_file_no, prev_percent);
			}
		}

	} while ( record_next (&curr_elem) == 0 );

	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	if ( sig_recvd != 0 )
	{
		return WFS_SIGNAL;
	}
	if ( ret_part == WFS_SUCCESS )
	{
		return ret_temp;
	}
	return ret_part;
}

/* ======================================================================== */

/**
 * Wipes the free space in partially used blocks on the given HFS+ filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_hfsp_wipe_part (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_part = WFS_SUCCESS;
	unsigned int prev_percent = 0;
	unsigned char * buf;
	UInt32 curr_file_no = 0;
	record dir;
	int res;
	wfs_errcode_t error = 0;
	struct volume * hfsp_volume;
	wfs_errcode_t * error_ret;
	size_t fs_block_size;

	hfsp_volume = (struct volume *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( hfsp_volume == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	fs_block_size = wfs_hfsp_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	/* get the root directory: */
	res = record_init_cnid (&dir, &(hfsp_volume->catalog), HFSP_ROOT_CNID);
	if ( res != 0 )
	{
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		ret_part = WFS_DIRITER;
		if ( sig_recvd != 0 )
		{
			ret_part = WFS_SIGNAL;
		}
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return ret_part;
	}

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	buf = (unsigned char *) malloc ( fs_block_size );
	if ( buf == NULL )
	{
# ifdef HAVE_ERRNO_H
		error = errno;
# else
		error = 12L;	/* ENOMEM */
# endif
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		return WFS_MALLOC;
	}

	ret_part = wfs_hfsp_wipe_part_dir (wfs_fs, &dir, buf,
		&curr_file_no, &prev_percent);

	free (buf);
	wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
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
 * Wipes the free space on the given HFS+ filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_hfsp_wipe_fs (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	unsigned int prev_percent = 0;
	UInt32 curr_block;
	unsigned long int j;
	int selected[WFS_NPAT] = {0};
	unsigned char * buf;
	wfs_errcode_t error = 0;
	struct volume * hfsp_volume;
	wfs_errcode_t * error_ret;
	int res;
	size_t fs_block_size;

	hfsp_volume = (struct volume *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( hfsp_volume == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	fs_block_size = wfs_hfsp_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	buf = (unsigned char *) malloc ( fs_block_size );
	if ( buf == NULL )
	{
# ifdef HAVE_ERRNO_H
		error = errno;
# else
		error = 12L;	/* ENOMEM */
# endif
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	for ( curr_block = 0;
		(curr_block < hfsp_volume->vol.total_blocks)
		&& (sig_recvd == 0);
		curr_block++ )
	{
		if ( volume_allocated (hfsp_volume, curr_block) == 0 )
		{
			/* block is not allocated - wipe it */
			for ( j = 0; (j < wfs_fs.npasses) && (sig_recvd == 0); j++ )
			{
				if ( wfs_fs.no_wipe_zero_blocks != 0 )
				{
					res = volume_readinbuf (hfsp_volume, buf,
						(long int)curr_block);
					if ( res != 0 )
					{
						if ( error_ret != NULL )
						{
							*error_ret = error;
						}
						return WFS_BLKRD;
					}
					if ( wfs_is_block_zero (buf,
						fs_block_size) != 0 )
					{
						/* this block is all-zeros - don't wipe, as requested */
						j = wfs_fs.npasses * 2;
						break;
					}
				}
				fill_buffer ( j, buf, fs_block_size, selected, wfs_fs );
				error = volume_writetobuf (hfsp_volume,
					buf, (long int)curr_block);
				if ( error != 0 )
				{
					ret_wfs = WFS_BLKWR;
					break;
				}
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
				{
					error = wfs_hfsp_flush_fs (wfs_fs);
				}
			}
			if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0)
				&& (ret_wfs == WFS_SUCCESS) )
			{
				/* this block is NOT all-zeros - wipe */
				if ( j != wfs_fs.npasses * 2 )
				{
					/* perform last wipe with zeros */
# ifdef HAVE_MEMSET
					memset ( buf, 0, fs_block_size );
# else
					for ( j = 0; j < fs_block_size; j++ )
					{
						buf[j] = '\0';
					}
# endif
					error = volume_writetobuf (hfsp_volume,
						buf, (long int)curr_block);
					if ( error != 0 )
					{
						ret_wfs = WFS_BLKWR;
						/* do NOT break here */
					}
					/* No need to flush the last writing of a given block. *
					if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
					{
						error = wfs_hfsp_flush_fs (wfs_fs);
					}*/
				}
			}
		} /* if (volume_allocated) */
		wfs_show_progress (WFS_PROGRESS_WFS,
			(unsigned int)(curr_block / hfsp_volume->vol.total_blocks),
			&prev_percent);
	} /* for (curr_block) */
	free (buf);

	wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
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
 * Starts recursive directory search for deleted inodes
 *	and undelete data on the given HFS+ filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_hfsp_wipe_unrm (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs WFS_ATTR ((unused)))
# else
	wfs_fs)
	wfs_fsid_t wfs_fs WFS_ATTR ((unused));
# endif
{
	wfs_errcode_t ret_unrm = WFS_SUCCESS;
	unsigned int prev_percent = 0;

	/*record_init_cnid (&(elem.hfsp_dirent), &(hfsp_volume->catalog), HFSP_ROOT_CNID);*/
	/* Don't know how to find deleted entries on HFS+ */
	wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
	if ( sig_recvd != 0 )
	{
		return WFS_SIGNAL;
	}
	return ret_unrm;
}
#endif /* WFS_WANT_UNRM */


/* ======================================================================== */

/**
 * Opens a HFS+ filesystem on the given device.
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
wfs_hfsp_open_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t * const wfs_fs,
	const wfs_fsdata_t * const data WFS_ATTR ((unused)))
#else
	wfs_fs, data)
	wfs_fsid_t * const wfs_fs;
	const wfs_fsdata_t * const data WFS_ATTR ((unused));
#endif
{
	wfs_errcode_t ret = WFS_OPENFS;
	int res;
	char * dev_name_copy;
	size_t namelen;
	wfs_errcode_t error = 0;
	struct volume * hfsp_volume;
	wfs_errcode_t * error_ret;
#ifndef HAVE_MEMSET
	size_t j;
#endif

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
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	hfsp_volume = (struct volume *) malloc (sizeof (struct volume));
	if ( hfsp_volume == NULL )
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
#ifdef HAVE_MEMSET
	memset (hfsp_volume, 0, sizeof (struct volume));
#else
	for ( j = 0; j < sizeof (struct volume); j++ )
	{
		((char *)hfsp_volume)[j] = '\0';
	}
#endif
	wfs_fs->whichfs = WFS_CURR_FS_NONE;
	namelen = strlen (wfs_fs->fsname);
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
		free (hfsp_volume);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	strncpy (dev_name_copy, wfs_fs->fsname, namelen + 1);
	dev_name_copy[namelen] = '\0';

	/* volume_open() wants a confirmation from the user when opening in read+write
	   mode, so put a 'y' in the standard input stream. */
	ungetc ('y', stdin);
	res = volume_open (hfsp_volume, dev_name_copy, 0 /*partition*/, HFSP_MODE_RDWR);
	flush_pipe_input (STDIN_FILENO);
	if ( res == 0 )
	{
		wfs_fs->whichfs = WFS_CURR_FS_HFSP;
		ret = WFS_SUCCESS;
		wfs_fs->fs_backend = hfsp_volume;
	}
	else
	{
		volume_close (hfsp_volume);
		free (hfsp_volume);
		error = WFS_OPENFS;
	}

	free (dev_name_copy);
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return ret;
}

/* ======================================================================== */

/**
 * Checks if the given HFS+ filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_hfsp_chk_mount (
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
 * Closes the HFS+ filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_hfsp_close_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs;
#endif
{
	int res;
	struct volume * hfsp_volume;
	wfs_errcode_t * error_ret;

	hfsp_volume = (struct volume *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( hfsp_volume == NULL )
	{
		return WFS_FSCLOSE;
	}
	res = volume_close (hfsp_volume);
	free (hfsp_volume);
	if ( res == 0 )
	{
		return WFS_SUCCESS;
	}
	if ( error_ret != NULL )
	{
		*error_ret = (wfs_errcode_t)res;
	}
	return WFS_FSCLOSE;
}

/* ======================================================================== */

/**
 * Checks if the HFS+ filesystem has errors.
 * \param wfs_fs The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_hfsp_check_err (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs;
#endif
{
	struct volume * hfsp_volume;

	hfsp_volume = (struct volume *) wfs_fs.fs_backend;
	if ( hfsp_volume == NULL )
	{
		return 1;
	}
	return hfsp_volume->vol.attributes & HFSPLUS_VOL_INCNSTNT;
}

/* ======================================================================== */

/**
 * Checks if the HFS+ filesystem is dirty (has unsaved changes).
 * \param wfs_fs The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_hfsp_is_dirty (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs )
#else
	wfs_fs )
	wfs_fsid_t wfs_fs;
#endif
{
	/* FIXME Don't know how to get this information. We have the
	   last modification time, but nothing else. */
	/*return WFS_SUCCESS;*/
	return wfs_hfsp_check_err (wfs_fs);
}

/* ======================================================================== */

/**
 * Flushes the HFS+ filesystem.
 * \param wfs_fs The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_hfsp_flush_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs WFS_ATTR ((unused)))
#else
	wfs_fs)
	wfs_fsid_t wfs_fs WFS_ATTR ((unused));
#endif
{
	/* Better than nothing */
#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_SYNC)
	sync ();
#endif
	return WFS_SUCCESS;
}

/* ======================================================================== */

/**
 * Print the version of the current library, if applicable.
 */
void wfs_hfsp_print_version (
#ifdef WFS_ANSIC
	void
#endif
)
{
	printf ( "HFS+: <?>\n");
}

/* ======================================================================== */

/**
 * Get the preferred size of the error variable.
 * \return the preferred size of the error variable.
 */
size_t wfs_hfsp_get_err_size (
#ifdef WFS_ANSIC
	void
#endif
)
{
	return sizeof (wfs_errcode_t);
}

/* ======================================================================== */

/**
 * Initialize the library.
 */
void wfs_hfsp_init (
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
void wfs_hfsp_deinit (
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
wfs_hfsp_show_error (
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
