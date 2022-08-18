/*
 * A program for secure cleaning of free space on filesystems.
 *	-- HFS+ file system-specific functions.
 *
 * Copyright (C) 2011-2013 Bogdan Drozdowski, bogdandr (at) op.pl
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

/* redefine the inline sig function from hfsp, each time with a different name */
#define sig(a,b,c,d) wfs_hfsp_sig(a,b,c,d)
#include "wipefreespace.h"

#if (defined HAVE_HFSPLUS_LIBHFSP_H) && (defined HAVE_LIBHFSP)
/*# include <hfsplus/libhfsp.h> included in wipefreespace.h */
# include <hfsplus/volume.h>
# include <hfsplus/blockiter.h>
#else
# if (defined HAVE_LIBHFSP_H) && (defined HAVE_LIBHFSP)
/*# include <libhfsp.h> included in wipefreespace.h */
# include <volume.h>
# include <blockiter.h>
# else
#  error Something wrong. HFS+ requested, but libhfsp.h or libhfsp missing.
# endif
#endif
extern int volume_writetobuf WFS_PARAMS ((volume * vol, void * buf, long int block));

#include "wfs_hfsp.h"
#include "wfs_signal.h"
#include "wfs_util.h"
#include "wfs_wiping.h"

/* ============================================================= */

#if (defined WFS_WANT_WFS) || (defined WFS_WANT_PART)
# ifndef WFS_ANSIC
static size_t WFS_ATTR ((warn_unused_result)) wfs_hfsp_get_block_size WFS_PARAMS ((const wfs_fsid_t FS));
# endif

/**
 * Returns the buffer size needed to work on the
 *	smallest physical unit on a HFS+ filesystem.
 * \param FS The filesystem.
 * \return Block size on the filesystem.
 */
static size_t WFS_ATTR ((warn_unused_result))
wfs_hfsp_get_block_size (
# ifdef WFS_ANSIC
	const wfs_fsid_t FS )
# else
	FS)
	const wfs_fsid_t FS;
# endif
{
	return FS.hfsp_volume.vol.blocksize;
}
#endif /* (defined WFS_WANT_WFS) || (defined WFS_WANT_PART) */

/* ======================================================================== */

#ifdef WFS_WANT_PART
# ifndef WFS_ANSIC
static wfs_errcode_t WFS_ATTR ((warn_unused_result))
	wfs_hfsp_wipe_part_file WFS_PARAMS ((
		wfs_fsid_t FS, record * const file, unsigned char buf[], wfs_error_type_t * const error,
		UInt32 * const curr_file, unsigned int * const prev_percent));
# endif

/**
 * Wipes the free space in partially used blocks in the given file.
 * \param FS The filesystem.
 * \param file The file to check.
 * \param buf The current buffer.
 * \param error Pointer to error variable.
 * \param curr_file_no Pointer to the number of files already checked.
 * \param prev_percent Pointer to previous progress.
 * \return 0 in case of no errors, other values otherwise.
 */
static wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_hfsp_wipe_part_file (
# ifdef WFS_ANSIC
	wfs_fsid_t FS, record * const file, unsigned char buf[], wfs_error_type_t * const error_ret,
	UInt32 * const curr_file_no, unsigned int * const prev_percent)
# else
	FS, file, buf, error_ret, curr_file_no, prev_percent)
	wfs_fsid_t FS;
	record * const file;
	unsigned char buf[];
	wfs_error_type_t * const error_ret;
	UInt32 * const curr_file_no;
	unsigned int * const prev_percent;
# endif
{
	wfs_errcode_t ret_part = WFS_SUCCESS;
	unsigned long int j;
	int selected[WFS_NPAT];
	blockiter iter;
	UInt32 last_block;
	int res;
	UInt64 remainder;
	wfs_error_type_t error = {CURR_HFSP, {0}};

	if ( (buf == NULL) || (file == NULL) )
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

	remainder = file->record.u.file.data_fork.total_size % wfs_hfsp_get_block_size (FS);
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

	blockiter_init (&iter, &(FS.hfsp_volume), &(file->record.u.file.data_fork),
		(UInt8)HFSP_EXTENT_DATA, file->record.u.file.id);
	/* skip the full blocks */
	if ( blockiter_skip (&iter,
		file->record.u.file.data_fork.total_blocks/wfs_hfsp_get_block_size (FS)) != 0 )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BLKITER;
	}
	/* read the last block here: */
	last_block = blockiter_curr (&iter);
	res = volume_readinbuf (&(FS.hfsp_volume), buf, (long int)last_block);
	if ( res != 0 )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BLKRD;
	}
	/* wipe the fail tail here: */
	for ( j = 0; (j < FS.npasses) && (sig_recvd == 0); j++ )
	{
		fill_buffer ( j, &buf[remainder], (size_t)(wfs_hfsp_get_block_size (FS) - remainder),
			selected, FS );
		error.errcode.gerror = volume_writetobuf (&(FS.hfsp_volume),
			buf, (long int)last_block);
		if ( error.errcode.gerror != 0 )
		{
			ret_part = WFS_BLKWR;
			break;
		}
		/* Flush after each writing, if more than 1 overwriting needs to be done.
		Allow I/O bufferring (efficiency), if just one pass is needed. */
		if ( (FS.npasses > 1) && (sig_recvd == 0) )
		{
			error.errcode.gerror = wfs_hfsp_flush_fs ( FS, &error );
		}
	}
	if ( (FS.zero_pass != 0) && (sig_recvd == 0) && (ret_part == WFS_SUCCESS) )
	{
		/* perform last wipe with zeros */
# ifdef HAVE_MEMSET
		memset ( &buf[remainder], 0, (size_t)(wfs_hfsp_get_block_size (FS) - remainder) );
# else
		for ( j=remainder; j < wfs_hfsp_get_block_size (FS); j++ )
		{
			buf[j] = '\0';
		}
# endif
		error.errcode.gerror = volume_writetobuf (&(FS.hfsp_volume),
			buf, (long int)last_block);
		if ( error.errcode.gerror != 0 )
		{
			ret_part = WFS_BLKWR;
			/* do NOT break here */
		}
		/* Flush after each writing, if more than 1 overwriting needs to be done.
		Allow I/O bufferring (efficiency), if just one pass is needed. */
		if ( (FS.npasses > 1) && (sig_recvd == 0) )
		{
			error.errcode.gerror = wfs_hfsp_flush_fs ( FS, &error );
		}
	}

	if ( curr_file_no != NULL )
	{
		(*curr_file_no) ++;
		if ( (prev_percent != NULL) && (FS.hfsp_volume.vol.file_count != 0) )
		{
			show_progress (WFS_PROGRESS_PART,
				(*curr_file_no)/(FS.hfsp_volume.vol.file_count), prev_percent);
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
static wfs_errcode_t WFS_ATTR ((warn_unused_result))
	wfs_hfsp_wipe_part_dir WFS_PARAMS ((
		wfs_fsid_t FS, record * const dir, unsigned char buf[], wfs_error_type_t * const error_ret,
		UInt32 * const curr_file_no, unsigned int * const prev_percent));
# endif

/**
 * Wipes the free space in partially used blocks in files in the given directory.
 * \param FS The filesystem.
 * \param dir The current directory.
 * \param buf The current buffer.
 * \param error Pointer to error variable.
 * \param curr_file_no Pointer to the number of files already checked.
 * \param prev_percent Pointer to previous progress.
 * \return 0 in case of no errors, other values otherwise.
 */
static wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_hfsp_wipe_part_dir (
# ifdef WFS_ANSIC
	wfs_fsid_t FS, record * const dir, unsigned char buf[], wfs_error_type_t * const error_ret,
	UInt32 * const curr_file_no, unsigned int * const prev_percent)
# else
	FS, dir, buf, error_ret, curr_file_no, prev_percent)
	wfs_fsid_t FS;
	record * const dir;
	unsigned char buf[];
	wfs_error_type_t * const error_ret;
	UInt32 * const curr_file_no;
	unsigned int * const prev_percent;
# endif
{
	wfs_errcode_t ret_part = WFS_SUCCESS;
	wfs_errcode_t ret_temp = WFS_SUCCESS;
	record curr_elem;
	wfs_error_type_t error = {CURR_HFSP, {0}};

	if ( (buf == NULL) || (dir == NULL) )
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
				ret_part = wfs_hfsp_wipe_part_dir (FS, &curr_elem, buf, &error,
					curr_file_no, prev_percent);
			}
			else
			{
				/* keep the current error */
				ret_temp = wfs_hfsp_wipe_part_dir (FS, &curr_elem, buf, &error,
					curr_file_no, prev_percent);
			}
		}
		else if ( curr_elem.record.type == HFSP_FILE )
		{
			if ( ret_part == WFS_SUCCESS )
			{
				ret_part = wfs_hfsp_wipe_part_file (FS, &curr_elem, buf, &error,
					curr_file_no, prev_percent);
			}
			else
			{
				/* keep the current error */
				ret_temp = wfs_hfsp_wipe_part_file (FS, &curr_elem, buf, &error,
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
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_hfsp_wipe_part (
# ifdef WFS_ANSIC
	wfs_fsid_t FS, wfs_error_type_t * const error_ret )
# else
	FS, error_ret )
	wfs_fsid_t FS;
	wfs_error_type_t * const error_ret;
# endif
{
	wfs_errcode_t ret_part = WFS_SUCCESS;
	unsigned int prev_percent = 0;
	unsigned char * buf;
	UInt32 curr_file_no = 0;
	record dir;
	int res;
	wfs_error_type_t error = {CURR_HFSP, {0}};

	/* get the root directory: */
	res = record_init_cnid (&dir, &(FS.hfsp_volume.catalog), HFSP_ROOT_CNID);
	if ( res != 0 )
	{
		show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
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
	buf = (unsigned char *) malloc ( wfs_hfsp_get_block_size (FS) );
	if ( buf == NULL )
	{
# ifdef HAVE_ERRNO_H
		error.errcode.gerror = errno;
# else
		error.errcode.gerror = 12L;	/* ENOMEM */
# endif
		show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		return WFS_MALLOC;
	}

	ret_part = wfs_hfsp_wipe_part_dir (FS, &dir, buf, &error, &curr_file_no, &prev_percent);

	free (buf);
	show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
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
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_hfsp_wipe_fs (
# ifdef WFS_ANSIC
	wfs_fsid_t FS, wfs_error_type_t * const error_ret )
# else
	FS, error_ret )
	wfs_fsid_t FS;
	wfs_error_type_t * const error_ret;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	unsigned int prev_percent = 0;
	UInt32 curr_block;
	unsigned long int j;
	int selected[WFS_NPAT];
	unsigned char * buf;
	wfs_error_type_t error = {CURR_HFSP, {0}};

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	buf = (unsigned char *) malloc ( wfs_hfsp_get_block_size (FS) );
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

	for ( curr_block = 0;
		(curr_block < FS.hfsp_volume.vol.total_blocks) && (sig_recvd == 0);
		curr_block++ )
	{
		if ( volume_allocated (&(FS.hfsp_volume), curr_block) == 0 )
		{
			/* block is not allocated - wipe it */
			for ( j = 0; (j < FS.npasses) && (sig_recvd == 0); j++ )
			{
				fill_buffer ( j, buf, wfs_hfsp_get_block_size (FS), selected, FS );
				error.errcode.gerror = volume_writetobuf (&(FS.hfsp_volume),
					buf, (long int)curr_block);
				if ( error.errcode.gerror != 0 )
				{
					ret_wfs = WFS_BLKWR;
					break;
				}
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( (FS.npasses > 1) && (sig_recvd == 0) )
				{
					error.errcode.gerror = wfs_hfsp_flush_fs ( FS, &error );
				}
			}
			if ( (FS.zero_pass != 0) && (sig_recvd == 0) && (ret_wfs == WFS_SUCCESS) )
			{
				/* perform last wipe with zeros */
# ifdef HAVE_MEMSET
				memset ( buf, 0, wfs_hfsp_get_block_size (FS) );
# else
				for ( j=0; j < wfs_hfsp_get_block_size (FS); j++ )
				{
					buf[j] = '\0';
				}
# endif
				error.errcode.gerror = volume_writetobuf (&(FS.hfsp_volume),
					buf, (long int)curr_block);
				if ( error.errcode.gerror != 0 )
				{
					ret_wfs = WFS_BLKWR;
					/* do NOT break here */
				}
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( (FS.npasses > 1) && (sig_recvd == 0) )
				{
					error.errcode.gerror = wfs_hfsp_flush_fs ( FS, &error );
				}
			}
		} /* if (volume_allocated) */
		show_progress (WFS_PROGRESS_WFS, curr_block/FS.hfsp_volume.vol.total_blocks, &prev_percent);
	} /* for (curr_block) */
	free (buf);

	show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
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
 * \param FS The filesystem.
 * \param node Filesystem element at which to start.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_hfsp_wipe_unrm (
# ifdef WFS_ANSIC
	wfs_fsid_t FS WFS_ATTR ((unused)),
	const wfs_fselem_t node WFS_ATTR ((unused)),
	wfs_error_type_t * const error WFS_ATTR ((unused)) )
# else
	FS, node, error )
	wfs_fsid_t FS WFS_ATTR ((unused));
	const wfs_fselem_t node WFS_ATTR ((unused));
	wfs_error_type_t * const error WFS_ATTR ((unused));
# endif
{
	wfs_errcode_t ret_unrm = WFS_SUCCESS;
	unsigned int prev_percent = 0;

	/* Don't know how to find deleted entries on HFS+ */
	show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
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
wfs_hfsp_open_fs (
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
	wfs_errcode_t ret = WFS_OPENFS;
	int res;
	char * dev_name_copy;
	size_t namelen;
	wfs_error_type_t error = {CURR_HFSP, {0}};

	if ((dev_name == NULL) || (FS == NULL) || (whichfs == NULL))
	{
		return WFS_BADPARAM;
	}

	*whichfs = CURR_NONE;
	namelen = strlen (dev_name);
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	dev_name_copy = (char *) malloc ( namelen + 1 );
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

	/* volume_open() wants a confirmation from the user when opening in read+write
	   mode, so put a 'y' in the standard input stream. */
	ungetc ('y', stdin);
	res = volume_open (&(FS->hfsp_volume), dev_name_copy, 0 /*partition*/, HFSP_MODE_RDWR);
	if ( res == 0 )
	{
		*whichfs = CURR_HFSP;
		ret = WFS_SUCCESS;
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
wfs_errcode_t WFS_ATTR ((warn_unused_result))
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_hfsp_chk_mount (
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
 * Closes the HFS+ filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_hfsp_close_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t FS, wfs_error_type_t * const error WFS_ATTR ((unused)) )
#else
	FS, error )
	wfs_fsid_t FS;
	wfs_error_type_t * const error WFS_ATTR ((unused));
#endif
{
	int res = volume_close (&(FS.hfsp_volume));
	if ( res == 0 )
	{
		return WFS_SUCCESS;
	}
	return WFS_FSCLOSE;
}

/* ======================================================================== */

/**
 * Checks if the HFS+ filesystem has errors.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_hfsp_check_err (
#ifdef WFS_ANSIC
	wfs_fsid_t FS )
#else
	FS )
	wfs_fsid_t FS;
#endif
{
	return FS.hfsp_volume.vol.attributes & HFSPLUS_VOL_INCNSTNT;
}

/* ======================================================================== */

/**
 * Checks if the HFS+ filesystem is dirty (has unsaved changes).
 * \param FS The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_hfsp_is_dirty (
#ifdef WFS_ANSIC
	wfs_fsid_t FS )
#else
	FS )
	wfs_fsid_t FS;
#endif
{
	/* FIXME Don't know how to get this information. We have the
	   last modification time, but nothing else. */
	/*return WFS_SUCCESS;*/
	return wfs_hfsp_check_err (FS);
}

/* ======================================================================== */

/**
 * Flushes the HFS+ filesystem.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_hfsp_flush_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t FS WFS_ATTR ((unused)), wfs_error_type_t * const error WFS_ATTR ((unused)) )
#else
	FS, error )
	wfs_fsid_t FS WFS_ATTR ((unused));
	wfs_error_type_t * const error WFS_ATTR ((unused));
#endif
{
	/* Better than nothing */
#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_SYNC)
	sync ();
#endif
	return WFS_SUCCESS;
}
