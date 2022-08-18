/*
 * A program for secure cleaning of free space on filesystems.
 *	-- JFS file system-specific functions.
 *
 * Copyright (C) 2010-2016 Bogdan Drozdowski, bogdandr (at) op.pl
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

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#else
# ifdef HAVE_VARARGS_H
#  include <varargs.h>
# endif
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

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_STRING_H
# if ((!defined STDC_HEADERS) || (!STDC_HEADERS)) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#include "wipefreespace.h"

/* define the undefined to 0 for JFS header files: */
#ifndef HAVE_SYS_BYTEORDER_H
# define WFS_ADDED_HAVE_SYS_BYTEORDER_H
# define HAVE_SYS_BYTEORDER_H 0
#endif
#ifndef HAVE_MACHINE_ENDIAN_H
# define WFS_ADDED_HAVE_MACHINE_ENDIAN_H
# define HAVE_MACHINE_ENDIAN_H 0
#endif
#ifndef HAVE_ENDIAN_H
# define WFS_ADDED_HAVE_ENDIAN_H
# define HAVE_ENDIAN_H 0
#endif

#if (defined HAVE_JFS_JFS_SUPERBLOCK_H) && (defined HAVE_LIBFS)
# include <jfs/jfs_types.h>
# include <jfs/jfs_superblock.h>
# ifndef __le32_to_cpu /* NTFS defines its own versions */
#  include <jfs/jfs_byteorder.h>
# endif
# include <jfs/jfs_filsys.h>
# include <jfs/jfs_dmap.h>
# include <jfs/jfs_logmgr.h>
#else
# if (defined HAVE_JFS_SUPERBLOCK_H) && (defined HAVE_LIBFS)
#  include <jfs_types.h>
#  include <jfs_superblock.h>
#  ifndef __le32_to_cpu /* NTFS defines its own versions */
#   include <jfs_byteorder.h>
#  endif
#  include <jfs_filsys.h>
#  include <jfs_dmap.h>
#  include <jfs_logmgr.h>
# else
#  error Something wrong. JFS requested, but jfs_superblock.h or libfs missing.
# endif
#endif

/* undo the defining, if any: */
#ifdef WFS_ADDED_HAVE_SYS_BYTEORDER_H
# undef HAVE_SYS_BYTEORDER_H
#endif
#ifdef WFS_ADDED_HAVE_MACHINE_ENDIAN_H
# undef HAVE_MACHINE_ENDIAN_H
#endif
#ifdef WFS_ADDED_HAVE_ENDIAN_H
# undef HAVE_ENDIAN_H
#endif

#ifndef GET
# define GET 0
#endif
#ifndef PUT
# define PUT 1
#endif

#include "wfs_jfs.h"
#include "wfs_signal.h"
#include "wfs_util.h"
#include "wfs_wiping.h"

static char wfs_jfs_dev_path[] = "/dev";

struct wfs_jfs
{
	FILE * fs;
	struct superblock super;
};

/* ============================================================= */
/* JFS external symbols, but declared nowhere. */
extern int ujfs_flush_dev WFS_PARAMS ((FILE *fp));
extern int ujfs_get_dev_size WFS_PARAMS ((FILE *device, int64_t *size));
extern int ujfs_get_superblk WFS_PARAMS ((FILE *fp, struct superblock *sb, int32_t is_primary));
extern int ujfs_rw_diskblocks WFS_PARAMS ((FILE *dev_ptr, int64_t disk_offset,
	int32_t disk_count, void *data_buffer, int32_t mode));
extern void ujfs_swap_dbmap WFS_PARAMS ((struct dbmap *dbm_t));
extern int ujfs_validate_super WFS_PARAMS ((struct superblock *sb));
extern FILE * walk_dir WFS_PARAMS ((char *path, uuid_t uuid,
	int is_label, int is_log, int *in_use));
extern void ujfs_swap_logsuper WFS_PARAMS ((struct logsuper *));
extern int jfs_logform WFS_PARAMS ((FILE *fp, int aggr_blk_size, int s_l2bsize,
	uint s_flag, int64_t log_start, int log_len, uuid_t uuid, char *label));

#if __BYTE_ORDER == __BIG_ENDIAN
extern void ujfs_swap_logsuper WFS_PARAMS ((struct logsuper *));
extern void ujfs_swap_dmap WFS_PARAMS ((struct dmap *));
#endif
#ifndef LOGPNTOB
# define LOGPNTOB(x)  ((x)<<L2LOGPSIZE)
#endif

/* ============================================================= */
/* JFS internal symbols, but used by the library. */
extern char log_device[1];
char log_device[1];

int v_fsck_send_msg WFS_PARAMS ((int msg_num , const char *file_name, int line_number, ... ));
int alloc_wrksp WFS_PARAMS ((unsigned length, int dynstg_object, int for_logredo, void **addr_wrksp_ptr ));

int
v_fsck_send_msg (
#ifdef WFS_ANSIC
	int msg_num WFS_ATTR ((unused)), const char *file_name WFS_ATTR ((unused)),
	int line_number WFS_ATTR ((unused)), ... )
#else
	va_alist )
	va_dcl /* no semicolons here! */
/*	msg_num, file_name, line_number, ...)
	int msg_num WFS_ATTR ((unused));
	const char *file_name WFS_ATTR ((unused));
	int line_number WFS_ATTR ((unused));*/
#endif
{
	return 0;
}

int
alloc_wrksp (
#ifdef WFS_ANSIC
	unsigned length, int dynstg_object WFS_ATTR ((unused)),
	int for_logredo WFS_ATTR ((unused)), void **addr_wrksp_ptr )
#else
	length, dynstg_object, for_logredo, addr_wrksp_ptr )
	unsigned length;
	int dynstg_object WFS_ATTR ((unused));
	int for_logredo WFS_ATTR ((unused));
	void **addr_wrksp_ptr;
#endif
{
	unsigned min_length;

	*addr_wrksp_ptr = NULL;	/* initialize return value */
	min_length = ((length + 7) / 4) * 4;	/* round up to an 4 byte boundary */

	*addr_wrksp_ptr = malloc (min_length);

	return 0;
}

/* ============================================================= */

#ifdef WFS_WANT_WFS
# ifndef WFS_ANSIC
static int GCC_WARN_UNUSED_RESULT is_block_free WFS_PARAMS ((
	const int64_t block, struct dmap * * const map, const int64_t nmaps));
# endif

/**
 * Checks if the given block is free (unused).
 * \param block The block number to check.
 * \return 0 if the block is used, 1 if unused (free).
 */
static int GCC_WARN_UNUSED_RESULT
is_block_free (
# ifdef WFS_ANSIC
	const int64_t block, struct dmap * * const map, const int64_t nmaps)
# else
	block, map, nmaps)
	const int64_t block;
	struct dmap * * const map;
	const int64_t nmaps;
# endif
{
	int dmap_index;
	int blk_in_dmap;
	int dmap_part;
	int dmap_bit;

	if ( (block < 0) || (map == NULL) || (nmaps == 0) )
	{
		return 0;
	}

	dmap_index = (int)(block / BPERDMAP);
	blk_in_dmap = (int)(block - dmap_index * BPERDMAP);
	dmap_part = blk_in_dmap >> L2DBWORD;
	dmap_bit = blk_in_dmap - (dmap_part << L2DBWORD);

	if ( dmap_index >= nmaps )
	{
		return 0;
	}
	if ( map[dmap_index] == NULL )
	{
		return 0;
	}

	/* shift by zero bits can be undefined, so handle the case here. */
	if ( (dmap_bit == 0) && (((map[dmap_index]->pmap[dmap_part] & 0x80000000) == 0)
		&& ((map[dmap_index]->wmap[dmap_part] & 0x80000000) == 0)) )
	{
		return 1;
	}
	if ( ((map[dmap_index]->pmap[dmap_part] & (0x80000000u >> dmap_bit)) == 0)
		&& ((map[dmap_index]->wmap[dmap_part] & (0x80000000u >> dmap_bit)) == 0) )
	{
		return 1;
	}

	return 0;
}
#endif /* WFS_WANT_WFS */

/* ======================================================================== */

#if (defined WFS_WANT_WFS) || (defined WFS_WANT_UNRM)
# ifndef WFS_ANSIC
static size_t GCC_WARN_UNUSED_RESULT wfs_jfs_get_block_size WFS_PARAMS ((const wfs_fsid_t wfs_fs));
# endif

/**
 * Returns the buffer size needed to work on the
 *	smallest physical unit on a JFS filesystem.
 * \param wfs_fs The filesystem.
 * \return Block size on the filesystem.
 */
static size_t GCC_WARN_UNUSED_RESULT
wfs_jfs_get_block_size (
# ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs )
# else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
# endif
{
	struct wfs_jfs * jfs;

	jfs = (struct wfs_jfs *) wfs_fs.fs_backend;
	if ( jfs == NULL )
	{
		return 0;
	}
	return (size_t)(jfs->super.s_bsize);
}

/* ======================================================================== */

# ifndef WFS_ANSIC
static wfs_errcode_t wfs_jfs_wipe_block WFS_PARAMS ((const wfs_fsid_t wfs_fs, const int64_t blocknum,
	unsigned char * const buf, const size_t bufsize, FILE * fp));
# endif

/**
 * Wipes the given block.
 * \param blocknum The number of the block to wipe.
 */
static wfs_errcode_t
wfs_jfs_wipe_block (
# ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs, const int64_t blocknum,
	unsigned char * const buf, const size_t bufsize,
	FILE * fp)
# else
	wfs_fs, blocknum, buf, bufsize, fp)
	const wfs_fsid_t wfs_fs;
	const int64_t blocknum;
	unsigned char * buf;
	size_t bufsize;
	FILE * fp;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	unsigned int j;
	int selected[WFS_NPAT] = {0};
	int res;
	wfs_errcode_t error = 0;
	wfs_errcode_t * error_ret;
	size_t fs_block_size;

	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( (buf == NULL) || (fp == NULL) )
	{
		ret_wfs = WFS_BADPARAM;
		if ( sig_recvd != 0 )
		{
			ret_wfs = WFS_SIGNAL;
		}
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return ret_wfs;
	}
	fs_block_size = wfs_jfs_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	for ( j = 0; (j < wfs_fs.npasses) && (sig_recvd == 0); j++ )
	{
		if ( wfs_fs.no_wipe_zero_blocks != 0 )
		{
			res = ujfs_rw_diskblocks (fp,
				blocknum * fs_block_size,
				(int32_t)bufsize, buf, GET);
			if ( res != 0 )
			{
				ret_wfs = WFS_BLKRD;
				break;
			}
			if ( wfs_is_block_zero (buf, fs_block_size) != 0 )
			{
				/* this block is all-zeros - don't wipe, as requested */
				j = wfs_fs.npasses * 2;
				break;
			}
		}
		fill_buffer ( j, buf, bufsize, selected, wfs_fs );
		if ( sig_recvd != 0 )
		{
			break;
		}
		res = ujfs_rw_diskblocks (fp, blocknum * fs_block_size,
			(int32_t)bufsize, buf, PUT);
		if ( res != 0 )
		{
			break;
		}
		/* Flush after each writing, if more than 1 overwriting needs to be done.
		Allow I/O bufferring (efficiency), if just one pass is needed. */
		if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
		{
			error = ujfs_flush_dev (fp);
		}
	}
	if ( j < wfs_fs.npasses )
	{
		if ( ret_wfs == WFS_SUCCESS )
		{
			ret_wfs = WFS_BLKWR;
		}
		if ( sig_recvd != 0 )
		{
			ret_wfs = WFS_SIGNAL;
		}
		return ret_wfs;
	}
	if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
	{
		/* last pass with zeros: */
		if ( j != wfs_fs.npasses * 2 )
		{
# ifdef HAVE_MEMSET
			memset ( buf, 0, bufsize );
# else
			for ( j=0; j < bufsize; j++ )
			{
				buf[j] = '\0';
			}
# endif
			if ( sig_recvd == 0 )
			{
				res = ujfs_rw_diskblocks (fp,
					blocknum * fs_block_size,
					(int32_t)bufsize, buf, PUT);
				if ( res != 0 )
				{
					ret_wfs = WFS_BLKWR;
					if ( sig_recvd != 0 )
					{
						ret_wfs = WFS_SIGNAL;
					}
					return ret_wfs;
				}
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
				{
					error = ujfs_flush_dev (fp);
				}
			}
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
	return WFS_SUCCESS;
}
#endif /* (defined WFS_WANT_WFS) || (defined WFS_WANT_UNRM) */

/* ======================================================================== */

#ifdef WFS_WANT_PART
/**
 * Wipes the free space in partially used blocks on the given JFS filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_jfs_wipe_part (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_part = WFS_SUCCESS;
	unsigned int prev_percent = 0;
	struct wfs_jfs * jfs;

	jfs = (struct wfs_jfs *) wfs_fs.fs_backend;
	if ( jfs == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( sig_recvd != 0 )
		{
			return WFS_SIGNAL;
		}
		return WFS_BADPARAM;
	}
	if ( jfs->fs == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( sig_recvd != 0 )
		{
			return WFS_SIGNAL;
		}
		return WFS_BADPARAM;
	}
	/* The library doesn't provide any method to search or open directories/files. */
	wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
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
 * Wipes the free space on the given JFS filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_jfs_wipe_fs (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	unsigned int prev_percent = 0;
	int res = 0;
	int64_t total_size = 0;
	int64_t nblocks = 0;
	int64_t i;
	int64_t j;
	struct dmap **block_map = NULL;
	int64_t start = 0;
	int level;
	int blocks;
	int64_t ndmaps;
	size_t bufsize;
	unsigned char * buf;
	wfs_errcode_t error = 0;
	struct wfs_jfs * jfs;
	wfs_errcode_t * error_ret;

	jfs = (struct wfs_jfs *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( jfs == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	if ( jfs->fs == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}

	bufsize = wfs_jfs_get_block_size (wfs_fs);
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	buf = (unsigned char *) malloc ( bufsize );
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

	res = ujfs_get_dev_size (jfs->fs, &total_size);
	if ( (res != 0) || (total_size <= 0) )
	{
		error = WFS_BLBITMAPREAD;
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		free (buf);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BLBITMAPREAD;
	}
	nblocks = total_size / jfs->super.s_bsize;
	level = BMAPSZTOLEV (nblocks);
	blocks = L2BPERDMAP + level * L2LPERCTL;
	ndmaps = nblocks >> blocks;
	/* round up: */
	if ( (nblocks & ((1 << blocks) - 1)) != 0 )
	{
		ndmaps++;
	}
	if ( ndmaps == 0 )
	{
		error = WFS_BLBITMAPREAD;
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		free (buf);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BLBITMAPREAD;
	}
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	block_map = (struct dmap **) malloc ((size_t)ndmaps * sizeof (struct dmap *));
	if ( block_map == NULL )
	{
# ifdef HAVE_ERRNO_H
		error = errno;
# else
		error = 12L;    /* ENOMEM */
# endif
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		free (buf);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}
	for ( i=0; i < ndmaps; i++ )
	{
		block_map[i] = NULL;
	}
	start = BMAP_OFF + PSIZE + PSIZE * (2 - level) + PSIZE;
	for ( i = 0; (i < ndmaps) && (sig_recvd == 0); i++ )
	{
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		block_map[i] = (struct dmap *) malloc (sizeof (struct dmap));
		if ( block_map[i] == NULL )
		{
# ifdef HAVE_ERRNO_H
			error = errno;
# else
			error = 12L;    /* ENOMEM */
# endif
			start += PSIZE;
			continue;
		}
		res = ujfs_rw_diskblocks (jfs->fs, start,
			sizeof (struct dmap) /*PSIZE*/, block_map[i], GET);
		if ( res != 0 )
		{
			start += PSIZE;
			continue;
		}
# if __BYTE_ORDER == __BIG_ENDIAN
		ujfs_swap_dmap (block_map[i]);
# endif
		start += PSIZE;
	}

	for ( i = 0; (i < ndmaps) && (sig_recvd == 0); i++ )
	{
		if ( block_map[i] == NULL )
		{
			continue;
		}
		/* skip this dmap if no free blocks */
		if ( block_map[i]->nfree == 0 )
		{
			continue;
		}
		for ( j = 0; (j < block_map[i]->nblocks)
			&& (sig_recvd == 0); j++ )
		{
			if ( is_block_free (block_map[i]->start + j,
				block_map, ndmaps) == 1 )
			{
				/* wipe the block here */
				if ( ret_wfs == WFS_SUCCESS )
				{
					ret_wfs = wfs_jfs_wipe_block (wfs_fs,
						block_map[i]->start + j,
						buf, bufsize, jfs->fs);
				}
				else
				{
					wfs_jfs_wipe_block (wfs_fs,
						block_map[i]->start + j,
						buf, bufsize, jfs->fs);
				}
				/* update the progress: */
				wfs_show_progress (WFS_PROGRESS_WFS, (unsigned int)((i*100)/ndmaps
					+ (j*100)/block_map[i]->nblocks/ndmaps), &prev_percent);
			}
		}
	}
	wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
	for ( i = 0; i < ndmaps; i++ )
	{
		if ( block_map[i] != NULL )
		{
			free (block_map[i]);
		}
	}
	free (block_map);
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
 * Starts recursive directory search for deleted inodes
 *	and undelete data on the given JFS filesystem.
 * \param wfs_fs The filesystem.
 * \param node Filesystem element at which to start.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_jfs_wipe_unrm (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_unrm = WFS_SUCCESS;
	struct logsuper journal;
	FILE * journal_fp = NULL;
	int journal_in_use = 1;
	int res;
	int64_t block;
	int64_t total_size = 0;
	unsigned char * buf = NULL;
	size_t bufsize;
	int64_t nblocks = 0;
	int32_t i;
	wfs_errcode_t error = 0;
	unsigned int prev_percent = 0;
	struct wfs_jfs * jfs;
	wfs_errcode_t * error_ret;

	jfs = (struct wfs_jfs *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( jfs == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	if ( jfs->fs == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}

	/* The library doesn't provide any method to search or open directories/files,
	   so wipe only the journal (log).*/
	if ( (jfs->super.s_flag & JFS_INLINELOG) == JFS_INLINELOG )
	{
		/* journal on the same device */
		block = (addressPXD (&(jfs->super.s_logpxd))
			<< jfs->super.s_l2bsize) + LOGPSIZE;

		res = ujfs_rw_diskblocks (jfs->fs, block,
			sizeof (struct logsuper) /*LOGPSIZE*/, &journal, GET);
		if ( res != 0 )
		{
			wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
			ret_unrm = WFS_OPENFS;
			if ( sig_recvd != 0 )
			{
				ret_unrm = WFS_SIGNAL;
			}
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return ret_unrm;
		}
# if __BYTE_ORDER == __BIG_ENDIAN
		ujfs_swap_logsuper (&journal);
# endif
		if ( journal.magic != LOGMAGIC )
		{
			wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
			ret_unrm = WFS_OPENFS;
			if ( sig_recvd != 0 )
			{
				ret_unrm = WFS_SIGNAL;
			}
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return ret_unrm;
		}
		bufsize = LOGPSIZE;
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		buf = (unsigned char *) malloc ( bufsize );
		if ( buf == NULL )
		{
# ifdef HAVE_ERRNO_H
			error = errno;
# else
			error = 12L;	/* ENOMEM */
# endif
			wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
			ret_unrm = WFS_MALLOC;
			if ( sig_recvd != 0 )
			{
				ret_unrm = WFS_SIGNAL;
			}
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return ret_unrm;
		}

		/* Skip the superblock, because we need its old UUID.
		Note that LOGPSIZE has been added TWICE to the "block" variable.
		*/
		block += LOGPSIZE;
		for ( i = 0; i < journal.size - 2; i++ )
		{
			/* NOTE: not the same block number for wfs_fs.jfs.fs and the journal. */
			/* wfs_jfs_wipe_block expects a block number, not an offset, while
			   "block" is an offset here, because it is required so below */
			if ( ret_unrm == WFS_SUCCESS )
			{
				ret_unrm = wfs_jfs_wipe_block (wfs_fs,
					(block + i*jfs->super.s_bsize)/jfs->super.s_bsize,
					buf, bufsize, jfs->fs);
			}
			else
			{
				wfs_jfs_wipe_block (wfs_fs,
					(block + i*jfs->super.s_bsize)/jfs->super.s_bsize,
					buf, bufsize, jfs->fs);
			}
		}
		free (buf);
		/* format a new journal: */
		jfs_logform (jfs->fs, jfs->super.s_bsize, jfs->super.s_l2bsize,
			jfs->super.s_flag, (block - 2 * LOGPSIZE)/jfs->super.s_bsize,
			(journal.size * LOGPSIZE)/jfs->super.s_bsize, journal.uuid,
			journal.label);
	}
	else
	{
		/* journal on an external device - jfs->super->s_loguuid has the UUID */
		journal_fp = walk_dir (wfs_jfs_dev_path, jfs->super.s_loguuid,
			0 /*is_label*/, 1 /*is_log*/, &journal_in_use);
		if ( journal_fp == NULL )
		{
			/* journal device not found under /dev */
			wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
			ret_unrm = WFS_MNTRW;
			if ( sig_recvd != 0 )
			{
				ret_unrm = WFS_SIGNAL;
			}
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return ret_unrm;
		}
		if ( journal_in_use != 0 )
		{
			fclose (journal_fp);
			wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
			ret_unrm = WFS_MNTRW;
			if ( sig_recvd != 0 )
			{
				ret_unrm = WFS_SIGNAL;
			}
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return ret_unrm;
		}
		res = ujfs_rw_diskblocks (journal_fp, (int64_t)(LOGPNTOB (LOGSUPER_B)),
			sizeof (struct logsuper), &journal, GET);
		if (res != 0)
		{
			/* can't read superblock */
			fclose (journal_fp);
			wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
			ret_unrm = WFS_OPENFS;
			if ( sig_recvd != 0 )
			{
				ret_unrm = WFS_SIGNAL;
			}
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return ret_unrm;
		}
# if __BYTE_ORDER == __BIG_ENDIAN
		ujfs_swap_logsuper (&journal);
# endif
		if ( journal.magic != LOGMAGIC )
		{
			fclose (journal_fp);
			wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
			ret_unrm = WFS_OPENFS;
			if ( sig_recvd != 0 )
			{
				ret_unrm = WFS_SIGNAL;
			}
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return ret_unrm;
		}

		res = ujfs_get_dev_size (jfs->fs, &total_size);
		if ( (res != 0) || (total_size <= 0) )
		{
			error = WFS_BLBITMAPREAD;
			fclose (journal_fp);
			wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
			ret_unrm = WFS_BLBITMAPREAD;
			if ( sig_recvd != 0 )
			{
				ret_unrm = WFS_SIGNAL;
			}
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return ret_unrm;
		}
		bufsize = (size_t)(journal.bsize);
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		buf = (unsigned char *) malloc ( bufsize );
		if ( buf == NULL )
		{
# ifdef HAVE_ERRNO_H
			error = errno;
# else
			error = 12L;	/* ENOMEM */
# endif
			fclose (journal_fp);
			wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
			ret_unrm = WFS_MALLOC;
			if ( sig_recvd != 0 )
			{
				ret_unrm = WFS_SIGNAL;
			}
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return ret_unrm;
		}

		nblocks = LOGPNTOB (LOGSUPER_B) + LOGPSIZE + total_size / journal.bsize;
		/* skip the superblock, because we need its old UUID */
		for ( block = LOGPNTOB (LOGSUPER_B) + LOGPSIZE; block < nblocks; block++ )
		{
			if ( ret_unrm == WFS_SUCCESS )
			{
				ret_unrm = wfs_jfs_wipe_block (wfs_fs, block,
					buf, bufsize, journal_fp);
			}
			else
			{
				wfs_jfs_wipe_block (wfs_fs, block, buf,
					bufsize, journal_fp);
			}
		}
		free (buf);
		/* format a new journal */
		block = LOGPNTOB (LOGSUPER_B); /* starting block of the journal */
		jfs_logform (journal_fp, jfs->super.s_bsize, jfs->super.s_l2bsize,
			jfs->super.s_flag, block / jfs->super.s_bsize,
			(journal.size * LOGPSIZE)/jfs->super.s_bsize, journal.uuid,
			journal.label);
		fclose (journal_fp);
	}

	wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	if ( sig_recvd != 0 )
	{
		return WFS_SIGNAL;
	}
	return ret_unrm;
}
#endif /* WFS_WANT_UNRM */


/* ======================================================================== */

/**
 * Opens a JFS filesystem on the given device.
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
wfs_jfs_open_fs (
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
	int res = 0;
	wfs_errcode_t error = 0;
	struct wfs_jfs * jfs;
	wfs_errcode_t * error_ret = NULL;

	if ( wfs_fs == NULL )
	{
		return WFS_BADPARAM;
	}
	error_ret = (wfs_errcode_t *) wfs_fs->fs_error;
	if ( wfs_fs->fsname == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}

	wfs_fs->whichfs = WFS_CURR_FS_NONE;
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	jfs = (struct wfs_jfs *) malloc (sizeof (struct wfs_jfs));
	if ( jfs == NULL )
	{
#ifdef HAVE_ERRNO_H
		error = errno;
#else
		error = 12L;	/* ENOMEM */
#endif
		return WFS_MALLOC;
	}
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	jfs->fs = fopen ( wfs_fs->fsname, "r+b" );
	if ( jfs->fs == NULL )
	{
#ifdef HAVE_ERRNO_H
		error = errno;
#else
		error = 1L;	/* EPERM */
#endif
		ret = WFS_OPENFS;
		free (jfs);
	}
	else
	{
		rewind (jfs->fs);
		res = ujfs_get_superblk (jfs->fs, &(jfs->super), 1);
		if ( res != 0 )
		{
			error = res;
			fclose (jfs->fs);
			jfs->fs = NULL;
			free (jfs);
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_OPENFS;
		}
		res = ujfs_validate_super (&(jfs->super));
		if ( res != 0 )
		{
			error = res;
			fclose (jfs->fs);
			jfs->fs = NULL;
			free (jfs);
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_OPENFS;
		}
		wfs_fs->whichfs = WFS_CURR_FS_JFS;
		ret = WFS_SUCCESS;
		wfs_fs->fs_backend = jfs;
	}
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return ret;
}

/* ======================================================================== */

/**
 * Checks if the given JFS filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_jfs_chk_mount (
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
 * Closes the JFS filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_jfs_close_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs;
#endif
{
	int res = 0;
	wfs_errcode_t error = 0;
	struct wfs_jfs * jfs;
	wfs_errcode_t * error_ret;

	jfs = (struct wfs_jfs *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( jfs != NULL )
	{
		if ( jfs->fs != NULL )
		{
#ifdef HAVE_ERRNO_H
			errno = 0;
#endif
			res = fclose (jfs->fs);
			free (jfs);
			if ( res != 0 )
			{
#ifdef HAVE_ERRNO_H
				error = errno;
#else
				error = 9L;	/* EBADF */
#endif
				if ( error_ret != NULL )
				{
					*error_ret = error;
				}
				return WFS_FSCLOSE;
			}
		}
		else
		{
			free (jfs);
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_BADPARAM;
		}
	}
	else
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return WFS_SUCCESS;
}

/* ======================================================================== */

/**
 * Checks if the JFS filesystem has errors.
 * \param wfs_fs The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_jfs_check_err (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs )
#else
	wfs_fs )
	wfs_fsid_t wfs_fs;
#endif
{
	int res = 0;
	struct wfs_jfs * jfs;

	jfs = (struct wfs_jfs *) wfs_fs.fs_backend;
	if ( jfs == NULL )
	{
		return 1;
	}
	if ( (jfs->super.s_state & FM_DIRTY) == FM_DIRTY )
	{
		res++;
	}
	if ( (jfs->super.s_state & FM_LOGREDO) == FM_LOGREDO )
	{
		res++;
	}
	if ( (jfs->super.s_state & FM_EXTENDFS) == FM_EXTENDFS )
	{
		res++;
	}
	return res;
}

/* ======================================================================== */

/**
 * Checks if the JFS filesystem is dirty (has unsaved changes).
 * \param wfs_fs The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_jfs_is_dirty (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs )
#else
	wfs_fs )
	wfs_fsid_t wfs_fs;
#endif
{
	int res = 0;
	struct wfs_jfs * jfs;

	jfs = (struct wfs_jfs *) wfs_fs.fs_backend;
	if ( jfs == NULL )
	{
		return 1;
	}
	if ( (jfs->super.s_state & FM_DIRTY) == FM_DIRTY )
	{
		res++;
	}
	return res;
}

/* ======================================================================== */

/**
 * Flushes the JFS filesystem.
 * \param wfs_fs The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_jfs_flush_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs;
#endif
{
	int wfs_err;
	struct wfs_jfs * jfs;
	wfs_errcode_t * error_ret;

	jfs = (struct wfs_jfs *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( jfs != NULL )
	{
		if ( jfs->fs != NULL )
		{
			wfs_err = ujfs_flush_dev (jfs->fs);
			if ( error_ret != NULL )
			{
				*error_ret = (wfs_errcode_t)wfs_err;
			}
		}
		else
		{
			return WFS_BADPARAM;
		}
	}
	else
	{
		return WFS_BADPARAM;
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
void wfs_jfs_print_version (
#ifdef WFS_ANSIC
	void
#endif
)
{
	printf ( "JFS: <?>\n");
}

/* ======================================================================== */

/**
 * Get the preferred size of the error variable.
 * \return the preferred size of the error variable.
 */
size_t wfs_jfs_get_err_size (
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
void wfs_jfs_init (
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
void wfs_jfs_deinit (
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
wfs_jfs_show_error (
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
