/*
 * A program for secure cleaning of free space on filesystems.
 *	-- JFS file system-specific functions.
 *
 * Copyright (C) 2010-2011 Bogdan Drozdowski, bogdandr (at) op.pl
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

/* redefine the inline sig function from hfsp, each time with a different name */
#define sig(a,b,c,d) wfs_jfs_sig(a,b,c,d)
#include "wipefreespace.h"

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

/* ============================================================= */
/* JFS external symbols, but declared nowhere. */
extern int ujfs_flush_dev PARAMS ((FILE *fp));
extern int ujfs_get_dev_size PARAMS ((FILE *device, int64_t *size));
extern int ujfs_get_superblk PARAMS ((FILE *fp, struct superblock *sb, int32_t is_primary));
extern int ujfs_rw_diskblocks PARAMS ((FILE *dev_ptr, int64_t disk_offset,
	int32_t disk_count, void *data_buffer, int32_t mode));
extern void ujfs_swap_dbmap PARAMS ((struct dbmap *dbm_t));
extern int ujfs_validate_super PARAMS ((struct superblock *sb));
extern FILE * walk_dir PARAMS ((char *path, uuid_t uuid,
	int is_label, int is_log, int *in_use));
extern void ujfs_swap_logsuper PARAMS ((struct logsuper *));
extern int jfs_logform PARAMS ((FILE *fp, int aggr_blk_size, int s_l2bsize,
	uint s_flag, int64_t log_start, int log_len, uuid_t uuid, char *label));

#if __BYTE_ORDER == __BIG_ENDIAN
extern void ujfs_swap_logsuper PARAMS ((struct logsuper *));
extern void ujfs_swap_dmap PARAMS ((struct dmap *));
#endif
#ifndef LOGPNTOB
# define LOGPNTOB(x)  ((x)<<L2LOGPSIZE)
#endif

/* ============================================================= */
/* JFS internal symbols, but used by the library. */
char log_device[1];

int v_fsck_send_msg PARAMS ((int msg_num , const char *file_name, int line_number, ... ));
int alloc_wrksp PARAMS ((unsigned length, int dynstg_object, int for_logredo, void **addr_wrksp_ptr ));

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
static int WFS_ATTR ((warn_unused_result)) is_block_free PARAMS ((
	const int64_t block, struct dmap * * const map, const int64_t nmaps));
# endif

/**
 * Checks if the given block is free (unused).
 * \param block The block number to check.
 * \return 0 if the block is used, 1 if unused (free).
 */
static int WFS_ATTR ((warn_unused_result))
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

	if ( (block < 0) || (map == NULL) || (nmaps == 0) ) return 0;

	dmap_index = (int)(block / BPERDMAP);
	blk_in_dmap = (int)(block - dmap_index * BPERDMAP);
	dmap_part = blk_in_dmap >> L2DBWORD;
	dmap_bit = blk_in_dmap - (dmap_part << L2DBWORD);

	if ( dmap_index >= nmaps ) return 0;
	if ( map[dmap_index] == NULL ) return 0;

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

#if (defined WFS_WANT_WFS) || (defined WFS_WANT_UNRM)
# ifndef WFS_ANSIC
static size_t WFS_ATTR ((warn_unused_result)) wfs_jfs_get_block_size PARAMS ((const wfs_fsid_t FS));
# endif

/**
 * Returns the buffer size needed to work on the
 *	smallest physical unit on a JFS filesystem.
 * \param FS The filesystem.
 * \return Block size on the filesystem.
 */
static size_t WFS_ATTR ((warn_unused_result))
wfs_jfs_get_block_size (
# ifdef WFS_ANSIC
	const wfs_fsid_t FS )
# else
	FS)
	const wfs_fsid_t FS;
# endif
{
	return (size_t)(FS.jfs.super.s_bsize);
}

# ifndef WFS_ANSIC
static errcode_enum wfs_jfs_wipe_block PARAMS ((const wfs_fsid_t FS, const int64_t blocknum,
	unsigned char * const buf, const size_t bufsize, error_type * const error, FILE * fp));
# endif

/**
 * Wipes the given block.
 * \param blocknum The number of the block to wipe.
 */
static errcode_enum
wfs_jfs_wipe_block (
# ifdef WFS_ANSIC
	const wfs_fsid_t FS, const int64_t blocknum,
	unsigned char * const buf, const size_t bufsize,
	error_type * const error, FILE * fp)
# else
	FS, blocknum, buf, bufsize, error, fp)
	const wfs_fsid_t FS;
	const int64_t blocknum;
	unsigned char * buf;
	size_t bufsize;
	error_type * const error;
	FILE * fp;
# endif
{
	unsigned int j;
	int selected[NPAT];
	int res;

	if ( (buf == NULL) || (fp == NULL) )
	{
		if ( sig_recvd != 0 ) return WFS_SIGNAL;
		return WFS_BADPARAM;
	}

	for ( j = 0; (j < npasses) && (sig_recvd == 0); j++ )
	{

		fill_buffer ( j, buf, bufsize, selected, FS );
		if ( sig_recvd != 0 )
		{
			break;
		}
		res = ujfs_rw_diskblocks (fp, blocknum * wfs_jfs_get_block_size (FS),
			(int32_t)bufsize, buf, PUT);
		if ( res != 0 )
		{
			break;
		}
		/* Flush after each writing, if more than 1 overwriting needs to be done.
		Allow I/O bufferring (efficiency), if just one pass is needed. */
		if ( (npasses > 1) && (sig_recvd == 0) )
		{
			if ( error != NULL )
			{
				error->errcode.gerror = ujfs_flush_dev (fp);
			}
			else
			{
				ujfs_flush_dev (fp);
			}
		}
	}
	if ( j < npasses )
	{
		if ( sig_recvd != 0 ) return WFS_SIGNAL;
		return WFS_BLKWR;
	}
	if ( (FS.zero_pass != 0) && (sig_recvd == 0) )
	{
		/* last pass with zeros: */
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
			res = ujfs_rw_diskblocks (fp, blocknum * wfs_jfs_get_block_size (FS),
				(int32_t)bufsize, buf, PUT);
			if ( res != 0 )
			{
				if ( sig_recvd != 0 ) return WFS_SIGNAL;
				return WFS_BLKWR;
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (npasses > 1) && (sig_recvd == 0) )
			{
				if ( error != NULL )
				{
					error->errcode.gerror = ujfs_flush_dev (fp);
				}
				else
				{
					ujfs_flush_dev (fp);
				}
			}
		}
	}
	if ( sig_recvd != 0 ) return WFS_SIGNAL;
	return WFS_SUCCESS;
}
#endif /* (defined WFS_WANT_WFS) || (defined WFS_WANT_UNRM) */

#ifdef WFS_WANT_PART
/**
 * Wipes the free space in partially used blocks on the given JFS filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_jfs_wipe_part (
# ifdef WFS_ANSIC
	wfs_fsid_t FS, error_type * const error WFS_ATTR ((unused)) )
# else
	FS, error )
	wfs_fsid_t FS;
	error_type * const error WFS_ATTR ((unused));
# endif
{
	errcode_enum ret_part = WFS_SUCCESS;
	unsigned int prev_percent = 0;
	if ( FS.jfs.fs == NULL )
	{
		show_progress (PROGRESS_PART, 100, &prev_percent);
		if ( sig_recvd != 0 ) return WFS_SIGNAL;
		return WFS_BADPARAM;
	}
	/* The library doesn't provide any method to search or open directories/files. */
	show_progress (PROGRESS_PART, 100, &prev_percent);
	if ( sig_recvd != 0 ) return WFS_SIGNAL;
	return ret_part;
}
#endif /* WFS_WANT_PART */

#ifdef WFS_WANT_WFS
/**
 * Wipes the free space on the given JFS filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_jfs_wipe_fs (
# ifdef WFS_ANSIC
	wfs_fsid_t FS, error_type * const error )
# else
	FS, error )
	wfs_fsid_t FS;
	error_type * const error;
# endif
{
	errcode_enum ret_wfs = WFS_SUCCESS;
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

	if ( FS.jfs.fs == NULL )
	{
		show_progress (PROGRESS_WFS, 100, &prev_percent);
		return WFS_BADPARAM;
	}

	bufsize = wfs_jfs_get_block_size (FS);
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	buf = (unsigned char *) malloc ( bufsize );
	if ( buf == NULL )
	{
		if ( error != NULL )
		{
# ifdef HAVE_ERRNO_H
			error->errcode.gerror = errno;
# else
			error->errcode.gerror = 12L;	/* ENOMEM */
# endif
		}
		show_progress (PROGRESS_WFS, 100, &prev_percent);
		return WFS_MALLOC;
	}

	res = ujfs_get_dev_size (FS.jfs.fs, &total_size);
	if ( (res != 0) || (total_size <= 0) )
	{
		if ( error != NULL )
		{
			error->errcode.gerror = WFS_BLBITMAPREAD;
		}
		show_progress (PROGRESS_WFS, 100, &prev_percent);
		free (buf);
		return WFS_BLBITMAPREAD;
	}
	nblocks = total_size / FS.jfs.super.s_bsize;
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
		if ( error != NULL )
		{
			error->errcode.gerror = WFS_BLBITMAPREAD;
		}
		show_progress (PROGRESS_WFS, 100, &prev_percent);
		free (buf);
		return WFS_BLBITMAPREAD;
	}
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	block_map = (struct dmap **) malloc ((size_t)ndmaps * sizeof (struct dmap *));
	if ( block_map == NULL )
	{
		if ( error != NULL )
		{
# ifdef HAVE_ERRNO_H
			error->errcode.gerror = errno;
# else
			error->errcode.gerror = 12L;    /* ENOMEM */
# endif
		}
		show_progress (PROGRESS_WFS, 100, &prev_percent);
		free (buf);
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
			if ( error != NULL )
			{
# ifdef HAVE_ERRNO_H
				error->errcode.gerror = errno;
# else
				error->errcode.gerror = 12L;    /* ENOMEM */
# endif
			}
			start += PSIZE;
			continue;
		}
		res = ujfs_rw_diskblocks (FS.jfs.fs, start,
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
		for ( j = 0; (j < block_map[i]->nblocks) && (sig_recvd == 0); j++ )
		{
			if ( is_block_free (block_map[i]->start + j, block_map, ndmaps) == 1 )
			{
				/* wipe the block here */
				if ( ret_wfs == WFS_SUCCESS )
				{
					ret_wfs = wfs_jfs_wipe_block (FS, block_map[i]->start + j,
						buf, bufsize, error, FS.jfs.fs);
				}
				else
				{
					wfs_jfs_wipe_block (FS, block_map[i]->start + j,
						buf, bufsize, error, FS.jfs.fs);
				}
				/* update the progress: */
				show_progress (PROGRESS_WFS, (unsigned int)((i*100)/ndmaps
					+ (j*100)/block_map[i]->nblocks/ndmaps), &prev_percent);
			}
		}
	}
	show_progress (PROGRESS_WFS, 100, &prev_percent);
	for ( i = 0; i < ndmaps; i++ )
	{
		if ( block_map[i] != NULL ) free (block_map[i]);
	}
	free (block_map);
	free (buf);
	if ( sig_recvd != 0 ) return WFS_SIGNAL;
	return ret_wfs;
}
#endif /* WFS_WANT_WFS */

#ifdef WFS_WANT_UNRM
/**
 * Starts recursive directory search for deleted inodes
 *	and undelete data on the given JFS filesystem.
 * \param FS The filesystem.
 * \param node Filesystem element at which to start.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_jfs_wipe_unrm (
# ifdef WFS_ANSIC
	wfs_fsid_t FS, const fselem_t node WFS_ATTR ((unused)), error_type * const error )
# else
	FS, node, error )
	wfs_fsid_t FS;
	const fselem_t node WFS_ATTR ((unused));
	error_type * const error;
# endif
{
	errcode_enum ret_unrm = WFS_SUCCESS;
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

	unsigned int prev_percent = 0;
	if ( FS.jfs.fs == NULL )
	{
		show_progress (PROGRESS_UNRM, 100, &prev_percent);
		return WFS_BADPARAM;
	}

	/* The library doesn't provide any method to search or open directories/files,
	   so wipe only the journal (log).*/
	if ( (FS.jfs.super.s_flag & JFS_INLINELOG) == JFS_INLINELOG )
	{
		/* journal on the same device */
		block = (addressPXD (&(FS.jfs.super.s_logpxd))
			<< FS.jfs.super.s_l2bsize) + LOGPSIZE;
		res = ujfs_rw_diskblocks (FS.jfs.fs, block,
			sizeof (struct logsuper) /*LOGPSIZE*/, &journal, GET);
		if (res != 0)
		{
			show_progress (PROGRESS_UNRM, 100, &prev_percent);
			if ( sig_recvd != 0 ) return WFS_SIGNAL;
			return WFS_OPENFS;
		}
# if __BYTE_ORDER == __BIG_ENDIAN
		ujfs_swap_logsuper (&journal);
# endif
		if ( journal.magic != LOGMAGIC )
		{
			show_progress (PROGRESS_UNRM, 100, &prev_percent);
			if ( sig_recvd != 0 ) return WFS_SIGNAL;
			return WFS_OPENFS;
		}
		bufsize = LOGPSIZE;
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		buf = (unsigned char *) malloc ( bufsize );
		if ( buf == NULL )
		{
			if ( error != NULL )
			{
# ifdef HAVE_ERRNO_H
				error->errcode.gerror = errno;
# else
				error->errcode.gerror = 12L;	/* ENOMEM */
# endif
			}
			show_progress (PROGRESS_UNRM, 100, &prev_percent);
			if ( sig_recvd != 0 ) return WFS_SIGNAL;
			return WFS_MALLOC;
		}

		block += LOGPSIZE; /* skip the superblock, because we need its old UUID */
		for ( i = 0; i < journal.size; i++ )
		{
			/* NOTE: not the same block number for FS.jfs.fs and the journal. */
			if ( ret_unrm == WFS_SUCCESS )
			{
				ret_unrm = wfs_jfs_wipe_block (FS, block + i, buf, bufsize, error, FS.jfs.fs);
			}
			else
			{
				wfs_jfs_wipe_block (FS, block + i, buf, bufsize, error, FS.jfs.fs);
			}
		}
		free (buf);
		/* format a new journal: */
		jfs_logform (FS.jfs.fs, FS.jfs.super.s_bsize, FS.jfs.super.s_l2bsize,
			FS.jfs.super.s_flag, (block - LOGPSIZE)/FS.jfs.super.s_bsize,
			(journal.size * LOGPSIZE)/FS.jfs.super.s_bsize, journal.uuid,
			journal.label);
	}
	else
	{
		/* journal on an external device - FS.jfs.super->s_loguuid has the UUID */
		journal_fp = walk_dir ("/dev", FS.jfs.super.s_loguuid,
			0 /*is_label*/, 1 /*is_log*/, &journal_in_use);
		if ( journal_fp == NULL )
		{
			/* journal device not found under /dev */
			show_progress (PROGRESS_UNRM, 100, &prev_percent);
			if ( sig_recvd != 0 ) return WFS_SIGNAL;
			return WFS_MNTRW;
		}
		if ( journal_in_use != 0 )
		{
			fclose (journal_fp);
			show_progress (PROGRESS_UNRM, 100, &prev_percent);
			if ( sig_recvd != 0 ) return WFS_SIGNAL;
			return WFS_MNTRW;
		}
		res = ujfs_rw_diskblocks (journal_fp, (int64_t)(LOGPNTOB (LOGSUPER_B)),
			sizeof (struct logsuper), &journal, GET);
		if (res != 0)
		{
			/* can't read superblock */
			fclose (journal_fp);
			show_progress (PROGRESS_UNRM, 100, &prev_percent);
			if ( sig_recvd != 0 ) return WFS_SIGNAL;
			return WFS_OPENFS;
		}
# if __BYTE_ORDER == __BIG_ENDIAN
		ujfs_swap_logsuper (&journal);
# endif
		if ( journal.magic != LOGMAGIC )
		{
			fclose (journal_fp);
			show_progress (PROGRESS_UNRM, 100, &prev_percent);
			if ( sig_recvd != 0 ) return WFS_SIGNAL;
			return WFS_OPENFS;
		}

		res = ujfs_get_dev_size (FS.jfs.fs, &total_size);
		if ( (res != 0) || (total_size <= 0) )
		{
			if ( error != NULL )
			{
				error->errcode.gerror = WFS_BLBITMAPREAD;
			}
			fclose (journal_fp);
			show_progress (PROGRESS_UNRM, 100, &prev_percent);
			if ( sig_recvd != 0 ) return WFS_SIGNAL;
			return WFS_BLBITMAPREAD;
		}
		bufsize = (size_t)(journal.bsize);
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		buf = (unsigned char *) malloc ( bufsize );
		if ( buf == NULL )
		{
			if ( error != NULL )
			{
# ifdef HAVE_ERRNO_H
				error->errcode.gerror = errno;
# else
				error->errcode.gerror = 12L;	/* ENOMEM */
# endif
			}
			fclose (journal_fp);
			show_progress (PROGRESS_UNRM, 100, &prev_percent);
			if ( sig_recvd != 0 ) return WFS_SIGNAL;
			return WFS_MALLOC;
		}

		nblocks = total_size / journal.bsize;
		/* skip the superblock, because we need its old UUID */
		for ( block = LOGPNTOB (LOGSUPER_B) + LOGPSIZE; block < nblocks; block++ )
		{
			if ( ret_unrm == WFS_SUCCESS )
			{
				ret_unrm = wfs_jfs_wipe_block (FS, block, buf, bufsize, error, journal_fp);
			}
			else
			{
				wfs_jfs_wipe_block (FS, block, buf, bufsize, error, journal_fp);
			}
		}
		free (buf);
		/* format a new journal */
		jfs_logform (journal_fp, FS.jfs.super.s_bsize, FS.jfs.super.s_l2bsize,
			FS.jfs.super.s_flag, (block - LOGPSIZE)/FS.jfs.super.s_bsize,
			(journal.size * LOGPSIZE)/FS.jfs.super.s_bsize, journal.uuid,
			journal.label);
		fclose (journal_fp);
	}

	show_progress (PROGRESS_UNRM, 100, &prev_percent);
	if ( sig_recvd != 0 ) return WFS_SIGNAL;
	return ret_unrm;
}
#endif /* WFS_WANT_UNRM */


/**
 * Opens a JFS filesystem on the given device.
 * \param dev_name Device name, like /dev/hdXY
 * \param FS Pointer to where the result will be put.
 * \param whichfs Pointer to an int saying which fs is curently in use.
 * \param data Pointer to fsdata structure containing information
 *	which may be needed to open the filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result))
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_jfs_open_fs (
#ifdef WFS_ANSIC
	const char * const dev_name, wfs_fsid_t * const FS, CURR_FS * const whichfs,
	const fsdata * const data WFS_ATTR ((unused)), error_type * const error )
#else
	dev_name, FS, whichfs, data, error )
	const char * const dev_name;
	wfs_fsid_t * const FS;
	CURR_FS * const whichfs;
	const fsdata * const data WFS_ATTR ((unused));
	error_type * const error;
#endif
{
	errcode_enum ret = WFS_OPENFS;
	int res = 0;

	if ((dev_name == NULL) || (FS == NULL) || (whichfs == NULL))
	{
		return WFS_BADPARAM;
	}

	*whichfs = CURR_NONE;
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	FS->jfs.fs = fopen ( dev_name, "r+b" );
	if ( FS->jfs.fs == NULL )
	{
		if ( error != NULL )
		{
#ifdef HAVE_ERRNO_H
			error->errcode.gerror = errno;
#else
			error->errcode.gerror = 1L;	/* EPERM */
#endif
		}
		ret = WFS_OPENFS;
	}
	else
	{
		rewind (FS->jfs.fs);
		res = ujfs_get_superblk (FS->jfs.fs, &(FS->jfs.super), 1);
		if ( res != 0 )
		{
			if ( error != NULL )
			{
				error->errcode.gerror = res;
			}
			fclose (FS->jfs.fs);
			FS->jfs.fs = NULL;
			return WFS_OPENFS;
		}
		res = ujfs_validate_super (&(FS->jfs.super));
		if ( res != 0 )
		{
			if ( error != NULL )
			{
				error->errcode.gerror = res;
			}
			fclose (FS->jfs.fs);
			FS->jfs.fs = NULL;
			return WFS_OPENFS;
		}
		*whichfs = CURR_JFS;
		ret = WFS_SUCCESS;
	}
	return ret;
}

/**
 * Checks if the given JFS filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result))
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_jfs_chk_mount (
#ifdef WFS_ANSIC
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
 * Closes the JFS filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_jfs_close_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t FS, error_type * const error )
#else
	FS, error )
	wfs_fsid_t FS;
	error_type * const error;
#endif
{
	int res = 0;

	if ( FS.jfs.fs != NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		res = fclose (FS.jfs.fs);
		if ( res != 0 )
		{
			if ( error != NULL )
			{
#ifdef HAVE_ERRNO_H
				error->errcode.gerror = errno;
#else
				error->errcode.gerror = 9L;	/* EBADF */
#endif
			}
			return WFS_FSCLOSE;
		}
	}
	else
	{
		return WFS_BADPARAM;
	}
	FS.jfs.fs = NULL;
	return WFS_SUCCESS;
}

/**
 * Checks if the JFS filesystem has errors.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_jfs_check_err (
#ifdef WFS_ANSIC
	wfs_fsid_t FS )
#else
	FS )
	wfs_fsid_t FS;
#endif
{
	int res = 0;
	if ( (FS.jfs.super.s_state & FM_DIRTY) == FM_DIRTY )
	{
		res++;
	}
	if ( (FS.jfs.super.s_state & FM_LOGREDO) == FM_LOGREDO )
	{
		res++;
	}
	if ( (FS.jfs.super.s_state & FM_EXTENDFS) == FM_EXTENDFS )
	{
		res++;
	}
	return res;
}

/**
 * Checks if the JFS filesystem is dirty (has unsaved changes).
 * \param FS The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_jfs_is_dirty (
#ifdef WFS_ANSIC
	wfs_fsid_t FS )
#else
	FS )
	wfs_fsid_t FS;
#endif
{
	int res = 0;
	if ( (FS.jfs.super.s_state & FM_DIRTY) == FM_DIRTY )
	{
		res++;
	}
	return res;
}

/**
 * Flushes the JFS filesystem.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_jfs_flush_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t FS, error_type * const error )
#else
	FS, error )
	wfs_fsid_t FS;
	error_type * const error;
#endif
{
	if ( FS.jfs.fs != NULL )
	{
		if ( error != NULL )
		{
			error->errcode.gerror = ujfs_flush_dev (FS.jfs.fs);
		}
		else
		{
			ujfs_flush_dev (FS.jfs.fs);
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
