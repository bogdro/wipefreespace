/*
 * A program for secure cleaning of free space on filesystems.
 *	-- OCFS file system-specific functions.
 *
 * Copyright (C) 2011-2012 Bogdan Drozdowski, bogdandr (at) op.pl
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
#define sig(a,b,c,d) wfs_ocfs_sig(a,b,c,d)
#include "wipefreespace.h"

#if (defined HAVE_OCFS2_OCFS2_H) && (defined HAVE_LIBOCFS2)
# include <ocfs2/ocfs2.h>
#else
# if (defined HAVE_OCFS2_H) && (defined HAVE_LIBOCFS2)
#  include <ocfs2.h>
# else
#  error Something wrong. OCFS requested, but ocfsp2.h or libocfs2 missing.
# endif
#endif

#include "wfs_ocfs.h"
#include "wfs_signal.h"
#include "wfs_util.h"
#include "wfs_wiping.h"

struct wfs_ocfs_block_data
{
	uint64_t total;
	struct ocfs2_dinode *inode;
	wfs_wipedata_t wd;
};

/* ============================================================= */

#ifndef WFS_ANSIC
static size_t WFS_ATTR ((warn_unused_result)) wfs_ocfs_get_block_size WFS_PARAMS ((const wfs_fsid_t FS));
#endif

/**
 * Returns the buffer size needed to work on the
 *	smallest physical unit on a OCFS filesystem.
 * \param FS The filesystem.
 * \return Block size on the filesystem.
 */
static size_t WFS_ATTR ((warn_unused_result))
wfs_ocfs_get_block_size (
#ifdef WFS_ANSIC
	const wfs_fsid_t FS )
#else
	FS)
	const wfs_fsid_t FS;
#endif
{
	if ( FS.ocfs2 == NULL )
	{
		return 0;
	}
	return (size_t)FS.ocfs2->fs_clustersize;
}

/* ============================================================= */

#ifdef WFS_WANT_PART

# ifndef WFS_ANSIC
static int wfs_ocfs_wipe_part_blocks WFS_PARAMS ((ocfs2_filesys *fs, uint64_t blkno,
	uint64_t bcount, uint16_t ext_flags, void *priv_data));
# endif

static int wfs_ocfs_wipe_part_blocks (
# ifdef WFS_ANSIC
	ocfs2_filesys *fs, uint64_t blkno, uint64_t bcount WFS_ATTR ((unused)),
	uint16_t ext_flags WFS_ATTR ((unused)), void *priv_data)
# else
	fs, blkno, bcount, ext_flags, priv_data)
	ocfs2_filesys *fs;
	uint64_t blkno;
	uint64_t bcount WFS_ATTR ((unused));
	uint16_t ext_flags WFS_ATTR ((unused));
	void *priv_data;
# endif
{
	wfs_errcode_t ret_part = WFS_SUCCESS;
	errcode_t err;
	struct wfs_ocfs_block_data * bd = (struct wfs_ocfs_block_data *)priv_data;
	wfs_error_type_t error;
	int changed = 0;
	int selected[WFS_NPAT];
	size_t to_wipe;
	unsigned int offset;
	unsigned int j;

	if ( (fs == NULL) || (bd == NULL) )
	{
		/* proceed with the next element */
		return 0;
	}

	if ( (bd->wd.filesys.ocfs2 == NULL) || (bd->inode == NULL) )
	{
		/* proceed with the next element */
		return 0;
	}
	if ( (bd->total < bd->inode->i_size)
		&& (bd->total + bd->wd.filesys.ocfs2->fs_blocksize >= bd->inode->i_size) )
	{
		/* this is the last block */
		to_wipe = (size_t)((bd->total + bd->wd.filesys.ocfs2->fs_blocksize
			- bd->inode->i_size) & 0x0FFFFFFFF);
		offset = (unsigned int)((bd->inode->i_size % bd->wd.filesys.ocfs2->fs_blocksize) & 0x0FFFFFFFF);
		if ( (to_wipe != 0) && (offset != bd->wd.filesys.ocfs2->fs_blocksize) )
		{
			err = io_read_block_nocache(bd->wd.filesys.ocfs2->fs_io, (int64_t)blkno, 1,
				(char *)bd->wd.buf);
			if ( err == 0 )
			{
				for ( j = 0; (j < bd->wd.filesys.npasses) && (sig_recvd == 0); j++ )
				{
					fill_buffer ( j, &bd->wd.buf[offset], to_wipe,
						selected, bd->wd.filesys );/* buf OK */
					if ( sig_recvd != 0 )
					{
						break;
					}
					/* writing modified cluster here: */
					err = io_write_block_nocache (bd->wd.filesys.ocfs2->fs_io,
						/* blkno */ (int64_t)blkno,
						/* count */ 1,
						(char *)bd->wd.buf);
					if ( err != 0 )
					{
						ret_part = WFS_BLKWR;
					}
					/* Flush after each writing, if more than 1 overwriting needs to be done.
					Allow I/O bufferring (efficiency), if just one pass is needed. */
					if ( (bd->wd.filesys.npasses > 1) && (sig_recvd == 0) )
					{
						error.errcode.gerror = wfs_ocfs_flush_fs ( bd->wd.filesys, &error );
					}
				}
				if ( (bd->wd.filesys.zero_pass != 0) && (sig_recvd == 0) )
				{
					/* last pass with zeros: */
# ifdef HAVE_MEMSET
					memset ( &bd->wd.buf[offset], 0, to_wipe );
# else
					for ( j = 0; j < to_wipe; j++ )
					{
						bd->wd.buf[offset+j] = '\0';
					}
# endif
					if ( sig_recvd == 0 )
					{
						/* writing modified cluster here: */
						err = io_write_block_nocache (bd->wd.filesys.ocfs2->fs_io,
							(int64_t)blkno,
							1, (char *)bd->wd.buf);
						if ( err != 0 )
						{
							ret_part = WFS_BLKWR;
						}
						/* Flush after each writing, if more than 1 overwriting needs to be done.
						Allow I/O bufferring (efficiency), if just one pass is needed. */
						if ( (bd->wd.filesys.npasses > 1) && (sig_recvd == 0) )
						{
							error.errcode.e2error = wfs_ocfs_flush_fs ( bd->wd.filesys,
								&error );
						}
					}
				}
				changed = 1;
			}
		}
	}
	bd->total += bd->wd.filesys.ocfs2->fs_blocksize;
	if ( (ret_part != WFS_SUCCESS) || (sig_recvd != 0) )
	{
		return OCFS2_BLOCK_ABORT;
	}
	else if ( changed != 0 )
	{
		return 0;/*OCFS2_BLOCK_CHANGED;*/
	}
	else
	{
		/* proceed with the next element */
		return 0;
	}
}

/* ============================================================= */

/**
 * Wipes the free space in partially used blocks on the given OCFS filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_ocfs_wipe_part (
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
	char * inode_buf;
	errcode_t err;
	struct wfs_ocfs_block_data bd;
	uint64_t blkno;
	struct ocfs2_dinode *dinode;
	ocfs2_inode_scan *iscan;
	size_t cluster_size;
	const size_t sig_len = strlen (OCFS2_INODE_SIGNATURE);
	unsigned int j;
	int selected[WFS_NPAT] = {0};
	size_t to_wipe;
	unsigned int offset;
	wfs_error_type_t error = {CURR_OCFS, {0}};

	if ( FS.ocfs2 == NULL )
	{
		show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	/*err = ocfs2_dir_iterate2(FS.ocfs2, FS.ocfs2->fs_root_blkno,
		OCFS2_DIRENT_FLAG_INCLUDE_EMPTY,
		NULL, &wfs_ocfs_wipe_unrm_dir, &wd);* /
	if ( err != 0 )
	{
		ret_part = WFS_DIRITER;
		if ( error != NULL )
		{
			error->errcode.e2error = err;
		}
	}
	*/

	err = ocfs2_open_inode_scan (FS.ocfs2, &iscan);
	if ( err != 0 )
	{
		error.errcode.e2error = err;
		show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_INOSCAN;
	}

	cluster_size = wfs_ocfs_get_block_size (FS);
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	inode_buf = (char *) malloc ( cluster_size );
	if ( inode_buf == NULL )
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
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	buf = (unsigned char *) malloc ( cluster_size );
	if ( buf == NULL )
	{
# ifdef HAVE_ERRNO_H
		error.errcode.gerror = errno;
# else
		error.errcode.gerror = 12L;	/* ENOMEM */
# endif
		show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		free (inode_buf);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	dinode = (struct ocfs2_dinode *)inode_buf;
	bd.wd.passno = 0;
	bd.wd.filesys = FS;
	bd.wd.total_fs = 0;
	bd.wd.ret_val = 0;
	bd.wd.buf = buf;
	do
	{
		err = ocfs2_get_next_inode (iscan, &blkno, inode_buf);
		if ( err != 0 )
		{
			ret_part = WFS_INOSCAN;
			continue;
		}
		if ( blkno == 0 )
		{
			break;
		}

		/* no signature? skip */
		if ( memcmp (dinode->i_signature, OCFS2_INODE_SIGNATURE, sig_len) != 0 )
		{
			continue;
		}
		ocfs2_swap_inode_to_cpu (FS.ocfs2, dinode);
		/* not a regular file? skip */
		if ( ! S_ISREG (dinode->i_mode))
		{
			continue;
		}
		if ((dinode->i_dyn_features & OCFS2_INLINE_DATA_FL) != 0)
		{
			to_wipe = (size_t)(ocfs2_max_inline_data_with_xattr ((int)FS.ocfs2->fs_blocksize,
				dinode) - (int)((dinode->i_size) & 0x0FFFFFFFF));
			offset = (unsigned int)((dinode->i_size) & 0x0FFFFFFFF);
			if ( (to_wipe != 0) && (offset != FS.ocfs2->fs_blocksize) )
			{
				for ( j = 0; (j < FS.npasses) && (sig_recvd == 0); j++ )
				{
					fill_buffer ( j, &dinode->id2.i_data.id_data[offset], to_wipe,
						selected, FS );/* buf OK */
					if ( sig_recvd != 0 )
					{
						break;
					}
					/* writing modified inode here: */
					err = ocfs2_write_inode (FS.ocfs2, dinode->i_blkno, inode_buf);
					if ( err != 0 )
					{
						error.errcode.e2error = err;
					}
					if ( err != 0 )
					{
						ret_part = WFS_BLKWR;
					}
					/* Flush after each writing, if more than 1 overwriting needs to be done.
					Allow I/O bufferring (efficiency), if just one pass is needed. */
					if ( (FS.npasses > 1) && (sig_recvd == 0) )
					{
						error.errcode.gerror = wfs_ocfs_flush_fs ( FS, &error );
					}
				}
				if ( (FS.zero_pass != 0) && (sig_recvd == 0) )
				{
					/* last pass with zeros: */
# ifdef HAVE_MEMSET
					memset ( &dinode->id2.i_data.id_data[offset], 0, to_wipe );
# else
					for ( j = 0; j < to_wipe; j++ )
					{
						dinode->id2.i_data.id_data[offset+j] = '\0';
					}
# endif
					if ( sig_recvd == 0 )
					{
						/* writing modified inode here: */
						err = ocfs2_write_inode (FS.ocfs2, dinode->i_blkno, inode_buf);
						if ( err != 0 )
						{
							ret_part = WFS_BLKWR;
						}
						/* Flush after each writing, if more than 1 overwriting needs to be done.
						Allow I/O bufferring (efficiency), if just one pass is needed. */
						if ( (FS.npasses > 1) && (sig_recvd == 0) )
						{
							error.errcode.gerror = wfs_ocfs_flush_fs ( FS, &error );
						}
					}
				}
			}
		}
		else
		{
			bd.total = 0;
			bd.inode = dinode;
			err = ocfs2_block_iterate_inode (FS.ocfs2, dinode, 0,
				&wfs_ocfs_wipe_part_blocks, &bd);
		}
		if ( err != 0 )
		{
			ret_part = WFS_INOSCAN;
			continue;
		}

	} while ( sig_recvd == 0 );

	ocfs2_close_inode_scan (iscan);
	free (buf);
	free (inode_buf);

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

/* ============================================================= */

#ifdef WFS_WANT_WFS
/**
 * Wipes the free space on the given OCFS filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_ocfs_wipe_fs (
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
	uint32_t curr_cluster;
	unsigned long int j;
	int selected[WFS_NPAT]= {0};
	unsigned char * buf;
	errcode_t err;
	int is_alloc;
	size_t cluster_size;
	unsigned int blocks_per_cluster;
	wfs_error_type_t error = {CURR_OCFS, {0}};

	if ( FS.ocfs2 == NULL )
	{
		show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}

	cluster_size = wfs_ocfs_get_block_size (FS);
	blocks_per_cluster = (unsigned int)(ocfs2_clusters_to_blocks (FS.ocfs2, 1) & 0x0FFFFFFFF);

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	buf = (unsigned char *) malloc ( cluster_size );
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

	for ( curr_cluster = 0;
		(curr_cluster < FS.ocfs2->fs_clusters) && (sig_recvd == 0); curr_cluster++ )
	{
		is_alloc = 1;
		err = ocfs2_test_cluster_allocated (FS.ocfs2, curr_cluster, &is_alloc);
		if ( err != 0 )
		{
			ret_wfs = WFS_BLBITMAPREAD;
			show_progress (WFS_PROGRESS_WFS, (unsigned int) (curr_cluster/FS.ocfs2->fs_clusters),
				&prev_percent);
			continue;
		}
		if ( is_alloc != 0 )
		{
			show_progress (WFS_PROGRESS_WFS, (unsigned int) (curr_cluster/FS.ocfs2->fs_clusters),
				&prev_percent);
			continue;
		}

		/* cluster is unused - wipe it */
		for ( j = 0; (j < FS.npasses) && (sig_recvd == 0); j++ )
		{

			fill_buffer ( j, buf, cluster_size, selected, FS );/* buf OK */
			if ( sig_recvd != 0 )
			{
		       		break;
			}
			/* writing modified cluster here: */
			err = io_write_block_nocache (FS.ocfs2->fs_io,
				/* blkno */ curr_cluster * blocks_per_cluster,
				/* count */ (int)blocks_per_cluster,
				(char *)buf);
			if ( err != 0 )
			{
				free (buf);
				show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
				if ( error_ret != NULL )
				{
					*error_ret = error;
				}
				return WFS_BLKWR;
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			   Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (FS.npasses > 1) && (sig_recvd == 0) )
			{
				error.errcode.gerror = wfs_ocfs_flush_fs ( FS, &error );
			}
		}
		if ( (FS.zero_pass != 0) && (sig_recvd == 0) )
		{
			/* last pass with zeros: */
# ifdef HAVE_MEMSET
			memset ( buf, 0, cluster_size );
# else
			for ( j=0; j < cluster_size; j++ )
			{
				buf[j] = '\0';
			}
# endif
			if ( sig_recvd == 0 )
			{
				/* writing modified cluster here: */
				err = io_write_block_nocache (FS.ocfs2->fs_io,
					curr_cluster * blocks_per_cluster,
					(int)blocks_per_cluster, (char *)buf);
				if ( err != 0 )
				{
					free (buf);
					show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
					if ( error_ret != NULL )
					{
						*error_ret = error;
					}
					return WFS_BLKWR;
				}
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( (FS.npasses > 1) && (sig_recvd == 0) )
				{
					error.errcode.gerror = wfs_ocfs_flush_fs ( FS, &error );
				}
			}
		}
		show_progress (WFS_PROGRESS_WFS, (unsigned int) ((100*curr_cluster)/FS.ocfs2->fs_clusters),
			&prev_percent);
	}

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

/* ============================================================= */

#ifdef WFS_WANT_UNRM

# ifndef WFS_ANSIC
static int wfs_ocfs_wipe_unrm_dir WFS_PARAMS ((uint64_t dir, int entry, struct ocfs2_dir_entry *dirent,
	uint64_t blocknr, int offset, int blocksize, char *buf, void *priv_data));
# endif

static int wfs_ocfs_wipe_unrm_dir (
# ifdef WFS_ANSIC
	uint64_t dir WFS_ATTR ((unused)), int entry, struct ocfs2_dir_entry *dirent,
	uint64_t blocknr WFS_ATTR ((unused)), int offset WFS_ATTR ((unused)),
	int blocksize WFS_ATTR ((unused)), char *buf WFS_ATTR ((unused)), void *priv_data)
# else
	dir, entry, dirent, blocknr, offset, blocksize, buf, priv_data)
	uint64_t dir WFS_ATTR ((unused));
	int entry;
	struct ocfs2_dir_entry *dirent;
	uint64_t blocknr WFS_ATTR ((unused));
	int offset WFS_ATTR ((unused));
	int blocksize WFS_ATTR ((unused));
	char *buf WFS_ATTR ((unused));
	void *priv_data;
# endif
{
	wfs_errcode_t ret_unrm = WFS_SUCCESS;
	errcode_t err;
	wfs_wipedata_t * wd = (wfs_wipedata_t *)priv_data;
	wfs_error_type_t error;
	int changed = 0;
	int selected[WFS_NPAT];
# ifndef HAVE_MEMSET
	size_t j;
# endif

	if ( (dirent == NULL) || (wd == NULL) )
	{
		/* proceed with the next element */
		return 0;
	}

	if ( (dirent->file_type == OCFS2_FT_DIR) && (dirent->name != NULL) )
	{
		if ( (strncmp (dirent->name, "..", OCFS2_MAX_FILENAME_LEN) != 0) &&
			(strncmp (dirent->name, ".", OCFS2_MAX_FILENAME_LEN) != 0) &&
			(entry != OCFS2_DIRENT_DOT_FILE) &&
			(entry != OCFS2_DIRENT_DOT_DOT_FILE) )
		{
			err = ocfs2_dir_iterate2(wd->filesys.ocfs2, dirent->inode,
				OCFS2_DIRENT_FLAG_INCLUDE_REMOVED, NULL, &wfs_ocfs_wipe_unrm_dir, &wd);
			if ( err != 0 )
			{
				ret_unrm = WFS_DIRITER;
				error.errcode.e2error = err;
			}
		}
	}
	else if ( (entry == OCFS2_DIRENT_DELETED_FILE) && (dirent->name != NULL) )
	{
		if ( (wd->filesys.zero_pass != 0) && (sig_recvd == 0) )
		{
# ifdef HAVE_MEMSET
			memset ( dirent->name, 0, OCFS2_MAX_FILENAME_LEN );
# else
			for ( j=0; j < OCFS2_MAX_FILENAME_LEN; j++ )
			{
				dirent->name[j] = '\0';
			}
# endif
		}
		else
		{
			fill_buffer ( wd->passno, (unsigned char *)dirent->name, OCFS2_MAX_FILENAME_LEN,
				selected, wd->filesys );
		}

		changed = 1;
	}

	if ( (ret_unrm != WFS_SUCCESS) || (sig_recvd != 0) )
	{
		return OCFS2_DIRENT_ABORT;
	}
	else if ( changed != 0 )
	{
		return OCFS2_DIRENT_CHANGED;
	}
	else
	{
		/* proceed with the next element */
		return 0;
	}
}

/* ============================================================= */

/**
 * Starts recursive directory search for deleted inodes
 *	and undelete data on the given OCFS filesystem.
 * \param FS The filesystem.
 * \param node Filesystem element at which to start.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_ocfs_wipe_unrm (
# ifdef WFS_ANSIC
	wfs_fsid_t FS,
	wfs_error_type_t * const error_ret )
# else
	FS, error_ret )
	wfs_fsid_t FS;
	wfs_error_type_t * const error_ret;
# endif
{
	wfs_errcode_t ret_unrm = WFS_SUCCESS;
	unsigned int prev_percent = 0;
	errcode_t err;
	wfs_wipedata_t wd;
	uint64_t curr_block;
	unsigned long int j;
	int selected[WFS_NPAT] = {0};
	unsigned char * buf;
	unsigned char * jbuf;
	size_t cluster_size;
	int i;
	/*uint32_t journal_size_in_clusters;*/
	uint64_t journal_block_numer;
	char jorunal_object_name[20];
	journal_superblock_t *jsb;
	/*ocfs2_fs_options journal_features;*/
	ocfs2_cached_inode *ci = NULL;
	uint64_t contig;
	size_t name_index;
	int si_name_percents;
	wfs_error_type_t error = {CURR_OCFS, {0}};

	if ( FS.ocfs2 == NULL )
	{
		show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}

	wd.passno = 0;
	wd.filesys = FS;
	wd.total_fs = 0;
	wd.ret_val = 0;
	err = ocfs2_dir_iterate2(FS.ocfs2, FS.ocfs2->fs_root_blkno,
		OCFS2_DIRENT_FLAG_INCLUDE_REMOVED, NULL, &wfs_ocfs_wipe_unrm_dir, &wd);
	if ( err != 0 )
	{
		ret_unrm = WFS_DIRITER;
		error.errcode.e2error = err;
	}
	/* journal: */
	cluster_size = wfs_ocfs_get_block_size (FS);

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	buf = (unsigned char *) malloc ( cluster_size );
	if ( buf == NULL )
	{
# ifdef HAVE_ERRNO_H
		error.errcode.gerror = errno;
# else
		error.errcode.gerror = 12L;	/* ENOMEM */
# endif
		show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	for ( i = 0; i < OCFS2_RAW_SB(FS.ocfs2->fs_super)->s_max_slots; i++ )
	{
		if ( ocfs2_system_inodes[JOURNAL_SYSTEM_INODE].si_name == NULL )
		{
			continue;
		}
		si_name_percents = 0;
		for ( name_index = 0; ; name_index++ )
		{
			if ( ocfs2_system_inodes[JOURNAL_SYSTEM_INODE].si_name[name_index] == '\0' )
			{
				break;
			}
			if ( (ocfs2_system_inodes[JOURNAL_SYSTEM_INODE].si_name[name_index] == '%')
				&& (ocfs2_system_inodes[JOURNAL_SYSTEM_INODE].si_name[name_index+1] != '%') )
			{
				si_name_percents++;
			}
		}
		if ( si_name_percents != 1 )
		{
			/* invalid format string, skip */
			continue;
		}

# if (!defined __STRICT_ANSI__) && (defined HAVE_SNPRINTF)
		snprintf (jorunal_object_name, sizeof(jorunal_object_name),
			ocfs2_system_inodes[JOURNAL_SYSTEM_INODE].si_name, i);
# else
		sprintf (jorunal_object_name,
			ocfs2_system_inodes[JOURNAL_SYSTEM_INODE].si_name, i);
# endif
		jorunal_object_name[sizeof(jorunal_object_name)-1] = '\0';
		err = ocfs2_lookup (FS.ocfs2, FS.ocfs2->fs_sysdir_blkno, jorunal_object_name,
			(int)strlen (jorunal_object_name), NULL, &journal_block_numer);
		if ( err != 0 )
		{
			continue;
		}

		err = ocfs2_read_cached_inode (FS.ocfs2, journal_block_numer, &ci);
		if ( err != 0 )
		{
			continue;
		}

		err = ocfs2_extent_map_get_blocks(ci, 0, 1, &journal_block_numer, &contig, NULL);
		if ( err != 0 )
		{
			continue;
		}

		/*err = ocfs2_read_blocks (FS.ocfs2, (int64_t)journal_block_numer, 1, (char *)buf);*/
		err = ocfs2_read_journal_superblock (FS.ocfs2, journal_block_numer, (char *)buf);
		if ( err != 0 )
		{
			continue;
		}

		jsb = (journal_superblock_t *)buf;
		/*ocfs2_swap_journal_superblock (jsb);*/
		if ( jsb->s_header.h_magic != JBD2_MAGIC_NUMBER )
		{
			continue;
		}

		/*ocfs2_swap_journal_superblock (jsb);*/

		/* wipe the journal */
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		jbuf = (unsigned char *) malloc ( (size_t)jsb->s_blocksize );
		if ( jbuf == NULL )
		{
# ifdef HAVE_ERRNO_H
			error.errcode.gerror = errno;
# else
			error.errcode.gerror = 12L;	/* ENOMEM */
# endif
			break;
		}
		/*journal_size_in_clusters = (jsb->s_blocksize * jsb->s_maxlen) >>
			OCFS2_RAW_SB(FS.ocfs2->fs_super)->s_clustersize_bits;*/

		for ( curr_block = journal_block_numer+1;
			(curr_block < journal_block_numer + jsb->s_maxlen) && (sig_recvd == 0); curr_block++ )
		{
			for ( j = 0; (j < FS.npasses) && (sig_recvd == 0); j++ )
			{
				fill_buffer ( j, jbuf, (size_t)jsb->s_blocksize, selected, FS );/* buf OK */
				if ( sig_recvd != 0 )
				{
					break;
				}
				/* writing modified cluster here: */
				err = io_write_block_nocache (FS.ocfs2->fs_io,
					/* blkno */ (int64_t)curr_block,
					/* count */ 1,
					(char *)jbuf);
				if ( err != 0 )
				{
					free (jbuf);
					free (buf);
					show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
					if ( error_ret != NULL )
					{
						*error_ret = error;
					}
					return WFS_BLKWR;
				}
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( (FS.npasses > 1) && (sig_recvd == 0) )
				{
					error.errcode.gerror = wfs_ocfs_flush_fs ( FS, &error );
				}
			}
			if ( (FS.zero_pass != 0) && (sig_recvd == 0) )
			{
				/* last pass with zeros: */
# ifdef HAVE_MEMSET
				memset ( buf, 0, (size_t)jsb->s_blocksize );
# else
				for ( j=0; j < (size_t)jsb->s_blocksize; j++ )
				{
					buf[j] = '\0';
				}
# endif
				if ( sig_recvd == 0 )
				{
					/* writing modified cluster here: */
					err = io_write_block_nocache (FS.ocfs2->fs_io,
						(int64_t)curr_block,
						1, (char *)jbuf);
					if ( err != 0 )
					{
						free (jbuf);
						free (buf);
						show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
						if ( error_ret != NULL )
						{
							*error_ret = error;
						}
						return WFS_BLKWR;
					}
					/* Flush after each writing, if more than 1 overwriting needs to be done.
					Allow I/O bufferring (efficiency), if just one pass is needed. */
					if ( (FS.npasses > 1) && (sig_recvd == 0) )
					{
						error.errcode.gerror = wfs_ocfs_flush_fs ( FS, &error );
					}
				}
			}
			show_progress (WFS_PROGRESS_UNRM,
				(unsigned int) (50+((curr_block - (journal_block_numer+1))*50)/jsb->s_maxlen),
				&prev_percent);
		}

		free (jbuf);
		/* recreate the journal: */
		/*
# ifdef HAVE_MEMSET
		memset ( &journal_features, 0, sizeof (journal_features) );
# else
		for ( j=0; j < sizeof (journal_features); j++ )
		{
			((char*)journal_features)[j] = '\0';
		}
# endif
		journal_features.opt_compat = jsb->s_feature_compat;
		journal_features.opt_incompat = jsb->s_feature_incompat;
		journal_features.opt_ro_compat = jsb->s_feature_ro_compat;

		err = ocfs2_make_journal (FS.ocfs2, journal_block_numer,
			journal_size_in_clusters, &journal_features);
		if ( (error != NULL) && (err != 0) )
		{
			error.errcode.e2error = err;
		}
		*/
		/*ocfs2_swap_journal_superblock (jsb);*/
		err = ocfs2_write_journal_superblock (FS.ocfs2, journal_block_numer, (char *)buf);
		if ( err != 0 )
		{
			error.errcode.e2error = err;
		}

		err = ocfs2_write_cached_inode (FS.ocfs2, ci);
		if ( err != 0 )
		{
			error.errcode.e2error = err;
		}
		ocfs2_free_cached_inode (FS.ocfs2, ci);
	}

	free (buf);
	show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
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


/* ============================================================= */

/**
 * Opens a OCFS filesystem on the given device.
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
wfs_ocfs_open_fs (
#ifdef WFS_ANSIC
	const char * const dev_name, wfs_fsid_t * const FS, wfs_curr_fs_t * const whichfs,
	const wfs_fsdata_t * const data WFS_ATTR ((unused)), wfs_error_type_t * const error )
#else
	dev_name, FS, whichfs, data, error )
	const char * const dev_name;
	wfs_fsid_t * const FS;
	wfs_curr_fs_t * const whichfs;
	const wfs_fsdata_t * const data WFS_ATTR ((unused));
	wfs_error_type_t * const error;
#endif
{
	wfs_errcode_t ret = WFS_OPENFS;
	errcode_t err;

	if ((dev_name == NULL) || (FS == NULL) || (whichfs == NULL))
	{
		return WFS_BADPARAM;
	}

	*whichfs = CURR_NONE;
	FS->ocfs2 = NULL;
	err = ocfs2_open (dev_name, OCFS2_FLAG_RW | OCFS2_FLAG_BUFFERED, 0, 0, &(FS->ocfs2));
	if ( (err != 0) || (FS->ocfs2 == NULL) )
	{
		if ( error != NULL )
		{
			error->errcode.e2error = err;
		}
		ret = WFS_OPENFS;
	}
	else
	{
		*whichfs = CURR_OCFS;
		ret = WFS_SUCCESS;
	}

	return ret;
}

/* ============================================================= */

/**
 * Checks if the given OCFS filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t WFS_ATTR ((warn_unused_result))
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_ocfs_chk_mount (
#ifdef WFS_ANSIC
	const char * const dev_name, wfs_error_type_t * const error )
#else
	dev_name, error )
	const char * const dev_name;
	wfs_error_type_t * const error;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	int flags = 0;
	errcode_t err;

	err = ocfs2_check_if_mounted (dev_name, &flags);
	if ( err != 0 )
	{
		if ( error != NULL )
		{
			error->errcode.e2error = err;
		}
		ret = WFS_MNTRW;
	}
	else
	{
		if ( ((flags & OCFS2_MF_SWAP) == OCFS2_MF_SWAP)
			|| ((flags & OCFS2_MF_BUSY) == OCFS2_MF_BUSY)
			)
		{
			ret = WFS_MNTRW;
		}
		else if ( (((flags & OCFS2_MF_MOUNTED) == OCFS2_MF_MOUNTED)
			|| ((flags & OCFS2_MF_MOUNTED_CLUSTER) == OCFS2_MF_MOUNTED_CLUSTER))
			&& ((flags & OCFS2_MF_READONLY) == 0) )
		{
			ret = WFS_MNTRW;
		}
	}
	return ret;
}

/* ============================================================= */

/**
 * Closes the OCFS filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_ocfs_close_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t FS, wfs_error_type_t * const error )
#else
	FS, error )
	wfs_fsid_t FS;
	wfs_error_type_t * const error;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	errcode_t err;

	if ( FS.ocfs2 == NULL )
	{
		return WFS_BADPARAM;
	}
	err = ocfs2_close (FS.ocfs2);
	if ( err != 0 )
	{
		ret = WFS_FSCLOSE;
		if ( error != NULL )
		{
			error->errcode.e2error = err;
		}
	}
	return ret;
}

/* ============================================================= */

/**
 * Checks if the OCFS filesystem has errors.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_ocfs_check_err (
#ifdef WFS_ANSIC
	wfs_fsid_t FS WFS_ATTR ((unused)) )
#else
	FS )
	wfs_fsid_t FS WFS_ATTR ((unused));
#endif
{
	/* Don't know how to get this information. */
	return 0;
}

/* ============================================================= */

/**
 * Checks if the OCFS filesystem is dirty (has unsaved changes).
 * \param FS The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_ocfs_is_dirty (
#ifdef WFS_ANSIC
	wfs_fsid_t FS )
#else
	FS )
	wfs_fsid_t FS;
#endif
{
	if ( FS.ocfs2 == NULL )
	{
		return 1;
	}
	return ((FS.ocfs2->fs_flags & OCFS2_FLAG_DIRTY) != 0) ? 1 : 0;
}

/* ============================================================= */

/**
 * Flushes the OCFS filesystem.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_ocfs_flush_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t FS, wfs_error_type_t * const error)
#else
	FS, error )
	wfs_fsid_t FS;
	wfs_error_type_t * const error;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	errcode_t err;

	if ( FS.ocfs2 == NULL )
	{
		return WFS_BADPARAM;
	}
	err = ocfs2_flush (FS.ocfs2);
	if ( err != 0 )
	{
		ret = WFS_FLUSHFS;
		if ( error != NULL )
		{
			error->errcode.e2error = err;
		}
	}

#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_SYNC)
	sync ();
#endif
	return ret;
}
