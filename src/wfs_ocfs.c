/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- OCFS file system-specific functions.
 *
 * Copyright (C) 2011-2024 Bogdan Drozdowski, bogdro (at) users.sourceforge.net
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

#ifdef HAVE_LIBINTL_H
# include <libintl.h>	/* translation stuff */
#endif

#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif

#ifdef HAVE_COM_ERR_H
# include <com_err.h>
#else
# if defined HAVE_ET_COM_ERR_H
#  include <et/com_err.h>
# endif
#endif

#include "wipefreespace.h"

/* fix conflict with <string.h>: */
#define index ocfs_index
#ifndef HAVE_UMODE_T
# define umode_t mode_t
#endif

#if (defined HAVE_OCFS2_OCFS2_H) && (defined HAVE_LIBOCFS2)
# include <ocfs2/ocfs2.h>
#else
# if (defined HAVE_OCFS2_H) && (defined HAVE_LIBOCFS2)
#  include <ocfs2.h>
# else
#  error Something wrong. OCFS requested, but ocfsp2.h or libocfs2 missing.
/* make a syntax error, because not all compilers treat #error as an error */
Something wrong. OCFS requested, but ocfsp2.h or libocfs2 missing.
# endif
#endif

#include "wfs_ocfs.h"
#include "wfs_signal.h"
#include "wfs_util.h"
#include "wfs_wiping.h"
#include "wfs_mount_check.h"

struct wfs_ocfs_block_data
{
	uint64_t total;
	struct ocfs2_dinode *inode;
	wfs_wipedata_t wd;
};

#if (defined TEST_COMPILE) && (defined WFS_ANSIC)
# undef WFS_ANSIC
#endif

/* ============================================================= */

#ifndef WFS_ANSIC
static size_t GCC_WARN_UNUSED_RESULT wfs_ocfs_get_block_size WFS_PARAMS ((const wfs_fsid_t wfs_fs));
#endif

/**
 * Returns the buffer size needed to work on the
 *	smallest physical unit on a OCFS filesystem.
 * \param wfs_fs The filesystem.
 * \return Block size on the filesystem.
 */
static size_t GCC_WARN_UNUSED_RESULT
wfs_ocfs_get_block_size (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs )
#else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
#endif
{
	ocfs2_filesys * ocfs2;

	ocfs2 = (ocfs2_filesys *) wfs_fs.fs_backend;
	if ( ocfs2 == NULL )
	{
		return 0;
	}
	return (size_t)ocfs2->fs_clustersize;
}

/* ============================================================= */

#ifdef WFS_WANT_PART

# ifndef WFS_ANSIC
static int wfs_ocfs_wipe_part_blocks WFS_PARAMS ((ocfs2_filesys * const fs, uint64_t blkno,
	uint64_t bcount, uint16_t ext_flags, void *priv_data));
# endif

static int wfs_ocfs_wipe_part_blocks (
# ifdef WFS_ANSIC
	ocfs2_filesys * const fs, uint64_t blkno, uint64_t bcount WFS_ATTR ((unused)),
	uint16_t ext_flags WFS_ATTR ((unused)), void *priv_data)
# else
	fs, blkno, bcount, ext_flags, priv_data)
	ocfs2_filesys * const fs;
	uint64_t blkno;
	uint64_t bcount WFS_ATTR ((unused));
	uint16_t ext_flags WFS_ATTR ((unused));
	void *priv_data;
# endif
{
	wfs_errcode_t ret_part = WFS_SUCCESS;
	errcode_t err;
	struct wfs_ocfs_block_data * bd = (struct wfs_ocfs_block_data *)priv_data;
	errcode_t error = 0;
	int changed = 0;
	int selected[WFS_NPAT] = {0};
	size_t to_wipe;
	unsigned int offset;
	unsigned long int j;
	ocfs2_filesys * ocfs2;
	errcode_t * error_ret;

	if ( (fs == NULL) || (bd == NULL) )
	{
		/* proceed with the next element */
		return 0;
	}

	ocfs2 = (ocfs2_filesys *) bd->wd.filesys.fs_backend;
	error_ret = (errcode_t *) bd->wd.filesys.fs_error;
	if ( (ocfs2 == NULL) || (bd->inode == NULL) )
	{
		/* proceed with the next element */
		return 0;
	}
	if ( (bd->total < bd->inode->i_size)
		&& (bd->total + ocfs2->fs_blocksize >= bd->inode->i_size) )
	{
		/* this is the last block */
		to_wipe = (size_t)((bd->total + ocfs2->fs_blocksize
			- bd->inode->i_size) & 0x0FFFFFFFF);
		offset = (unsigned int)((bd->inode->i_size % ocfs2->fs_blocksize) & 0x0FFFFFFFF);
		if ( (to_wipe != 0) && (offset != ocfs2->fs_blocksize) )
		{
			err = io_read_block_nocache(ocfs2->fs_io,
				(int64_t)blkno, 1,
				(char *)bd->wd.buf);
			if ( err == 0 )
			{
				for ( j = 0; (j < bd->wd.filesys.npasses)
					&& (sig_recvd == 0); j++ )
				{
					if ( bd->wd.filesys.no_wipe_zero_blocks != 0 )
					{
						if ( wfs_is_block_zero (bd->wd.buf, ocfs2->fs_blocksize) != 0 )
						{
							/* this block is all-zeros - don't wipe, as requested */
							j = bd->wd.filesys.npasses * 2;
							break;
						}
					}
					wfs_fill_buffer ( j, &(bd->wd.buf[offset]), to_wipe,
						selected, bd->wd.filesys );/* buf OK */
					if ( sig_recvd != 0 )
					{
						break;
					}
					/* writing modified cluster here: */
					err = io_write_block_nocache (ocfs2->fs_io,
						/* blkno */ (int64_t)blkno,
						/* count */ 1,
						(char *)bd->wd.buf);
					if ( err != 0 )
					{
						ret_part = WFS_BLKWR;
					}
					/* Flush after each writing, if more than 1 overwriting needs to be done.
					Allow I/O bufferring (efficiency), if just one pass is needed. */
					if ( WFS_IS_SYNC_NEEDED(bd->wd.filesys) )
					{
						error = wfs_ocfs_flush_fs (
							bd->wd.filesys);
					}
				}
				if ( (bd->wd.filesys.zero_pass != 0)
					&& (sig_recvd == 0) )
				{
					if ( j != bd->wd.filesys.npasses * 2 )
					{
						/* last pass with zeros: */
						WFS_MEMSET ( &bd->wd.buf[offset], 0, to_wipe );
						if ( sig_recvd == 0 )
						{
							/* writing modified cluster here: */
							err = io_write_block_nocache (ocfs2->fs_io,
								(int64_t)blkno,
								1, (char *)bd->wd.buf);
							if ( err != 0 )
							{
								ret_part = WFS_BLKWR;
							}
							/* No need to flush the last writing of a given block. *
							if ( (bd->wd.filesys.npasses > 1)
								&& (sig_recvd == 0) )
							{
								error = wfs_ocfs_flush_fs (
									bd->wd.filesys);
							}*/
						}
					}
				}
				changed = 1;
			}
		}
	}
	bd->total += ocfs2->fs_blocksize;
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
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
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_ocfs_wipe_part (
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
	errcode_t error = 0;
	ocfs2_filesys * ocfs2;
	errcode_t * error_ret;

	ocfs2 = (ocfs2_filesys *) wfs_fs.fs_backend;
	error_ret = (errcode_t *) wfs_fs.fs_error;
	if ( ocfs2 == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	/*err = ocfs2_dir_iterate2(ocfs2, ocfs2->fs_root_blkno,
		OCFS2_DIRENT_FLAG_INCLUDE_EMPTY,
		NULL, &wfs_ocfs_wipe_unrm_dir, &wd);* /
	if ( err != 0 )
	{
		ret_part = WFS_DIRITER;
		if ( error != NULL )
		{
			error = err;
		}
	}
	*/

	err = ocfs2_open_inode_scan (ocfs2, &iscan);
	if ( err != 0 )
	{
		error = err;
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_INOSCAN;
	}

	cluster_size = wfs_ocfs_get_block_size (wfs_fs);
	if ( cluster_size == 0 )
	{
		return WFS_BADPARAM;
	}

	WFS_SET_ERRNO (0);
	inode_buf = (char *) malloc ( cluster_size );
	if ( inode_buf == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (ENOMEM);
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}
	WFS_SET_ERRNO (0);
	buf = (unsigned char *) malloc ( cluster_size );
	if ( buf == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (ENOMEM);
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		free (inode_buf);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	dinode = (struct ocfs2_dinode *)inode_buf;
	bd.wd.passno = 0;
	bd.wd.filesys = wfs_fs;
	bd.wd.total_fs = 0;
	bd.wd.ret_val = 0;
	bd.wd.buf = buf;
	do
	{
		err = ocfs2_get_next_inode (iscan, &blkno, inode_buf);
		if ( err != 0 )
		{
			ret_part = WFS_INOSCAN;
			error = err;
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
		ocfs2_swap_inode_to_cpu (ocfs2, dinode);

		/* invalid? skip */
		if ( (dinode->i_flags & OCFS2_VALID_FL) == 0 )
		{
			continue;
		}

		/* not a regular file? skip */
		if ( ! S_ISREG (dinode->i_mode) )
		{
			continue;
		}
		if ((dinode->i_dyn_features & OCFS2_INLINE_DATA_FL) != 0)
		{
			to_wipe = (size_t)(ocfs2_max_inline_data_with_xattr (
				(int)ocfs2->fs_blocksize,
				dinode) - (int)((dinode->i_size) & 0x0FFFFFFFF));
			offset = (unsigned int)((dinode->i_size) & 0x0FFFFFFFF);
			if ( (to_wipe != 0) && (offset != ocfs2->fs_blocksize) )
			{
				for ( j = 0; (j < wfs_fs.npasses)
					&& (sig_recvd == 0); j++ )
				{
					wfs_fill_buffer ( j, &(dinode->id2.i_data.id_data[offset]),
						to_wipe, selected, wfs_fs );/* buf OK */
					if ( sig_recvd != 0 )
					{
						break;
					}
					/* writing modified inode here: */
					err = ocfs2_write_inode (ocfs2,
						dinode->i_blkno, inode_buf);
					if ( err != 0 )
					{
						error = err;
						ret_part = WFS_BLKWR;
					}
					/* Flush after each writing, if more than 1 overwriting needs to be done.
					Allow I/O bufferring (efficiency), if just one pass is needed. */
					if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
					{
						error = wfs_ocfs_flush_fs (wfs_fs);
					}
				}
				if ( (wfs_fs.zero_pass != 0)
					&& (sig_recvd == 0) )
				{
					/* last pass with zeros: */
					WFS_MEMSET ( &(dinode->id2.i_data.id_data[offset]),
						0, to_wipe );
					if ( sig_recvd == 0 )
					{
						/* writing modified inode here: */
						err = ocfs2_write_inode (ocfs2,
							dinode->i_blkno, inode_buf);
						if ( err != 0 )
						{
							ret_part = WFS_BLKWR;
							error = err;
						}
						/* No need to flush the last writing of a given block. *
						if ( (wfs_fs.npasses > 1)
							&& (sig_recvd == 0) )
						{
							error = wfs_ocfs_flush_fs (
								wfs_fs);
						}*/
					}
				}
			}
		}
		else
		{
			bd.total = 0;
			bd.inode = dinode;
			err = ocfs2_block_iterate_inode (ocfs2, dinode, 0,
				&wfs_ocfs_wipe_part_blocks, &bd);
			if ( err == OCFS2_ET_INODE_CANNOT_BE_ITERATED )
			{
				/* i-node does neither contain inline data
				or extents - can't be iterated over. Skip it. */
				err = 0;
				continue;
			}
		}
		if ( err != 0 )
		{
			ret_part = WFS_INOSCAN;
			error = err;
			continue;
		}

	} while ( sig_recvd == 0 );

	ocfs2_close_inode_scan (iscan);
	free (buf);
	free (inode_buf);

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

/* ============================================================= */

#ifdef WFS_WANT_WFS
/**
 * Wipes the free space on the given OCFS filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_ocfs_wipe_fs (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	unsigned int prev_percent = 0;
	uint32_t curr_cluster;
	unsigned long int j;
	int selected[WFS_NPAT] = {0};
	unsigned char * buf;
	errcode_t err;
	int is_alloc;
	size_t cluster_size;
	unsigned int blocks_per_cluster;
	errcode_t error = 0;
	ocfs2_filesys * ocfs2;
	errcode_t * error_ret;

	ocfs2 = (ocfs2_filesys *) wfs_fs.fs_backend;
	error_ret = (errcode_t *) wfs_fs.fs_error;
	if ( ocfs2 == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}

	cluster_size = wfs_ocfs_get_block_size (wfs_fs);
	if ( cluster_size == 0 )
	{
		return WFS_BADPARAM;
	}

	blocks_per_cluster = (unsigned int)(ocfs2_clusters_to_blocks (
		ocfs2, 1) & 0x0FFFFFFFF);

	WFS_SET_ERRNO (0);
	buf = (unsigned char *) malloc ( cluster_size );
	if ( buf == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (ENOMEM);
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	if ( wfs_fs.wipe_mode == WFS_WIPE_MODE_PATTERN )
	{
		for ( j = 0; (j < wfs_fs.npasses) && (sig_recvd == 0); j++ )
		{
			for ( curr_cluster = 0;
				(curr_cluster < ocfs2->fs_clusters) && (sig_recvd == 0);
				curr_cluster++ )
			{
				is_alloc = 1;
				err = ocfs2_test_cluster_allocated (ocfs2, curr_cluster,
					&is_alloc);
				if ( err != 0 )
				{
					ret_wfs = WFS_BLBITMAPREAD;
					wfs_show_progress (WFS_PROGRESS_WFS,
						(unsigned int) (((ocfs2->fs_clusters * j + curr_cluster) * 100)/(ocfs2->fs_clusters * wfs_fs.npasses)),
						&prev_percent);
					continue;
				}
				if ( is_alloc != 0 )
				{
					wfs_show_progress (WFS_PROGRESS_WFS,
						(unsigned int) (((ocfs2->fs_clusters * j + curr_cluster) * 100)/(ocfs2->fs_clusters * wfs_fs.npasses)),
						&prev_percent);
					continue;
				}

				/* cluster is unused - wipe it */
				if ( wfs_fs.no_wipe_zero_blocks != 0 )
				{
					err = io_read_block_nocache (ocfs2->fs_io,
						/* blkno */ curr_cluster * blocks_per_cluster,
						/* count */ (int)blocks_per_cluster,
						(char *)buf);
					if ( err != 0 )
					{
						ret_wfs = WFS_BLKRD;
						break;
					}
					if ( wfs_is_block_zero (buf, cluster_size) != 0 )
					{
						/* this block is all-zeros - don't wipe, as requested */
						j = wfs_fs.npasses * 2;
						break;
					}
				}
				wfs_fill_buffer ( j, buf, cluster_size,
					selected, wfs_fs );/* buf OK */
				if ( sig_recvd != 0 )
				{
					break;
				}
				/* writing modified cluster here: */
				err = io_write_block_nocache (ocfs2->fs_io,
					/* blkno */ curr_cluster * blocks_per_cluster,
					/* count */ (int)blocks_per_cluster,
					(char *)buf);
				if ( err != 0 )
				{
					free (buf);
					wfs_show_progress (WFS_PROGRESS_WFS, 100,
						&prev_percent);
					if ( error_ret != NULL )
					{
						*error_ret = error;
					}
					return WFS_BLKWR;
				}
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
				{
					error = wfs_ocfs_flush_fs (wfs_fs);
				}
				wfs_show_progress (WFS_PROGRESS_WFS,
					(unsigned int) (((ocfs2->fs_clusters * j + curr_cluster) * 100)/(ocfs2->fs_clusters * wfs_fs.npasses)),
					&prev_percent);
			}
		}
		if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
		{
			if ( j != wfs_fs.npasses * 2 )
			{
				/* last pass with zeros: */
				WFS_MEMSET ( buf, 0, cluster_size );
				if ( sig_recvd == 0 )
				{
					wfs_ocfs_flush_fs (wfs_fs);
					for ( curr_cluster = 0;
						(curr_cluster < ocfs2->fs_clusters) && (sig_recvd == 0);
						curr_cluster++ )
					{
						/* writing modified cluster here: */
						err = io_write_block_nocache (ocfs2->fs_io,
							curr_cluster * blocks_per_cluster,
							(int)blocks_per_cluster, (char *)buf);
						if ( err != 0 )
						{
							free (buf);
							wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
							if ( error_ret != NULL )
							{
								*error_ret = error;
							}
							return WFS_BLKWR;
						}
						/* No need to flush the last writing of a given block. *
						if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
						{
							error = wfs_ocfs_flush_fs (
								wfs_fs);
						}*/
					}
					wfs_ocfs_flush_fs (wfs_fs);
				}
			}
		}
	}
	else
	{
		for ( curr_cluster = 0;
			(curr_cluster < ocfs2->fs_clusters) && (sig_recvd == 0);
			curr_cluster++ )
		{
			is_alloc = 1;
			err = ocfs2_test_cluster_allocated (ocfs2, curr_cluster,
				&is_alloc);
			if ( err != 0 )
			{
				ret_wfs = WFS_BLBITMAPREAD;
				wfs_show_progress (WFS_PROGRESS_WFS,
					(unsigned int) ((curr_cluster * 100)/ocfs2->fs_clusters),
					&prev_percent);
				continue;
			}
			if ( is_alloc != 0 )
			{
				wfs_show_progress (WFS_PROGRESS_WFS,
					(unsigned int) ((curr_cluster * 100)/ocfs2->fs_clusters),
					&prev_percent);
				continue;
			}

			/* cluster is unused - wipe it */
			for ( j = 0; (j < wfs_fs.npasses) && (sig_recvd == 0); j++ )
			{
				if ( wfs_fs.no_wipe_zero_blocks != 0 )
				{
					err = io_read_block_nocache (ocfs2->fs_io,
						/* blkno */ curr_cluster * blocks_per_cluster,
						/* count */ (int)blocks_per_cluster,
						(char *)buf);
					if ( err != 0 )
					{
						ret_wfs = WFS_BLKRD;
						break;
					}
					if ( wfs_is_block_zero (buf, cluster_size) != 0 )
					{
						/* this block is all-zeros - don't wipe, as requested */
						j = wfs_fs.npasses * 2;
						break;
					}
				}
				wfs_fill_buffer ( j, buf, cluster_size,
					selected, wfs_fs );/* buf OK */
				if ( sig_recvd != 0 )
				{
					break;
				}
				/* writing modified cluster here: */
				err = io_write_block_nocache (ocfs2->fs_io,
					/* blkno */ curr_cluster * blocks_per_cluster,
					/* count */ (int)blocks_per_cluster,
					(char *)buf);
				if ( err != 0 )
				{
					free (buf);
					wfs_show_progress (WFS_PROGRESS_WFS, 100,
						&prev_percent);
					if ( error_ret != NULL )
					{
						*error_ret = error;
					}
					return WFS_BLKWR;
				}
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
				{
					error = wfs_ocfs_flush_fs (wfs_fs);
				}
			}
			if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
			{
				if ( j != wfs_fs.npasses * 2 )
				{
					/* last pass with zeros: */
					WFS_MEMSET ( buf, 0, cluster_size );
					if ( sig_recvd == 0 )
					{
						/* writing modified cluster here: */
						err = io_write_block_nocache (ocfs2->fs_io,
							curr_cluster * blocks_per_cluster,
							(int)blocks_per_cluster, (char *)buf);
						if ( err != 0 )
						{
							free (buf);
							wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
							if ( error_ret != NULL )
							{
								*error_ret = error;
							}
							return WFS_BLKWR;
						}
						/* No need to flush the last writing of a given block. *
						if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
						{
							error = wfs_ocfs_flush_fs (
								wfs_fs);
						}*/
					}
				}
			}
			wfs_show_progress (WFS_PROGRESS_WFS,
				(unsigned int) ((100*curr_cluster)/ocfs2->fs_clusters),
				&prev_percent);
		}
	}

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

/* ============================================================= */

#ifdef WFS_WANT_UNRM

# ifndef WFS_ANSIC
static int wfs_ocfs_wipe_unrm_dir WFS_PARAMS ((uint64_t dir,
	int entry, struct ocfs2_dir_entry *dirent,
	uint64_t blocknr, int offset, int blocksize,
	char *buf, void *priv_data));
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
	int changed = 0;
	int selected[WFS_NPAT] = {0};
	ocfs2_filesys * ocfs2;

	if ( (dirent == NULL) || (wd == NULL) )
	{
		/* proceed with the next element */
		return 0;
	}

	ocfs2 = (ocfs2_filesys *) wd->filesys.fs_backend;
	if ( ocfs2 == NULL )
	{
		/* proceed with the next element */
		return 0;
	}
	if ( (dirent->file_type == OCFS2_FT_DIR) /*&& (dirent->name != NULL)*/ )
	{
		if ( (strncmp (dirent->name, "..", OCFS2_MAX_FILENAME_LEN) != 0) &&
			(strncmp (dirent->name, ".", OCFS2_MAX_FILENAME_LEN) != 0) &&
			(entry != OCFS2_DIRENT_DOT_FILE) &&
			(entry != OCFS2_DIRENT_DOT_DOT_FILE) )
		{
			err = ocfs2_dir_iterate2 (ocfs2, dirent->inode,
				OCFS2_DIRENT_FLAG_INCLUDE_REMOVED, NULL,
				&wfs_ocfs_wipe_unrm_dir, wd);
			if ( err != 0 )
			{
				ret_unrm = WFS_DIRITER;
			}
		}
	}
	else if ( (entry == OCFS2_DIRENT_DELETED_FILE) /*&& (dirent->name != NULL)*/ )
	{
		if ( (wd->filesys.zero_pass != 0) && (sig_recvd == 0) )
		{
			WFS_MEMSET ( dirent->name, 0, OCFS2_MAX_FILENAME_LEN );
		}
		else
		{
			wfs_fill_buffer ( wd->passno,
				(unsigned char *)dirent->name,
				OCFS2_MAX_FILENAME_LEN,
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
 * \param wfs_fs The filesystem.
 * \param node Filesystem element at which to start.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_ocfs_wipe_unrm (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
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
	unsigned int i;
	/*uint32_t journal_size_in_clusters;*/
	uint64_t journal_block_numer;
	char jorunal_object_name[20];
	journal_superblock_t *jsb;
	/*ocfs2_fs_options journal_features;*/
	ocfs2_cached_inode *ci = NULL;
	uint64_t contig;
	size_t name_index;
	int si_name_percents;
	errcode_t error = 0;
	ocfs2_filesys * ocfs2;
	errcode_t * error_ret;
	unsigned int journal_size;

	ocfs2 = (ocfs2_filesys *) wfs_fs.fs_backend;
	error_ret = (errcode_t *) wfs_fs.fs_error;
	if ( ocfs2 == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}

	wd.passno = 0;
	wd.filesys = wfs_fs;
	wd.total_fs = 0;
	wd.ret_val = 0;
	err = ocfs2_dir_iterate2(ocfs2, ocfs2->fs_root_blkno,
		OCFS2_DIRENT_FLAG_INCLUDE_REMOVED, NULL,
		&wfs_ocfs_wipe_unrm_dir, &wd);
	if ( err != 0 )
	{
		ret_unrm = WFS_DIRITER;
		error = err;
	}
	/* journal: */
	cluster_size = wfs_ocfs_get_block_size (wfs_fs);
	if ( cluster_size == 0 )
	{
		return WFS_BADPARAM;
	}

	WFS_SET_ERRNO (0);
	buf = (unsigned char *) malloc ( cluster_size );
	if ( buf == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (ENOMEM);
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	for ( i = 0; i < OCFS2_RAW_SB(ocfs2->fs_super)->s_max_slots; i++ )
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
		err = ocfs2_lookup (ocfs2, ocfs2->fs_sysdir_blkno,
			jorunal_object_name, (int)strlen (jorunal_object_name),
			NULL, &journal_block_numer);
		if ( err != 0 )
		{
			continue;
		}

		err = ocfs2_read_cached_inode (ocfs2,
			journal_block_numer, &ci);
		if ( err != 0 )
		{
			continue;
		}

		err = ocfs2_extent_map_get_blocks(ci, 0, 1,
			&journal_block_numer, &contig, NULL);
		if ( err != 0 )
		{
			ocfs2_free_cached_inode (ocfs2, ci);
			continue;
		}

		/*err = ocfs2_read_blocks (ocfs2, (int64_t)journal_block_numer, 1, (char *)buf);*/
		err = ocfs2_read_journal_superblock (ocfs2,
			journal_block_numer, (char *)buf);
		if ( err != 0 )
		{
			ocfs2_free_cached_inode (ocfs2, ci);
			continue;
		}

		jsb = (journal_superblock_t *)buf;
		/*ocfs2_swap_journal_superblock (jsb);*/
		if ( jsb->s_header.h_magic != JBD2_MAGIC_NUMBER )
		{
			ocfs2_free_cached_inode (ocfs2, ci);
			continue;
		}

		/*ocfs2_swap_journal_superblock (jsb);*/

		/* wipe the journal */
		WFS_SET_ERRNO (0);
		jbuf = (unsigned char *) malloc ( (size_t)jsb->s_blocksize );
		if ( jbuf == NULL )
		{
			ocfs2_free_cached_inode (ocfs2, ci);
			error = WFS_GET_ERRNO_OR_DEFAULT (ENOMEM);
			break;
		}
		/*journal_size_in_clusters = (jsb->s_blocksize * jsb->s_maxlen) >>
			OCFS2_RAW_SB(ocfs2->fs_super)->s_clustersize_bits;*/
		journal_size = jsb->s_maxlen; /* save before overwriting */
		for ( curr_block = journal_block_numer+1;
			(curr_block < journal_block_numer + journal_size)
			&& (sig_recvd == 0); curr_block++ )
		{
			for ( j = 0; (j < wfs_fs.npasses)
				&& (sig_recvd == 0); j++ )
			{
				wfs_fill_buffer ( j, jbuf,
					(size_t)jsb->s_blocksize, selected,
					wfs_fs );/* buf OK */
				if ( sig_recvd != 0 )
				{
					break;
				}
				/* writing modified cluster here: */
				err = io_write_block_nocache (ocfs2->fs_io,
					/* blkno */ (int64_t)curr_block,
					/* count */ 1,
					(char *)jbuf);
				if ( err != 0 )
				{
					free (jbuf);
					free (buf);
					wfs_show_progress (WFS_PROGRESS_UNRM, 100,
						&prev_percent);
					if ( error_ret != NULL )
					{
						*error_ret = err;
					}
					ocfs2_free_cached_inode (ocfs2, ci);
					return WFS_BLKWR;
				}
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
				{
					err = wfs_ocfs_flush_fs (
						wfs_fs);
					if ( err != 0 )
					{
						error = err;
					}
				}
			}
			if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
			{
				/* last pass with zeros: */
				WFS_MEMSET ( buf, 0, (size_t)jsb->s_blocksize );
				if ( sig_recvd == 0 )
				{
					/* writing modified cluster here: */
					err = io_write_block_nocache (ocfs2->fs_io,
						(int64_t)curr_block,
						1, (char *)jbuf);
					if ( err != 0 )
					{
						free (jbuf);
						free (buf);
						wfs_show_progress (WFS_PROGRESS_UNRM,
							100, &prev_percent);
						if ( error_ret != NULL )
						{
							*error_ret = err;
						}
						ocfs2_free_cached_inode (ocfs2, ci);
						return WFS_BLKWR;
					}
					/* No need to flush the last writing of a given block. *
					if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
					{
						err = wfs_ocfs_flush_fs (
							wfs_fs);
						if ( err != 0 )
						{
							error = err;
						}
					}*/
				}
			}
			wfs_show_progress (WFS_PROGRESS_UNRM,
				(unsigned int) (50+((curr_block -
					(journal_block_numer+1))*50)/journal_size),
				&prev_percent);
		}

		free (jbuf);
		/* recreate the journal: */
		/*
		WFS_MEMSET ( &journal_features, 0, sizeof (journal_features) );
		journal_features.opt_compat = jsb->s_feature_compat;
		journal_features.opt_incompat = jsb->s_feature_incompat;
		journal_features.opt_ro_compat = jsb->s_feature_ro_compat;

		err = ocfs2_make_journal (ocfs2, journal_block_numer,
			journal_size_in_clusters, &journal_features);
		if ( (error != NULL) && (err != 0) )
		{
			err = err;
		}
		*/
		/*ocfs2_swap_journal_superblock (jsb);*/
		err = ocfs2_write_journal_superblock (ocfs2,
			journal_block_numer, (char *)buf);
		if ( err != 0 )
		{
			error = err;
		}

		err = ocfs2_write_cached_inode (ocfs2, ci);
		if ( err != 0 )
		{
			error = err;
		}
		ocfs2_free_cached_inode (ocfs2, ci);
	}

	free (buf);
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


/* ============================================================= */

/**
 * Opens a OCFS filesystem on the given device.
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
wfs_ocfs_open_fs (
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
	errcode_t err;
	ocfs2_filesys * ocfs2;
	errcode_t * error_ret;

	if ( wfs_fs == NULL )
	{
		return WFS_BADPARAM;
	}
	error_ret = (errcode_t *) wfs_fs->fs_error;
	if ( wfs_fs->fsname == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = WFS_BADPARAM;
		}
		return WFS_BADPARAM;
	}

	wfs_fs->whichfs = WFS_CURR_FS_NONE;
	ocfs2 = NULL;
	err = ocfs2_open (wfs_fs->fsname, OCFS2_FLAG_RW | OCFS2_FLAG_BUFFERED,
		0, 0, &ocfs2);
	if ( (err != 0) || (ocfs2 == NULL) )
	{
		if ( error_ret != NULL )
		{
			*error_ret = err;
		}
		ret = WFS_OPENFS;
	}
	else
	{
		wfs_fs->whichfs = WFS_CURR_FS_OCFS;
		ret = WFS_SUCCESS;
		wfs_fs->fs_backend = ocfs2;
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
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_ocfs_chk_mount (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	int flags = 0;
	errcode_t err = 0;
	errcode_t * error_ret;

	error_ret = (errcode_t *) wfs_fs.fs_error;
	if ( wfs_fs.fsname == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = err;
		}
		return WFS_BADPARAM;
	}

	err = ocfs2_check_if_mounted (wfs_fs.fsname, &flags);

	if ( err != 0 )
	{
		if ( error_ret != NULL )
		{
			*error_ret = err;
		}
		ret = WFS_MNTRW;
	}
	else
	{
		if ( ((flags & OCFS2_MF_SWAP) == OCFS2_MF_SWAP)
			/* the "busy" flag is set even when the filesystem
			   is mounted read-only */
			/*|| ((flags & OCFS2_MF_BUSY) == OCFS2_MF_BUSY)*/
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

	if ( ret == WFS_SUCCESS )
	{
		ret = wfs_check_mounted (wfs_fs);
		if ( ret == WFS_MNTRW )
		{
			if ( error_ret != NULL )
			{
				*error_ret = (errcode_t)ret;
			}
		}
	}
	return ret;
}

/* ============================================================= */

/**
 * Closes the OCFS filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_ocfs_close_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	errcode_t err;
	ocfs2_filesys * ocfs2;
	errcode_t * error_ret;

	ocfs2 = (ocfs2_filesys *) wfs_fs.fs_backend;
	error_ret = (errcode_t *) wfs_fs.fs_error;
	if ( ocfs2 == NULL )
	{
		return WFS_BADPARAM;
	}
	err = ocfs2_close (ocfs2);
	/*ocfs2_freefs (ocfs2);*/
	if ( err != 0 )
	{
		ret = WFS_FSCLOSE;
		if ( error_ret != NULL )
		{
			*error_ret = err;
		}
	}
	return ret;
}

/* ============================================================= */

/**
 * Checks if the OCFS filesystem has errors.
 * \param wfs_fs The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_ocfs_check_err (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs WFS_ATTR ((unused)) )
#else
	wfs_fs )
	wfs_fsid_t wfs_fs WFS_ATTR ((unused));
#endif
{
	/* Don't know how to get this information. */
	return 0;
}

/* ============================================================= */

/**
 * Checks if the OCFS filesystem is dirty (has unsaved changes).
 * \param wfs_fs The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_ocfs_is_dirty (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs )
#else
	wfs_fs )
	wfs_fsid_t wfs_fs;
#endif
{
	ocfs2_filesys * ocfs2;

	ocfs2 = (ocfs2_filesys *) wfs_fs.fs_backend;
	if ( ocfs2 == NULL )
	{
		return 1;
	}
	return ((ocfs2->fs_flags & OCFS2_FLAG_DIRTY) != 0) ? 1 : 0;
}

/* ============================================================= */

/**
 * Flushes the OCFS filesystem.
 * \param wfs_fs The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_ocfs_flush_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	errcode_t err;
	ocfs2_filesys * ocfs2;
	errcode_t * error_ret;

	ocfs2 = (ocfs2_filesys *) wfs_fs.fs_backend;
	error_ret = (errcode_t *) wfs_fs.fs_error;
	if ( ocfs2 == NULL )
	{
		return WFS_BADPARAM;
	}
	err = ocfs2_flush (ocfs2);
	if ( err != 0 )
	{
		ret = WFS_FLUSHFS;
		if ( error_ret != NULL )
		{
			*error_ret = err;
		}
	}

#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_SYNC)
	sync ();
#endif
	return ret;
}

/* ======================================================================== */

/**
 * Print the version of the current library, if applicable.
 */
void wfs_ocfs_print_version (WFS_VOID)
{
	printf ( "OCFS: <?>\n");
}

/* ======================================================================== */

/**
 * Get the preferred size of the error variable.
 * \return the preferred size of the error variable.
 */
size_t wfs_ocfs_get_err_size (WFS_VOID)
{
	return sizeof (errcode_t);
}

/* ======================================================================== */

/**
 * Initialize the library.
 */
void wfs_ocfs_init (WFS_VOID)
{
	/*initialize_o2cb_error_table ();*/
	/*initialize_o2dl_error_table ();*/
	initialize_ocfs_error_table ();
}

/* ======================================================================== */

/**
 * De-initialize the library.
 */
void wfs_ocfs_deinit (WFS_VOID)
{
#if (defined HAVE_COM_ERR_H) || (defined HAVE_ET_COM_ERR_H)
	/*remove_error_table (&et_o2cb_error_table);*/
	/*remove_error_table (&et_o2dl_error_table);*/
	remove_error_table (&et_ocfs_error_table);
#endif
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
wfs_ocfs_show_error (
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
#if ((defined HAVE_ET_COM_ERR_H) || (defined HAVE_COM_ERR_H)) && (defined HAVE_LIBCOM_ERR)
	errcode_t e = 0;
	const char * progname;
#endif

	if ( (wfs_is_stderr_open() == 0) || (msg == NULL) )
	{
		return;
	}
#if ((defined HAVE_ET_COM_ERR_H) || (defined HAVE_COM_ERR_H)) && (defined HAVE_LIBCOM_ERR)
	if ( wfs_fs.fs_error != NULL )
	{
		e = *(errcode_t *)(wfs_fs.fs_error);
	}

	progname = wfs_get_program_name();
	com_err ((progname != NULL)? progname : "",
		e,
		WFS_ERR_MSG_FORMATL,
		_(wfs_err_msg),
		e,
		_(msg),
		(extra != NULL)? extra : "",
		(wfs_fs.fsname != NULL)? wfs_fs.fsname : "");
#else
	wfs_show_fs_error_gen (msg, extra, wfs_fs);
#endif
	fflush (stderr);
}
