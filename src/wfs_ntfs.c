/*
 * A program for secure cleaning of free space on filesystems.
 *	-- NTFS file system-specific functions.
 *
 * Copyright (C) 2007 Bogdan Drozdowski, bogdandr (at) op.pl
 * License: GNU General Public License, v3+
 *
 * Parts of this file come from libnfts or ntfsprogs, and are:
 * Copyright (c) 2002-2005 Richard Russon
 * Copyright (c) 2003-2006 Anton Altaparmakov
 * Copyright (c) 2003 Lode Leroy
 * Copyright (c) 2004 Yura Pakhuchiy
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* sync() */
#endif

#ifdef HAVE_SYS_MOUNT_H
# include <sys/mount.h>	/* umount() */
#endif

/*
#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif
*/

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
# if ((!defined STDC_HEADERS) || (!STDC_HEADERS)) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>	/* memset() */
#endif

#ifdef HAVE_LIMITS_H
# include <limits.h>
#else
# ifndef CHAR_BIT
#  ifdef __CHAR_BIT__
#   define CHAR_BIT __CHAR_BIT__
#  else
#   define CHAR_BIT 8
#  endif
# endif
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#if (defined HAVE_NTFS_NTFS_VOLUME_H) && (defined HAVE_LIBNTFS)
# include <ntfs/ntfs_volume.h>
# include <ntfs/ntfs_attrib.h>	/* ntfs_attr_search_ctx() */
# include <ntfs/ntfs_list.h>		/* list_for_each_safe() */
# include <ntfs/ntfs_mft.h>		/* ntfs_mft_records_write() */
#else
# if (defined HAVE_NTFS_VOLUME_H) && (defined HAVE_LIBNTFS)
#  include <ntfs/volume.h>
#  include <ntfs/attrib.h>	/* ntfs_attr_search_ctx() */
#  include <ntfs/list.h>		/* list_for_each_safe() */
#  include <ntfs/mft.h>		/* ntfs_mft_records_write() */
# else
#  if (defined HAVE_VOLUME_H) && (defined HAVE_LIBNTFS)
#   include <volume.h>
#   include <attrib.h>
#   include <list.h>
#   include <mft.h>
#  else
#   error Something wrong. NTFS requested, but headers or library missing.
#  endif
# endif
#endif

#include "wipefreespace.h"
#include "wfs_ntfs.h"
#include "wfs_signal.h"

struct filename
{
	char		*parent_name;
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	struct ntfs_list_head list;	/* Previous/Next links */
#else
	struct list_head list;		/* Previous/Next links */
#endif
	ntfschar	*uname;		/* Filename in unicode */
	int		 uname_len;	/* and its length */
	long long	 size_alloc;	/* Allocated size (multiple of cluster size) */
	long long	 size_data;	/* Actual size of data */
	long long	 parent_mref;
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	NTFS_FILE_ATTR_FLAGS	 flags;
#else
	FILE_ATTR_FLAGS	 flags;
#endif
	time_t		 date_c;	/* Time created */
	time_t		 date_a;	/*	altered */
	time_t		 date_m;	/*	mft record changed */
	time_t		 date_r;	/*	read */
	char		*name;		/* Filename in current locale */
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	NTFS_FILE_NAME_TYPE_FLAGS name_space;
#else
	FILE_NAME_TYPE_FLAGS name_space;
#endif
	char		 padding[7];	/* Unused: padding to 64 bit. */
};

struct data
{
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	struct ntfs_list_head list;	/* Previous/Next links */
#else
	struct list_head list;		/* Previous/Next links */
#endif
	char		*name;		/* Stream name in current locale */
	ntfschar	*uname;		/* Unicode stream name */
	int		 uname_len;	/* and its length */
	int		 resident;	/* Stream is resident */
	int		 compressed;	/* Stream is compressed */
	int		 encrypted;	/* Stream is encrypted */
	long long	 size_alloc;	/* Allocated size (multiple of cluster size) */
	long long	 size_data;	/* Actual size of data */
	long long	 size_init;	/* Initialised size, may be less than data size */
	long long	 size_vcn;	/* Highest VCN in the data runs */
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	ntfs_runlist_element *runlist;	/* Decoded data runs */
#else
	runlist_element *runlist;	/* Decoded data runs */
#endif
	int		 percent;	/* Amount potentially recoverable */
	void		*data;		/* If resident, a pointer to the data */
	char		 padding[4];	/* Unused: padding to 64 bit. */
};

struct ufile
{
	long long	 inode;		/* MFT record number */
	time_t		 date;		/* Last modification date/time */
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	struct ntfs_list_head name;	/* A list of filenames */
#else
	struct list_head name;		/* A list of filenames */
#endif
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	struct ntfs_list_head data;	/* A list of data streams */
#else
	struct list_head data;		/* A list of data streams */
#endif
	char		*pref_name;	/* Preferred filename */
	char		*pref_pname;	/*	     parent filename */
	long long	 max_size;	/* Largest size we find */
	int		 attr_list;	/* MFT record may be one of many */
	int		 directory;	/* MFT record represents a directory */
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	NTFS_MFT_RECORD	*mft;		/* Raw MFT record */
#else
	MFT_RECORD	*mft;		/* Raw MFT record */
#endif
	char		 padding[4];	/* Unused: padding to 64 bit. */
};

/**
 * Returns the buffer size needed to work on the smallest physical unit on a NTFS filesystem
 * \param FS The filesystem.
 * \return Block size on the filesystem.
 */
static u32 WFS_ATTR ((warn_unused_result))
wfs_ntfs_get_block_size (const wfs_fsid_t FS)
{
	return FS.ntfs.cluster_size;
	/* return ntfs_device_sector_size_get(&(FS.ntfs)); */
}


/**
 * Part of ntfsprogs.
 * Modified: removed logging, memset replaced by fill_buffer, signal handling.
 *
 * wipe_compressed_attribute - Wipe compressed $DATA attribute
 * \param	vol	An ntfs volume obtained from ntfs_mount
 * \param	na	Opened ntfs attribute
 *
 * \return >0  Success, the attribute was wiped
 *          0  Nothing to wipe
 *         -1  Error, something went wrong
 */
static s64 WFS_ATTR ((nonnull))
wipe_compressed_attribute (const ntfs_volume * const vol,
	ntfs_attr * const na, unsigned char * const buf)
{
	unsigned char *mybuf = NULL;
	s64 size, offset, ret = 0, wiped = 0;
	u16 block_size;
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	NTFS_VCN cur_vcn = 0;
	ntfs_runlist *rlc = na->rl;
#else
	VCN cur_vcn = 0;
	runlist *rlc = na->rl;
#endif
	s64 cu_mask = na->compression_block_clusters - 1;

	size_t bufsize = 0;
	unsigned long int j;
	s64 two = 2;
	wfs_fsid_t FS;
	int go_back;
	int selected[NPAT];
	error_type error;

	if ( (vol == NULL) || (na == NULL) || (buf == NULL) ) return 0;

	FS.ntfs = *vol;

	while ( (rlc->length != 0) && (sig_recvd==0) )
	{

		go_back = 0;
		cur_vcn += rlc->length;
		if ( ((cur_vcn & cu_mask) != 0) ||
			(
			 (((rlc + 1)->length) != 0) &&
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
			 (rlc->lcn != NTFS_LCN_HOLE)
#else
			 (rlc->lcn != LCN_HOLE)
#endif
			)
		   )
		{
			rlc++;
			continue;
		}
		if ( sig_recvd != 0 ) return -1;

#if (defined HAVE_NTFS_NTFS_VOLUME_H)
		if (rlc->lcn == NTFS_LCN_HOLE)
#else
		if (rlc->lcn == LCN_HOLE)
#endif
		{
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
			ntfs_runlist *rlt;
#else
			runlist *rlt;
#endif

			offset = cur_vcn - rlc->length;
			if (offset == (offset & (~cu_mask)))
			{
				rlc++;
				continue;
			}
			offset = (offset & (~cu_mask)) << vol->cluster_size_bits;
			rlt = rlc;
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
			while ((rlt - 1)->lcn == NTFS_LCN_HOLE) rlt--;
#else
			while ((rlt - 1)->lcn == LCN_HOLE) rlt--;
#endif
			while ( sig_recvd == 0 )
			{
				ret = ntfs_rl_pread (vol, na->rl, offset, two, &block_size);
				block_size = le16_to_cpu (block_size);
				if (ret != two)
				{
					return -1;
				}
				if (block_size == 0)
				{
					offset += 2;
					break;
				}
				block_size &= 0x0FFF;
				block_size += 3;
				offset += block_size;
				if (offset >= ( ((rlt->vcn) << vol->cluster_size_bits) - 2) )
				{
					go_back = 1;
					break;
				}
			}
			if ( go_back != 0 ) continue;
			size = (rlt->vcn << vol->cluster_size_bits) - offset;
		}
		else
		{
			size = na->allocated_size - na->data_size;
			offset = (cur_vcn << vol->cluster_size_bits) - size;
		}

		if ( (size < 0) || (sig_recvd!=0) )
		{
			return -1;
		}

		if ( size == 0 )
		{
			wiped += size;
			rlc++;
			continue;
		}
		if ( size > wfs_ntfs_get_block_size (FS) )
		{
			bufsize = (size_t) size;
			mybuf = (unsigned char *) malloc (bufsize);
			if ( mybuf == NULL ) continue;
		}

		for ( j = 0; (j < npasses) && (sig_recvd == 0); j++ )
		{

			if ( mybuf != NULL )
			{
				fill_buffer ( j, mybuf, bufsize, selected );	/* buf OK */
			}
			else
			{
				fill_buffer ( j, buf, (size_t) size, selected );	/* buf OK */
			}
			if ( sig_recvd != 0 )
			{
		       		break;
			}
			if ( mybuf != NULL )
			{
				ret = ntfs_rl_pwrite (vol, na->rl, offset, size, mybuf);
			}
			else
			{
				ret = ntfs_rl_pwrite (vol, na->rl, offset, size, buf);
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			   Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (npasses > 1) && (sig_recvd == 0) )
			{
				/*ntfs_inode_mark_dirty(na->ni);*/
				ntfs_inode_sync (na->ni);
				error.errcode.gerror = wfs_ntfs_flush_fs ( FS, &error );
			}
			if (ret != size)
			{
				break;
			}
		}
		if ( mybuf != NULL )
		{
			free (mybuf);
		}
		if (ret != size)
		{
			break;
		}

		wiped += ret;
		rlc++;
	}

	if ( sig_recvd != 0 ) return -1;
	return wiped;
}


/**
 * Part of ntfsprogs.
 * Modified: removed logging, memset replaced by fill_buffer, signal handling.
 *
 * wipe_attribute - Wipe not compressed $DATA attribute
 * \param	vol	An ntfs volume obtained from ntfs_mount
 * \param	na	Opened ntfs attribute
 *
 * \return: >0  Success, the attribute was wiped
 *          0  Nothing to wipe
 *         -1  Error, something went wrong
 */
static s64 WFS_ATTR ((nonnull))
wipe_attribute (const ntfs_volume * const vol, ntfs_attr * const na, unsigned char * const buf)
{
	s64 size, ret = 0;
	unsigned long int j;
	s64 offset = na->data_size;
	wfs_fsid_t FS;
	int selected[NPAT];
	error_type error;

	if ( (vol == NULL) || (na == NULL) || (buf == NULL) ) return 0;

	FS.ntfs = *vol;

	if (offset == 0) return 0;

	if (NAttrEncrypted (na) != 0)
	{
		offset = (((offset - 1) >> 10) + 1) << 10;
	}
	size = (vol->cluster_size - (u64)offset) % vol->cluster_size;

	for ( j = 0; (j < npasses) && (sig_recvd == 0); j++ )
	{

		fill_buffer ( j, buf, (size_t) size, selected );	/* buf OK */
		if ( sig_recvd != 0 )
		{
	       		break;
		}

		ret = ntfs_rl_pwrite (vol, na->rl, offset, size, buf);
		if ( (ret != size) || (sig_recvd!=0) )
		{
			return -1;
		}
		/* Flush after each writing, if more than 1 overwriting needs to be done.
		   Allow I/O bufferring (efficiency), if just one pass is needed. */
		if ( (npasses > 1) && (sig_recvd == 0) )
		{
			/*ntfs_inode_mark_dirty(na->ni);*/
			ntfs_inode_sync (na->ni);
			error.errcode.gerror = wfs_ntfs_flush_fs ( FS, &error );
		}
	}
	if ( sig_recvd != 0 ) return -1;
	return ret;
}

/**
 * Part of ntfsprogs.
 * Modified: removed logging, signal handling, check for memset, added "(ntfs_bmplcn < 0) ||".
 *
 * utils_cluster_in_use - Determine if a cluster is in use
 * \param vol  An ntfs volume obtained from ntfs_mount
 * \param lcn  The Logical Cluster Number to test
 *
 * The metadata file $Bitmap has one binary bit representing each cluster on
 * disk.  The bit will be set for each cluster that is in use.  The function
 * reads the relevant part of $Bitmap into a buffer and tests the bit.
 *
 * This function has a static buffer in which it caches a section of $Bitmap.
 * If the lcn, being tested, lies outside the range, the buffer will be
 * refreshed.
 *
 * \return  1  Cluster is in use
 *	    0  Cluster is free space
 *	   -1  Error occurred
 */
static int WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
utils_cluster_in_use (const ntfs_volume * const vol, const long long lcn)
{

#define	 BUFSIZE	512
	static unsigned char ntfs_buffer[BUFSIZE];
	static long long ntfs_bmplcn = -BUFSIZE - 1;	/* Which bit of $Bitmap is in the buffer */

	int byte, bit;
	ntfs_attr *attr = NULL;

#ifndef HAVE_MEMSET
	int i;
#endif
	s64 sizeof_ntfs_buffer = BUFSIZE;

	if ( vol == NULL) return 1 /* always used */;

	/* Does lcn lie in the section of $Bitmap we already have cached? */
	if (	(ntfs_bmplcn < 0) ||
		(lcn < ntfs_bmplcn) ||
		(lcn >= (ntfs_bmplcn + (BUFSIZE << 3)) )
	   )
	{

#if (defined HAVE_NTFS_NTFS_VOLUME_H)
		attr = ntfs_attr_open (vol->lcnbmp_ni, NTFS_AT_DATA, NTFS_AT_UNNAMED, 0);
#else
		attr = ntfs_attr_open (vol->lcnbmp_ni, AT_DATA, AT_UNNAMED, 0);
#endif
		if ( (attr == NULL) || (sig_recvd != 0) )
		{
			return -1;
		}

		/* Mark the buffer as in use, in case the read is shorter. */
#ifdef HAVE_MEMSET
		memset (ntfs_buffer, 0xFF, BUFSIZE);
#else
		for ( i=0; (i < BUFSIZE) && (sig_recvd==0); i++ )
		{
			ntfs_buffer[i] = '\xff';
		}
#endif
		if ( sig_recvd != 0 ) return -1;
		ntfs_bmplcn = lcn & (~((BUFSIZE << 3) - 1));

		if (ntfs_attr_pread (attr, (ntfs_bmplcn>>3), sizeof_ntfs_buffer, ntfs_buffer) < 0)
		{
			ntfs_attr_close (attr);
			return -1;
		}

		ntfs_attr_close (attr);
	}

	bit  = 1 << (lcn & 7);
	byte = (lcn >> 3) & (BUFSIZE - 1);
	if ( sig_recvd != 0 ) return -1;
	return (ntfs_buffer[byte] & bit);
}

/**
 * Part of ntfsprogs.
 * Modified: removed logging, signal handling, removed data.
 *
 * free_file - Release the resources used by a file object
 * \param file  The unwanted file object
 *
 * This will free up the memory used by a file object and iterate through the
 * object's children, freeing their resources too.
 *
 * \return  none
 */
static void WFS_ATTR ((nonnull))
free_file (struct ufile *file)
{
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	struct ntfs_list_head *item = NULL, *tmp = NULL;
#else
	struct list_head *item = NULL, *tmp = NULL;
#endif
	struct filename *f = NULL;
	struct data *d = NULL;

	if ( (file==NULL) || (sig_recvd!=0) )
		return;

#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	ntfs_list_for_each_safe (item, tmp, &(file->name))
#else
	list_for_each_safe (item, tmp, &(file->name))
#endif
	{ /* List of filenames */

#if (defined HAVE_NTFS_NTFS_VOLUME_H)
		f = ntfs_list_entry (item, struct filename, list);
#else
		f = list_entry (item, struct filename, list);
#endif
		if (f->name != NULL)
			free (f->name);
		if (f->parent_name != NULL) {
			free (f->parent_name);
		}
		free (f);
	}

#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	ntfs_list_for_each_safe (item, tmp, &(file->data))
#else
	list_for_each_safe (item, tmp, &(file->data))
#endif
	{ /* List of data streams */

#if (defined HAVE_NTFS_NTFS_VOLUME_H)
		d = ntfs_list_entry (item, struct data, list);
#else
		d = list_entry (item, struct data, list);
#endif
		if (d->name != NULL)
			free (d->name);
		if (d->runlist != NULL)
			free (d->runlist);
		free (d);
	}
	free (file->mft);
	free (file);
}

/**
 * Destroys the specified record's filenames and data.
 *
 * \param FS The filesystem.
 * \param record The record (i-node number), which filenames & data to destroy.
 * \param buf Buffer for wipe data.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
static errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
destroy_record (const wfs_fsid_t FS, const s64 record, unsigned char * const buf,
	error_type * const error)
{
	struct ufile *file = NULL;
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	ntfs_runlist_element *rl = NULL;
#else
	runlist_element *rl = NULL;
#endif
	ntfs_attr *mft = NULL;

	ntfs_attr_search_ctx *ctx = NULL;
	errcode_enum ret_wfs = WFS_SUCCESS;
	unsigned long int pass, i;
	s64 j;
	u32 a_offset;
	int selected[NPAT];

	/*if ( buf == NULL ) return WFS_BADPARAM;*/

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	file = (struct ufile *) malloc (sizeof (struct ufile));
	if (file==NULL)
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		return WFS_MALLOC;
	}

#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	NTFS_INIT_LIST_HEAD (&(file->name));
	NTFS_INIT_LIST_HEAD (&(file->data));
#else
	INIT_LIST_HEAD (&(file->name));
	INIT_LIST_HEAD (&(file->data));
#endif
	file->inode = record;

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	file->mft = (NTFS_MFT_RECORD *) malloc (FS.ntfs.mft_record_size);
#else
	file->mft = (MFT_RECORD *) malloc (FS.ntfs.mft_record_size);
#endif
	if (file->mft == NULL)
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		free_file (file);
		return WFS_MALLOC;
	}

#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	mft = ntfs_attr_open (FS.ntfs.mft_ni, NTFS_AT_DATA, NTFS_AT_UNNAMED, 0);
#else
	mft = ntfs_attr_open (FS.ntfs.mft_ni, AT_DATA, AT_UNNAMED, 0);
#endif
	if (mft == NULL)
	{
		free_file (file);
		return WFS_ATTROPEN;
	}

	/* Read the MFT reocrd of the i-node */
	if (ntfs_attr_mst_pread (mft, FS.ntfs.mft_record_size * record, 1LL,
		FS.ntfs.mft_record_size, file->mft) < 1)
	{

		ntfs_attr_close (mft);
		free_file (file);
		return WFS_ATTROPEN;
	}
	ntfs_attr_close (mft);
	mft = NULL;

	ctx = ntfs_attr_get_search_ctx (NULL, file->mft);
	if (ctx == NULL)
	{
		free_file (file);
		return WFS_CTXERROR;
	}

	/* Wiping file names */
	while ( sig_recvd == 0 )
	{

#if (defined HAVE_NTFS_NTFS_VOLUME_H)
        	if (ntfs_attr_lookup (NTFS_AT_FILE_NAME, NULL, 0, 0, 0LL, NULL, 0, ctx) != 0)
#else
        	if (ntfs_attr_lookup (AT_FILE_NAME, NULL, 0, 0, 0LL, NULL, 0, ctx) != 0)
#endif
        	{
			break;	/* None / no more of that type */
		}
		if ( ctx->attr == NULL ) break;

		/* We know this will always be resident.
		   Find the offset of the data, including the MFT record. */
		a_offset = ((u32) ctx->attr + le16_to_cpu (ctx->attr->value_offset) );

		for ( pass = 0; (pass < npasses) && (sig_recvd == 0); pass++ )
		{

			fill_buffer ( pass, (unsigned char *) a_offset, ctx->attr->value_length,
				selected );
			if ( sig_recvd != 0 )
			{
		       		break;
			}

#if (defined HAVE_NTFS_NTFS_VOLUME_H)
			if ( ntfs_mft_records_write (&(FS.ntfs), NTFS_MK_MREF (record, 0),
					1LL, ctx->mrec) != 0 )
#else
			if ( ntfs_mft_records_write (&(FS.ntfs), MK_MREF (record, 0),
					1LL, ctx->mrec) != 0 )
#endif
			{
				ret_wfs = WFS_BLKWR;
				break;
			}

			/* Flush after each writing, if more than 1 overwriting needs to be done.
			   Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (npasses > 1) && (sig_recvd == 0) )
			{
				error->errcode.gerror = wfs_ntfs_flush_fs ( FS, error );
			}
		}
		/* Wiping file name length */
		for ( pass = 0; (pass < npasses) && (sig_recvd == 0); pass++ )
		{

			fill_buffer ( pass, (unsigned char *) ctx->attr->value_length, sizeof(u32),
				selected );
			if ( sig_recvd != 0 )
			{
		       		break;
			}

#if (defined HAVE_NTFS_NTFS_VOLUME_H)
			if ( ntfs_mft_records_write (&(FS.ntfs), NTFS_MK_MREF (record, 0),
					1LL, ctx->mrec) != 0 )
#else
			if ( ntfs_mft_records_write (&(FS.ntfs), MK_MREF (record, 0),
					1LL, ctx->mrec) != 0 )
#endif
			{
				ret_wfs = WFS_BLKWR;
				break;
			}

			/* Flush after each writing, if more than 1 overwriting needs to be done.
			   Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (npasses > 1) && (sig_recvd == 0) )
			{
				error->errcode.gerror = wfs_ntfs_flush_fs ( FS, error );
			}
		}
		ctx->attr->value_length = 0;
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
		if ( ntfs_mft_records_write (&(FS.ntfs), NTFS_MK_MREF (record, 0),
				1LL, ctx->mrec) != 0 )
#else
		if ( ntfs_mft_records_write (&(FS.ntfs), MK_MREF (record, 0),
				1LL, ctx->mrec) != 0 )
#endif
		{
			ret_wfs = WFS_BLKWR;
			break;
		}
	}

	ntfs_attr_reinit_search_ctx (ctx);

	/* Wiping file data */
	while ( sig_recvd == 0 )
	{

#if (defined HAVE_NTFS_NTFS_VOLUME_H)
        	if (ntfs_attr_lookup (NTFS_AT_DATA, NULL, 0, 0, 0LL, NULL, 0, ctx) != 0)
#else
        	if (ntfs_attr_lookup (AT_DATA, NULL, 0, 0, 0LL, NULL, 0, ctx) != 0)
#endif
        	{
			break;	/* None / no more of that type */
		}
		if ( ctx->attr == NULL ) break;

		if (ctx->attr->non_resident == 0)
		{	/* attribute is resident (part of MFT record) */

			/* find the offset of the data, including the MFT record */
			a_offset = ((u32) ctx->attr + le16_to_cpu (ctx->attr->value_offset) );

			/* Wiping the data itself */
			for ( pass = 0; (pass < npasses) && (sig_recvd == 0); pass++ )
			{

				fill_buffer ( pass, (unsigned char *) a_offset, ctx->attr->value_length,
					selected );
				if ( sig_recvd != 0 )
				{
			       		break;
				}

#if (defined HAVE_NTFS_NTFS_VOLUME_H)
				if ( ntfs_mft_records_write (&(FS.ntfs), NTFS_MK_MREF (record, 0),
						1LL, ctx->mrec) != 0 )
#else
				if ( ntfs_mft_records_write (&(FS.ntfs), MK_MREF (record, 0),
						1LL, ctx->mrec) != 0 )
#endif
				{
					ret_wfs = WFS_BLKWR;
					break;
				}

				/* Flush after each writing, if more than 1 overwriting needs to be done.
				   Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( (npasses > 1) && (sig_recvd == 0) )
				{
					error->errcode.gerror = wfs_ntfs_flush_fs ( FS, error );
				}
			}
			/* Wiping data length */
			for ( pass = 0; (pass < npasses) && (sig_recvd == 0); pass++ )
			{

				fill_buffer ( pass, (unsigned char *) &(ctx->attr->value_length),
					sizeof(u32), selected );
				if ( sig_recvd != 0 )
				{
			       		break;
				}

#if (defined HAVE_NTFS_NTFS_VOLUME_H)
				if ( ntfs_mft_records_write (&(FS.ntfs), NTFS_MK_MREF (record, 0),
						1LL, ctx->mrec) != 0 )
#else
				if ( ntfs_mft_records_write (&(FS.ntfs), MK_MREF (record, 0),
						1LL, ctx->mrec) != 0 )
#endif
				{
					ret_wfs = WFS_BLKWR;
					break;
				}

				/* Flush after each writing, if more than 1 overwriting needs to be done.
				   Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( (npasses > 1) && (sig_recvd == 0) )
				{
					error->errcode.gerror = wfs_ntfs_flush_fs ( FS, error );
				}
			}
			ctx->attr->value_length = 0;
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
			if ( ntfs_mft_records_write (&(FS.ntfs), NTFS_MK_MREF (record, 0),
					1LL, ctx->mrec) != 0 )
#else
			if ( ntfs_mft_records_write (&(FS.ntfs), MK_MREF (record, 0),
					1LL, ctx->mrec) != 0 )
#endif
			{
				ret_wfs = WFS_BLKWR;
				break;
			}

		}
		else
		{	/* Non-resident here */

			rl = ntfs_mapping_pairs_decompress (&(FS.ntfs), ctx->attr, NULL);
			if (rl == NULL)
			{
				continue;
			}

			if (rl[0].length <= 0)
			{
				continue;
			}

			for (i = 0; (rl[i].length > 0) && (sig_recvd == 0) && (ret_wfs == WFS_SUCCESS); i++)
			{

				for (j = rl[i].lcn; (j < rl[i].lcn + rl[i].length) &&
					(sig_recvd == 0) && (ret_wfs == WFS_SUCCESS); j++)
				{

					if (utils_cluster_in_use (&(FS.ntfs), j) == 0 )
					{
						for ( pass = 0; (pass < npasses) && (sig_recvd == 0); pass++ )
						{

							fill_buffer ( pass, buf /* buf OK */,
								(size_t) wfs_ntfs_get_block_size (FS),
								selected );
							if ( sig_recvd != 0 )
							{
			       					break;
							}
							if (ntfs_cluster_write (&(FS.ntfs), j, 1LL, buf) < 1)
							{
								ret_wfs = WFS_BLKWR;
								break;
							}

					/* Flush after each writing, if more than 1 overwriting needs to be done.
					   Allow I/O bufferring (efficiency), if just one pass is needed. */
							if ( (npasses > 1) && (sig_recvd == 0) )
							{
								error->errcode.gerror =
									wfs_ntfs_flush_fs ( FS, error );
							}
						}
					}
				}
			}
			/* Wipe the data length here */
			for ( pass = 0; (pass < npasses) && (sig_recvd == 0); pass++ )
			{

				fill_buffer ( pass, (unsigned char *) &(ctx->attr->lowest_vcn),
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
					sizeof(NTFS_VCN), selected );
#else
					sizeof(VCN), selected );
#endif
				fill_buffer ( pass, (unsigned char *) &(ctx->attr->highest_vcn),
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
					sizeof(NTFS_VCN), selected );
#else
					sizeof(VCN), selected );
#endif
				fill_buffer ( pass, (unsigned char *) &(ctx->attr->allocated_size),
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
					sizeof(NTFS_VCN), selected );
#else
					sizeof(VCN), selected );
#endif
				fill_buffer ( pass, (unsigned char *) &(ctx->attr->data_size),
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
					sizeof(NTFS_VCN), selected );
#else
					sizeof(VCN), selected );
#endif
				fill_buffer ( pass, (unsigned char *) &(ctx->attr->initialized_size),
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
					sizeof(NTFS_VCN), selected );
#else
					sizeof(VCN), selected );
#endif
				fill_buffer ( pass, (unsigned char *) &(ctx->attr->compressed_size),
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
					sizeof(NTFS_VCN), selected );
#else
					sizeof(VCN), selected );
#endif
				if ( sig_recvd != 0 )
				{
			       		break;
				}

#if (defined HAVE_NTFS_NTFS_VOLUME_H)
				if ( ntfs_mft_records_write (&(FS.ntfs), NTFS_MK_MREF (record, 0),
						1LL, ctx->mrec) != 0 )
#else
				if ( ntfs_mft_records_write (&(FS.ntfs), MK_MREF (record, 0),
						1LL, ctx->mrec) != 0 )
#endif
				{
					ret_wfs = WFS_BLKWR;
					break;
				}

				/* Flush after each writing, if more than 1 overwriting needs to be done.
				   Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( (npasses > 1) && (sig_recvd == 0) )
				{
					error->errcode.gerror = wfs_ntfs_flush_fs ( FS, error );
				}
			}
			ctx->attr->lowest_vcn = 0;
			ctx->attr->highest_vcn = 0;
			ctx->attr->allocated_size = 0;
			ctx->attr->data_size = 0;
			ctx->attr->initialized_size = 0;
			ctx->attr->compressed_size = 0;
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
			if ( ntfs_mft_records_write (&(FS.ntfs), NTFS_MK_MREF (record, 0),
					1LL, ctx->mrec) != 0 )
#else
			if ( ntfs_mft_records_write (&(FS.ntfs), MK_MREF (record, 0),
					1LL, ctx->mrec) != 0 )
#endif
			{
				ret_wfs = WFS_BLKWR;
				break;
			}
		}	/* end of resident check */
	} /* end of 'wiping file data' loop */

	ntfs_attr_put_search_ctx (ctx);
	free_file (file);

	if ( sig_recvd != 0 )
	{
		ret_wfs = WFS_SIGNAL;
	}

	return ret_wfs;
}

/**
 * Wipes the free space in partially used blocks on the given NTFS filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result))
wfs_ntfs_wipe_part (wfs_fsid_t FS, error_type * const error)
{
	errcode_enum ret_wfs = WFS_SUCCESS;

	u64 nr_mft_records, inode_num;
	ntfs_inode *ni = NULL;
	ntfs_attr *na = NULL;
	unsigned char * buf;

	nr_mft_records = FS.ntfs.mft_na->initialized_size >>
			FS.ntfs.mft_record_size_bits;

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	buf = (unsigned char *) malloc ( wfs_ntfs_get_block_size (FS) );
	if ( buf == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		return WFS_MALLOC;
	}
	/* 16 is the first i-node for user use. */
	for (inode_num = 16; (inode_num < nr_mft_records) && (sig_recvd==0)
		&& (ret_wfs == WFS_SUCCESS); inode_num++ )
	{

		ret_wfs = WFS_SUCCESS;
		ni = ntfs_inode_open (&(FS.ntfs), inode_num);

		if (ni == NULL)
		{
			ret_wfs = WFS_INOREAD;
			continue;
                }
		if ( sig_recvd != 0 ) break;
		/* wipe only if base MFT record */
		if (ni->mrec->base_mft_record == 0)
		{
			if ( sig_recvd != 0 )
			{
	       			break;
			}

#if (defined HAVE_NTFS_NTFS_VOLUME_H)
			na = ntfs_attr_open (ni, NTFS_AT_DATA, NTFS_AT_UNNAMED, 0);
#else
			na = ntfs_attr_open (ni, AT_DATA, AT_UNNAMED, 0);
#endif
			if ( (na != NULL) && (sig_recvd==0) )
			{

				/* Only nonresident allowed. Resident ones are in the
				   MFT record itself, so this doesn't apply to them, I think. */
				if (NAttrNonResident (na) != 0)
				{

					if ( sig_recvd != 0 )
					{
				       		break;
					}

					if (ntfs_attr_map_whole_runlist (na) != 0)
					{
						ret_wfs = WFS_NTFSRUNLIST;
						ntfs_attr_close (na);
						ntfs_inode_close (ni);
					}

					if ( (ret_wfs == WFS_SUCCESS) && (NAttrCompressed (na) != 0) )
					{
						/*wiped = */wipe_compressed_attribute (&(FS.ntfs), na, buf);
					}
					else
					{
						/*wiped = */wipe_attribute (&(FS.ntfs), na, buf);
					}
				}
				ntfs_attr_close (na);
			}
			else
			{
				ret_wfs = WFS_ATTROPEN;
			}
		}
		ntfs_inode_close (ni);

	}
	if ( sig_recvd != 0 ) ret_wfs = WFS_SIGNAL;
	free (buf);
	return ret_wfs;
}

/**
 * Wipes the free space on the given NTFS filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_ntfs_wipe_fs (const wfs_fsid_t FS, error_type * const error)
{
	errcode_enum ret_wfs = WFS_SUCCESS;
	s64 i, size, result;
	unsigned long int j;
	int selected[NPAT];
	unsigned char * buf;

	if ( error == NULL )
	{
		return WFS_BADPARAM;
	}

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	buf = (unsigned char *) malloc ( wfs_ntfs_get_block_size (FS) );
	if ( buf == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		return WFS_MALLOC;
	}

	for (i = 0; (i < FS.ntfs.nr_clusters) && (sig_recvd==0); i++)
	{

		/* check if cluster in use */
		if (utils_cluster_in_use (&(FS.ntfs), i) != 0)
		{
			continue;
		}

		/* cluster is unused - wipe it */
		for ( j = 0; (j < npasses) && (sig_recvd == 0); j++ )
		{

			fill_buffer ( j, buf, (size_t) wfs_ntfs_get_block_size (FS), selected );/* buf OK */
			if ( sig_recvd != 0 )
			{
		       		break;
			}

			size = FS.ntfs.cluster_size;
			/* writing modified cluster here: */
			result = ntfs_pwrite (FS.ntfs.dev, FS.ntfs.cluster_size * i, size, buf);
			if (result != size)
			{
				free (buf);
				return WFS_BLKWR;
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			   Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (npasses > 1) && (sig_recvd == 0) )
			{
				error->errcode.gerror = wfs_ntfs_flush_fs ( FS, error );
			}
		}
	}
	if ( sig_recvd != 0 ) ret_wfs = WFS_SIGNAL;
	free (buf);

	return ret_wfs;
}

/**
 * Starts search for deleted inodes and undelete data on the given NTFS filesystem.
 * \param FS The filesystem.
 * \param node Directory i-node (unused, probably due to the nature of the NTFS).
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result))
wfs_ntfs_wipe_unrm (const wfs_fsid_t FS, const fselem_t node WFS_ATTR ((unused)),
	error_type * const error )
{
	errcode_enum ret_wfs = WFS_SUCCESS;
	int ret;
	ntfs_attr *bitmapattr = NULL;
	s64 bmpsize, size, nr_mft_records, i, j, k;
	unsigned char b;

	unsigned char * buf;

#define MYBUF_SIZE 8192
	unsigned char *mybuf;
#define MINIM(x, y) ( ((x)<(y))?(x):(y) )

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	mybuf = (unsigned char *) malloc (MYBUF_SIZE);
	if (mybuf == NULL)
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		return WFS_MALLOC;
	}

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	buf = (unsigned char *) malloc ( wfs_ntfs_get_block_size (FS) );
	if ( buf == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		free (mybuf);
		return WFS_MALLOC;
	}

#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	bitmapattr = ntfs_attr_open (FS.ntfs.mft_ni, NTFS_AT_BITMAP, NTFS_AT_UNNAMED, 0);
#else
	bitmapattr = ntfs_attr_open (FS.ntfs.mft_ni, AT_BITMAP, AT_UNNAMED, 0);
#endif
	if (bitmapattr == NULL)
	{
		free (buf);
		free (mybuf);
		return WFS_ATTROPEN;
	}
	bmpsize = bitmapattr->initialized_size;

	nr_mft_records = FS.ntfs.mft_na->initialized_size >> FS.ntfs.mft_record_size_bits;

	if ( sig_recvd != 0 )
	{
		ntfs_attr_close (bitmapattr);
		free (buf);
		free (mybuf);
		return WFS_SIGNAL;
	}

	/* just like ntfsundelete; detects i-node numbers fine */
	for (i = 0; (i < bmpsize) && (sig_recvd==0) && (ret_wfs==WFS_SUCCESS); i += MYBUF_SIZE)
	{

		/* read a part of the file bitmap */
		size = ntfs_attr_pread (bitmapattr, i, MINIM ((bmpsize - i), MYBUF_SIZE), mybuf);
		if (size < 0) break;

		/* parse each byte of the just-read part of the bitmap */
		for (j = 0; (j < size) && (sig_recvd==0) && (ret_wfs==WFS_SUCCESS); j++)
		{
			b = mybuf[j];
			/* parse each bit of the byte Bit 1 means 'in use'. */
			for (k = 0; (k < CHAR_BIT) && (sig_recvd==0) && (ret_wfs==WFS_SUCCESS); k++, b>>=1)
			{
				/* (i+j)*8+k is the i-node bit number */
				if (((i+j)*CHAR_BIT+k) >= nr_mft_records)
				{
					goto done;
				}
				if ((b & 1) != 0)
				{
					continue;	/* i-node is in use, skip it */
				}
				if ( sig_recvd != 0 ) break;
				/* wiping the i-node here: */
				ret = destroy_record (FS, (i+j)*CHAR_BIT+k, buf, error);
				if ( ret != WFS_SUCCESS )
				{
					ret_wfs = ret;
				}
			}
		}
	}
done:
	ntfs_attr_close (bitmapattr);
	free (buf);
	free (mybuf);

	if ( sig_recvd != 0 ) ret_wfs = WFS_SIGNAL;
	return ret_wfs;
}

/**
 * Opens an NTFS filesystem on the given device.
 * \param devname Device name, like /dev/hdXY
 * \param FS Pointer to where the result will be put.
 * \param whichfs Pointer to an int saying which fs is curently in use.
 * \param data Pointer to fsdata structure containing information which may be needed to
 *	open the filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_ntfs_open_fs (
			const char * const dev_name,
			wfs_fsid_t * const FS,
			CURR_FS * const which_fs,
			const fsdata * const data WFS_ATTR ((unused)),
			error_type * const error
		 )
{

	errcode_enum ret = WFS_SUCCESS;
	int res = 0;
	ntfs_volume *nv = NULL;

	if ( (dev_name == NULL) || (FS == NULL) || (which_fs == NULL) || (error == NULL) )
	{
		return WFS_BADPARAM;
	}
	*which_fs = CURR_NONE;

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	nv = ntfs_mount (dev_name, 0);
	if ( (nv == NULL) && (sig_recvd == 0) )
	{
#ifdef HAVE_ERRNO_H
		if ( errno != 0 )
		{
			error->errcode.gerror = errno;
		}
#endif
		ret = WFS_OPENFS;
#ifdef HAVE_SYS_MOUNT_H
		res = umount ( dev_name );
		if ( (res == 0) && (sig_recvd == 0) )
		{
			nv = ntfs_mount (dev_name, 0);
			if ( nv != NULL )
			{
				*which_fs = CURR_NTFS;
				FS->ntfs = *nv;
#ifdef HAVE_MEMCPY
/*				memcpy(&(FS->ntfs), nv, sizeof(ntfs_volume));*/
#endif
				ret = WFS_SUCCESS;
			}
		}
#endif
	}
	else if ( nv != NULL )
	{
		*which_fs = CURR_NTFS;
		FS->ntfs = *nv;
#ifdef HAVE_MEMCPY
/*		memcpy(&(FS->ntfs), nv, sizeof(ntfs_volume));*/
#endif
		ret = WFS_SUCCESS;
	}
	else if ( sig_recvd != 0 )
	{
		ret = WFS_SIGNAL;
	}

	return ret;
}

/**
 * Checks if the given NTFS filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_ntfs_chk_mount ( const char * const dev_name, error_type * const error )
{
	errcode_enum ret = WFS_SUCCESS;
	unsigned long int mt_flags = 0;		/* Mount flags */

	if ( (dev_name == NULL) || (error == NULL) ) return WFS_BADPARAM;

	/* reject if mounted for read and write (when we can't go on with our work) */
	error->errcode.gerror = ntfs_check_if_mounted ( dev_name, &mt_flags );
	if ( error->errcode.gerror != 0 )
	{

		ret = WFS_MNTCHK;
	}

	if ( 	(ret == WFS_SUCCESS) &&
		((mt_flags & NTFS_MF_MOUNTED) != 0) &&
		((mt_flags & NTFS_MF_READONLY) == 0)
	   )
	{
		error->errcode.gerror = 1L;
		ret = WFS_MNTRW;
	}

	return ret;
}

/**
 * Closes the NTFS filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((nonnull))
wfs_ntfs_close_fs (wfs_fsid_t FS, error_type * const error)
{
	errcode_enum ret = WFS_SUCCESS;

	if ( error == NULL )
	{
		return WFS_BADPARAM;
	}

	error->errcode.gerror = ntfs_umount (&(FS.ntfs), FALSE);
	if ( error->errcode.gerror != 0 )
	{
		show_error ( *error, err_msg_close, fsname );
		ret = WFS_FSCLOSE;
	}

	return ret;
}

/**
 * Checks if the NTFS filesystem has errors.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_ntfs_check_err (const wfs_fsid_t FS)
{
	/* better than nothing... */
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	return (FS.ntfs.flags & NTFS_VOLUME_MODIFIED_BY_CHKDSK);
#else
	return (FS.ntfs.flags & VOLUME_MODIFIED_BY_CHKDSK);
#endif
}

/**
 * Checks if the NTFS filesystem is dirty (has unsaved changes).
 * \param FS The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_ntfs_is_dirty (const wfs_fsid_t FS)
{
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	return ((FS.ntfs.flags & NTFS_VOLUME_IS_DIRTY)
		| (FS.ntfs.flags & NTFS_VOLUME_MODIFIED_BY_CHKDSK)
# ifdef NVolWasDirty
		| NVolWasDirty(FS.ntfs.dev)
# endif
		);
#else
	return ((FS.ntfs.flags & VOLUME_IS_DIRTY)
		| (FS.ntfs.flags & VOLUME_MODIFIED_BY_CHKDSK)
# ifdef NVolWasDirty
		| NVolWasDirty(FS.ntfs.dev)
# endif
		);
#endif
}

/**
 * Flushes the NTFS filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((nonnull))
wfs_ntfs_flush_fs (const wfs_fsid_t FS, error_type * const error )
{
	errcode_enum ret = WFS_SUCCESS;

	if ( error == NULL )
	{
		return WFS_BADPARAM;
	}
#ifdef NTFS_RICH
	error->errcode.gerror = ntfs_volume_commit (&(FS.ntfs));
	if (error->errcode.gerror < 0)
	{
		ret = WFS_FLUSHFS;
	}
#endif
	error->errcode.gerror = FS.ntfs.dev->d_ops->sync (FS.ntfs.dev);
	if (error->errcode.gerror != 0)
	{
		ret = WFS_FLUSHFS;
	}
	if ( ret != WFS_SUCCESS )
	{
		show_error ( *error, err_msg_flush, fsname );
	}
#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_SYNC)
	sync ();
#endif
	return ret;
}
