/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- NTFS file system-specific functions.
 *
 * Copyright (C) 2007-2024 Bogdan Drozdowski, bogdro (at) users.sourceforge.net
 * License: GNU General Public License, v2+
 *
 * Parts of this file come from libnfts or ntfsprogs, and are:
 * Copyright (c) 2002-2005 Richard Russon
 * Copyright (c) 2003-2006 Anton Altaparmakov
 * Copyright (c) 2003 Lode Leroy
 * Copyright (c) 2004 Yura Pakhuchiy
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
#endif
#ifndef CHAR_BIT
# ifdef __CHAR_BIT__
#  define CHAR_BIT __CHAR_BIT__
# else
#  define CHAR_BIT 8
# endif
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#include "wipefreespace.h"

#if ((defined HAVE_NTFS_NTFS_VOLUME_H) || (defined HAVE_NTFS_3G_NTFS_VOLUME_H)) \
	&& ((defined HAVE_LIBNTFS) || (defined HAVE_LIBNTFS_3G))
# ifdef HAVE_NTFS_NTFS_VOLUME_H
#  include <ntfs/ntfs_volume.h>
#  include <ntfs/ntfs_version.h>
#  include <ntfs/ntfs_attrib.h>		/* ntfs_attr_search_ctx() */
#  include <ntfs/ntfs_mft.h>		/* ntfs_mft_records_write() */
#  include <ntfs/ntfs_logfile.h>	/* ntfs_empty_logfile() */
# else
#  include <ntfs-3g/ntfs_volume.h>
#  include <ntfs-3g/ntfs_attrib.h>	/* ntfs_attr_search_ctx() */
#  include <ntfs-3g/ntfs_mft.h>		/* ntfs_mft_records_write() */
#  include <ntfs-3g/ntfs_logfile.h>	/* ntfs_empty_logfile() */
# endif
#else
# if ((defined HAVE_NTFS_VOLUME_H) || (defined HAVE_NTFS_3G_VOLUME_H)) \
	&& ((defined HAVE_LIBNTFS) || (defined HAVE_LIBNTFS_3G))
#  ifdef HAVE_NTFS_VOLUME_H
#   include <ntfs/volume.h>
#   include <ntfs/version.h>
#   include <ntfs/attrib.h>		/* ntfs_attr_search_ctx() */
#   include <ntfs/mft.h>		/* ntfs_mft_records_write() */
#   include <ntfs/logfile.h>		/* ntfs_empty_logfile() */
#  else
#   include <ntfs-3g/volume.h>
#   include <ntfs-3g/attrib.h>		/* ntfs_attr_search_ctx() */
#   include <ntfs-3g/mft.h>		/* ntfs_mft_records_write() */
#   include <ntfs-3g/logfile.h>		/* ntfs_empty_logfile() */
#  endif
# else
#  if (defined HAVE_VOLUME_H) && ((defined HAVE_LIBNTFS) || (defined HAVE_LIBNTFS_3G))
#   include <volume.h>
#   ifndef HAVE_LIBNTFS_3G
#    include <version.h>
#   endif
#   include <attrib.h>
#   include <mft.h>
#   include <logfile.h>
#  else
#   error Something wrong. NTFS requested, but headers or library missing.
/* make a syntax error, because not all compilers treat #error as an error */
Something wrong. NTFS requested, but headers or library missing.
#  endif
# endif
#endif

#include "wfs_ntfs.h"
#include "wfs_signal.h"
#include "wfs_util.h"
#include "wfs_wiping.h"
#include "wfs_subprocess.h"
#include "wfs_mount_check.h"

#ifdef TEST_COMPILE
# undef WFS_ANSIC
#endif

/* ====================== list definitions ================================ */

struct wfs_ntfs_list_head
{
	struct wfs_ntfs_list_head * prev;
	struct wfs_ntfs_list_head * next;
};

#define WFS_NTFS_INIT_LIST_HEAD(ptr) \
	do { \
		(ptr)->next = (ptr); (ptr)->prev = (ptr); \
	} while (0)

#define WFS_NTFS_LIST_ENTRY(ptr, type, member) \
	((type *)((char *)(ptr) - (unsigned long int)(&((type *)0)->member)))

#define WFS_NTFS_LIST_FOR_EACH_SAFE(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

/* ======================================================================== */

struct filename
{
	char		*parent_name;
	struct wfs_ntfs_list_head list;	/* Previous/Next links */
	ntfschar	*uname;		/* Filename in unicode */
	int		 uname_len;	/* and its length */
	long long int	 size_alloc;	/* Allocated size (multiple of cluster size) */
	long long int	 size_data;	/* Actual size of data */
	long long int	 parent_mref;
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
	struct wfs_ntfs_list_head list;	/* Previous/Next links */
	char		*name;		/* Stream name in current locale */
	ntfschar	*uname;		/* Unicode stream name */
	int		 uname_len;	/* and its length */
	int		 resident;	/* Stream is resident */
	int		 compressed;	/* Stream is compressed */
	int		 encrypted;	/* Stream is encrypted */
	long long int	 size_alloc;	/* Allocated size (multiple of cluster size) */
	long long int	 size_data;	/* Actual size of data */
	long long int	 size_init;	/* Initialised size, may be less than data size */
	long long int	 size_vcn;	/* Highest VCN in the data runs */
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	ntfs_runlist_element *runlist;	/* Decoded data runs */
#else
	runlist_element *runlist;	/* Decoded data runs */
#endif
	int		 percent;	/* Amount potentially recoverable */
	void		*data;		/* If resident, a pointer to the data */
	char		 padding[4];	/* Unused: padding to 64 bit. */
};

#ifndef HAVE_LIBNTFS_3G
struct ufile
{
	long long int	 inode;		/* MFT record number */
	time_t		 date;		/* Last modification date/time */
	struct wfs_ntfs_list_head name;	/* A list of filenames */
	struct wfs_ntfs_list_head data;	/* A list of data streams */
	char		*pref_name;	/* Preferred filename */
	char		*pref_pname;	/*	     parent filename */
	long long int	 max_size;	/* Largest size we find */
	int		 attr_list;	/* MFT record may be one of many */
	int		 directory;	/* MFT record represents a directory */
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
	NTFS_MFT_RECORD	*mft;		/* Raw MFT record */
# else
	MFT_RECORD	*mft;		/* Raw MFT record */
# endif
	char		 padding[4];	/* Unused: padding to 64 bit. */
};

#else /* HAVE_LIBNTFS_3G */
struct ufile {
        long long        inode;         /* MFT record number */
        time_t           date;          /* Last modification date/time */
        struct wfs_ntfs_list_head name;          /* A list of filenames */
        struct wfs_ntfs_list_head data;          /* A list of data streams */
        char            *pref_name;     /* Preferred filename */
        char            *pref_pname;    /*           parent filename */
        long long        max_size;      /* Largest size we find */
        int              attr_list;     /* MFT record may be one of many */
        int              directory;     /* MFT record represents a directory */
        MFT_RECORD      *mft;           /* Raw MFT record */
};
#endif /* ! defined HAVE_LIBNTFS_3G */

#ifndef WFS_ANSIC
static u32 GCC_WARN_UNUSED_RESULT wfs_ntfs_get_block_size WFS_PARAMS ((const wfs_fsid_t wfs_fs));
#endif

/* ======================================================================== */

/**
 * Returns the buffer size needed to work on the smallest physical unit on a NTFS filesystem.
 * \param wfs_fs The filesystem.
 * \return Block size on the filesystem.
 */
static u32 GCC_WARN_UNUSED_RESULT
wfs_ntfs_get_block_size (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs )
#else
	wfs_fs )
	const wfs_fsid_t wfs_fs;
#endif
{
	ntfs_volume * ntfs;

	ntfs = (ntfs_volume *) wfs_fs.fs_backend;
	if ( ntfs == NULL )
	{
		return 0;
	}
	return ntfs->cluster_size;
	/* return ntfs_device_sector_size_get(ntfs); */
}

/* ======================================================================== */

#ifdef WFS_WANT_PART
# ifndef WFS_ANSIC
static s64 wipe_compressed_attribute WFS_PARAMS((ntfs_attr * const na,
	unsigned char * const buf, wfs_fsid_t wfs_fs));
# endif

/**
 * Part of ntfsprogs.
 * Modified: removed logging, memset replaced by wfs_fill_buffer, signal handling.
 *
 * wipe_compressed_attribute - Wipe compressed $DATA attribute
 * \param	vol	An ntfs volume obtained from ntfs_mount
 * \param	na	Opened ntfs attribute
 *
 * \return >0  Success, the attribute was wiped
 *          0  Nothing to wipe
 *         -1  Error, something went wrong
 */
static s64
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wipe_compressed_attribute (
# ifdef WFS_ANSIC
	ntfs_attr * const na,
	unsigned char * const buf,
	wfs_fsid_t wfs_fs
	)
# else
	na, buf, wfs_fs)
	ntfs_attr * const na;
	unsigned char * const buf;
	wfs_fsid_t wfs_fs;
# endif
{
	unsigned char *mybuf = NULL;
	s64 size, offset, ret = 0, wiped = 0;
	u16 block_size;
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
	NTFS_VCN cur_vcn = 0;
	ntfs_runlist *rlc;
# else
	VCN cur_vcn = 0;
	runlist *rlc;
# endif
	s64 cu_mask;

	size_t bufsize = 0;
	unsigned long int j;
	s64 two = 2;
# ifdef HAVE_LIBNTFS_3G
	s64 s64zero = 0;
# endif
	/*wfs_fsid_t wfs_fs;*/
	int go_back;
	int selected[WFS_NPAT] = {0};
	ntfs_volume * ntfs;
	wfs_errcode_t gerror = 0;
	wfs_errcode_t * error_ret;
	size_t fs_block_size;

	ntfs = (ntfs_volume *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( (ntfs == NULL) || (na == NULL) || (buf == NULL) )
	{
		return 0;
	}
	fs_block_size = wfs_ntfs_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return -1;
	}

	rlc = na->rl;
	cu_mask = na->compression_block_clusters - 1;

	while ( (rlc->length != 0) && (sig_recvd == 0) )
	{

		go_back = 0;
		cur_vcn += rlc->length;
		if ( ((cur_vcn & cu_mask) != 0) ||
			(
			 (((rlc + 1)->length) != 0) &&
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
			 (rlc->lcn != NTFS_LCN_HOLE)
# else
			 (rlc->lcn != LCN_HOLE)
# endif
			)
		   )
		{
			rlc++;
			continue;
		}
		if ( sig_recvd != 0 )
		{
			if ( error_ret != NULL )
			{
				*error_ret = WFS_SIGNAL;
			}
			return -1;
		}

# if (defined HAVE_NTFS_NTFS_VOLUME_H)
		if (rlc->lcn == NTFS_LCN_HOLE)
# else
		if (rlc->lcn == LCN_HOLE)
# endif
		{
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
			ntfs_runlist *rlt;
# else
			runlist *rlt;
# endif

			offset = cur_vcn - rlc->length;
			if (offset == (offset & (~cu_mask)))
			{
				rlc++;
				continue;
			}
			offset = (offset & (~cu_mask)) << ntfs->cluster_size_bits;
			rlt = rlc;
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
			while ((rlt - 1)->lcn == NTFS_LCN_HOLE)
			{
				rlt--;
			}
# else
			while ((rlt - 1)->lcn == LCN_HOLE)
			{
				rlt--;
			}
# endif
			while ( sig_recvd == 0 )
			{
				ret = ntfs_rl_pread (ntfs, na->rl, offset, two, &block_size);
				block_size = le16_to_cpu (block_size);
				if (ret != two)
				{
					if ( error_ret != NULL )
					{
						*error_ret = WFS_BLKITER;
					}
					return -1;
				}
				if (block_size == 0)
				{
					offset += 2;
					break;
				}
				block_size = (u16) ((block_size & 0x0FFF) + 3);
				offset += block_size;
				if (offset >= ( ((rlt->vcn) << ntfs->cluster_size_bits) - 2) )
				{
					go_back = 1;
					break;
				}
			}
			if ( go_back != 0 )
			{
				continue;
			}
			size = (rlt->vcn << ntfs->cluster_size_bits) - offset;
		}
		else
		{
			size = na->allocated_size - na->data_size;
			offset = (cur_vcn << ntfs->cluster_size_bits) - size;
		}

		if ( (size < 0) || (sig_recvd != 0) )
		{
			return -1;
		}

		if ( size == 0 )
		{
			wiped += size;
			rlc++;
			continue;
		}
		if ( size > (s64)fs_block_size )
		{
			bufsize = (size_t) size;
			mybuf = (unsigned char *) malloc (bufsize);
			if ( mybuf == NULL )
			{
				continue;
			}
		}

		for ( j = 0; (j < wfs_fs.npasses) && (sig_recvd == 0); j++ )
		{
			if ( wfs_fs.no_wipe_zero_blocks != 0 )
			{
				if ( mybuf != NULL )
				{
					ret = ntfs_rl_pread (ntfs, na->rl, offset, 1LL * (s64)bufsize, mybuf);
					if (ret != 1LL * (s64)bufsize)
					{
						if ( error_ret != NULL )
						{
							*error_ret = WFS_BLKRD;
						}
						break;
					}
					if ( wfs_is_block_zero (mybuf, bufsize) != 0 )
					{
						/* this block is all-zeros - don't wipe, as requested */
						j = wfs_fs.npasses * 2;
						break;
					}
				}
				else
				{
					ret = ntfs_rl_pread (ntfs, na->rl, offset, size, buf);
					if (ret != size)
					{
						if ( error_ret != NULL )
						{
							*error_ret = WFS_BLKRD;
						}
						break;
					}
					if ( wfs_is_block_zero (buf, (size_t)size) != 0 )
					{
						/* this block is all-zeros - don't wipe, as requested */
						j = wfs_fs.npasses * 2;
						break;
					}
				}
			}
			if ( mybuf != NULL )
			{
				wfs_fill_buffer (j, mybuf, bufsize, selected, wfs_fs);	/* buf OK */
			}
			else
			{
				wfs_fill_buffer (j, buf, (size_t) size, selected, wfs_fs);	/* buf OK */
			}
			if ( sig_recvd != 0 )
			{
		       		break;
			}
			if ( mybuf != NULL )
			{
# ifndef HAVE_LIBNTFS_3G
				ret = ntfs_rl_pwrite (ntfs, na->rl, offset, size, mybuf);
# else
				ret = ntfs_rl_pwrite (ntfs, na->rl, s64zero, offset, size, mybuf);
# endif
			}
			else
			{
# ifndef HAVE_LIBNTFS_3G
				ret = ntfs_rl_pwrite (ntfs, na->rl, offset, size, buf);
# else
				ret = ntfs_rl_pwrite (ntfs, na->rl, s64zero, offset, size, buf);
# endif
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			   Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
			{
				/*ntfs_inode_mark_dirty(na->ni);*/
				ntfs_inode_sync (na->ni);
				gerror = wfs_ntfs_flush_fs (wfs_fs);
			}
			if (ret != size)
			{
				break;
			}
		}
		if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
		{
			/* last pass with zeros: */
			if ( j != wfs_fs.npasses * 2 )
			{
				/* this block is NOT all-zeros - wipe */
				if ( mybuf != NULL )
				{
					WFS_MEMSET (mybuf, 0, bufsize);
				}
				else
				{
					WFS_MEMSET (buf, 0, (size_t) size);
				}
				if ( sig_recvd == 0 )
				{
					if ( mybuf != NULL )
					{
# ifndef HAVE_LIBNTFS_3G
						ret = ntfs_rl_pwrite (ntfs, na->rl, offset, size, mybuf);
# else
						ret = ntfs_rl_pwrite (ntfs, na->rl, s64zero, offset, size, mybuf);
# endif
					}
					else
					{
# ifndef HAVE_LIBNTFS_3G
						ret = ntfs_rl_pwrite (ntfs, na->rl, offset, size, buf);
# else
						ret = ntfs_rl_pwrite (ntfs, na->rl, s64zero, offset, size, buf);
# endif
					}
					/* No need to flush the last writing of a given block. *
					if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
					{
						/ * ntfs_inode_mark_dirty(na->ni); * /
						ntfs_inode_sync (na->ni);
						gerror = wfs_ntfs_flush_fs (wfs_fs);
					} */
					if (ret != size)
					{
						if ( mybuf != NULL )
						{
							free (mybuf);
						}
						break;
					}
				}
			}
		}
		if ( mybuf != NULL )
		{
			free (mybuf);
		}
		if ( ret != size )
		{
			break;
		}

		wiped += ret;
		rlc++;
	} /* while */

	if ( error_ret != NULL )
	{
		*error_ret = gerror;
	}
	if ( sig_recvd != 0 )
	{
		return -1;
	}
	return wiped;
}

/* ======================================================================== */

# ifndef WFS_ANSIC
static s64 wipe_attribute WFS_PARAMS ((ntfs_attr * const na,
	unsigned char * const buf, wfs_fsid_t wfs_fs));
# endif

/**
 * Part of ntfsprogs.
 * Modified: removed logging, memset replaced by wfs_fill_buffer, signal handling.
 *
 * wipe_attribute - Wipe not compressed $DATA attribute
 * \param	vol	An ntfs volume obtained from ntfs_mount
 * \param	na	Opened ntfs attribute
 *
 * \return: >0  Success, the attribute was wiped
 *          0  Nothing to wipe
 *         -1  Error, something went wrong
 */
static s64
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wipe_attribute (
# ifdef WFS_ANSIC
	ntfs_attr * const na,
	unsigned char * const buf,
	wfs_fsid_t wfs_fs
	)
# else
	na, buf, wfs_fs)
	ntfs_attr * const na;
	unsigned char * const buf;
	wfs_fsid_t wfs_fs;
# endif
{
	s64 size, ret = 0;
	unsigned long int j;
	s64 offset;
	/*wfs_fsid_t wfs_fs;*/
	int selected[WFS_NPAT] = {0};
# ifdef HAVE_LIBNTFS_3G
	s64 s64zero = 0;
# endif
	ntfs_volume * ntfs;
	wfs_errcode_t gerror = 0;
	wfs_errcode_t * error_ret;

	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	ntfs = (ntfs_volume *) wfs_fs.fs_backend;
	if ( (ntfs == NULL) || (na == NULL) || (buf == NULL) )
	{
		return 0;
	}

	offset = na->data_size;
	if (offset == 0)
	{
		return 0;
	}

	if (NAttrEncrypted (na) != 0)
	{
		offset = (((offset - 1) >> 10) + 1) << 10;
	}
	size = ntfs->cluster_size - offset % ntfs->cluster_size;

	for ( j = 0; (j < wfs_fs.npasses) && (sig_recvd == 0); j++ )
	{
		if ( wfs_fs.no_wipe_zero_blocks != 0 )
		{
			ret = ntfs_rl_pread (ntfs, na->rl, offset, size, buf);
			if (ret != size)
			{
				if ( error_ret != NULL )
				{
					*error_ret = WFS_BLKRD;
				}
				break;
			}
			if ( wfs_is_block_zero (buf, (size_t)size) != 0 )
			{
				/* this block is all-zeros - don't wipe, as requested */
				j = wfs_fs.npasses * 2;
				break;
			}
		}
		wfs_fill_buffer (j, buf, (size_t) size, selected, wfs_fs);	/* buf OK */
		if ( sig_recvd != 0 )
		{
	       		break;
		}

# ifndef HAVE_LIBNTFS_3G
		ret = ntfs_rl_pwrite (ntfs, na->rl, offset, size, buf);
# else
		ret = ntfs_rl_pwrite (ntfs, na->rl, s64zero, offset, size, buf);
# endif
		if ( (ret != size) || (sig_recvd != 0) )
		{
			if ( error_ret != NULL )
			{
				*error_ret = WFS_BLKWR;
			}
			return -1;
		}
		/* Flush after each writing, if more than 1 overwriting needs to be done.
		   Allow I/O bufferring (efficiency), if just one pass is needed. */
		if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
		{
			/*ntfs_inode_mark_dirty(na->ni);*/
			ntfs_inode_sync (na->ni);
			gerror = wfs_ntfs_flush_fs (wfs_fs);
		}
	}

	if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
	{
		if ( j != wfs_fs.npasses * 2 )
		{
			/* last pass with zeros: */
			WFS_MEMSET ( buf, 0, (size_t) size );
			if ( sig_recvd == 0 )
			{
# ifndef HAVE_LIBNTFS_3G
				ret = ntfs_rl_pwrite (ntfs, na->rl, offset, size, buf);
# else
				ret = ntfs_rl_pwrite (ntfs, na->rl, s64zero, offset, size, buf);
# endif
				if ( (ret != size) || (sig_recvd!=0) )
				{
					if ( error_ret != NULL )
					{
						*error_ret = WFS_BLKWR;
					}
					return -1;
				}
				/* No need to flush the last writing of a given block. *
				if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
				{
					/ * ntfs_inode_mark_dirty(na->ni); * /
					ntfs_inode_sync (na->ni);
					gerror = wfs_ntfs_flush_fs (wfs_fs);
				} */
			}
		}
	}

	if ( error_ret != NULL )
	{
		*error_ret = gerror;
	}
	if ( sig_recvd != 0 )
	{
		return -1;
	}
	return ret;
}
#endif /* WFS_WANT_PART */

/* ======================================================================== */

#if (defined WFS_WANT_WFS) || (defined WFS_WANT_UNRM)
# ifndef WFS_ANSIC
static int GCC_WARN_UNUSED_RESULT utils_cluster_in_use WFS_PARAMS ((
	const ntfs_volume * const vol, const s64 lcn));
# endif

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
static int GCC_WARN_UNUSED_RESULT
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
utils_cluster_in_use (
# ifdef WFS_ANSIC
	const ntfs_volume * const vol, const s64 lcn)
# else
	vol, lcn)
	const ntfs_volume * const vol;
	const s64 lcn;
# endif
{

# undef	BUFSIZE
# define	BUFSIZE	512
	static unsigned char ntfs_buffer[BUFSIZE];
	static s64 ntfs_bmplcn = -BUFSIZE - 1;	/* Which bit of $Bitmap is in the buffer */
	int cbyte, bit;
	ntfs_attr *attr = NULL;

	s64 sizeof_ntfs_buffer = BUFSIZE;

	if ( vol == NULL )
	{
		return 1 /* always used */;
	}

	/* Does lcn lie in the section of $Bitmap we already have cached? */
	if (	(ntfs_bmplcn < 0) ||
		(lcn < ntfs_bmplcn) ||
		(lcn >= (ntfs_bmplcn + (BUFSIZE << 3)) )
	   )
	{

# if (defined HAVE_NTFS_NTFS_VOLUME_H)
		attr = ntfs_attr_open (vol->lcnbmp_ni, NTFS_AT_DATA, NTFS_AT_UNNAMED, 0);
# else
		attr = ntfs_attr_open (vol->lcnbmp_ni, AT_DATA, AT_UNNAMED, 0);
# endif
		if ( (attr == NULL) || (sig_recvd != 0) )
		{
			return -1;
		}

		/* Mark the buffer as in use, in case the read is shorter. */
		WFS_MEMSET (ntfs_buffer, 0xFF, BUFSIZE);
		if ( sig_recvd != 0 )
		{
			return -1;
		}
		ntfs_bmplcn = lcn & (~((BUFSIZE << 3) - 1));

		if (ntfs_attr_pread (attr, (ntfs_bmplcn>>3), sizeof_ntfs_buffer, ntfs_buffer) < 0)
		{
			ntfs_attr_close (attr);
			return -1;
		}

		ntfs_attr_close (attr);
	}

	bit  = 1 << (lcn & 7);
	cbyte = (int) ((lcn >> 3) & (BUFSIZE - 1));
	if ( sig_recvd != 0 )
	{
		return -1;
	}
	return (ntfs_buffer[cbyte] & bit);
}
#endif /* (defined WFS_WANT_WFS) || (defined WFS_WANT_UNRM) */

/* ======================================================================== */

#ifdef WFS_WANT_UNRM
# ifndef WFS_ANSIC
static void free_file WFS_PARAMS ((struct ufile *file));
# endif

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
static void
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
free_file (
# ifdef WFS_ANSIC
	struct ufile *file)
# else
	file)
	struct ufile * file;
# endif
{
	struct wfs_ntfs_list_head *item = NULL, *tmp = NULL;
	struct filename *f = NULL;
	struct data *d = NULL;

	if ( (file==NULL) || (sig_recvd!=0) )
	{
		return;
	}

	item = (&(file->name))->next;
	if ( item == NULL )
	{
		if (file->mft != NULL)
		{
			free (file->mft);
		}
		free (file);
		return;
	}
	tmp = item->next;
	while (item != (&(file->name)))
	{ /* List of filenames */

		/*f = WFS_NTFS_LIST_ENTRY (item, struct filename, list);*/
		f = ((struct filename *)((char *)(item) - (unsigned long int)(&((struct filename *)0)->list)));
		if (f != NULL)
		{
			if (f->name != NULL)
			{
				free (f->name);
			}
			if (f->parent_name != NULL)
			{
				free (f->parent_name);
			}
			free (f);
		}
		item = tmp;
		if ( item == NULL )
		{
			break;
		}
		tmp = item->next;
	}

	/*WFS_NTFS_LIST_FOR_EACH_SAFE (item, tmp, &(file->data))*/
	item = (&(file->data))->next;
	if ( item == NULL )
	{
		if (file->mft != NULL)
		{
			free (file->mft);
		}
		free (file);
		return;
	}
	tmp = item->next;
	while (item != (&(file->data)))
	{ /* List of data streams */

		/*d = WFS_NTFS_LIST_ENTRY (item, struct data, list);*/
		/* XXX: A cheat for the GCC analyzer, "d" points to the same place, the code is correct... */
		if ( item->next != NULL )
		{
			d = ((struct data *)((char *)(item->next->prev) - (unsigned long int)(&((struct data *)0)->list)));
		}
		else
		{
			d = ((struct data *)((char *)(item) - (unsigned long int)(&((struct data *)0)->list)));
		}
		if (d != NULL)
		{
			if (d->name != NULL)
			{
				free (d->name);
				d->name = NULL;
			}
			if (d->runlist != NULL)
			{
				free (d->runlist);
				d->runlist = NULL;
			}
			free (d);
			d = NULL;
		}
		item = tmp;
		if ( item == NULL )
		{
			break;
		}
		tmp = item->next;
	}

	if (file->mft != NULL)
	{
		free (file->mft);
	}
	free (file);
}

/* ======================================================================== */

# ifndef WFS_ANSIC
static wfs_errcode_t GCC_WARN_UNUSED_RESULT destroy_record WFS_PARAMS ((
	const wfs_fsid_t wfs_fs, const s64 record, unsigned char * const buf));
# endif

/**
 * Destroys the specified record's filenames and data.
 *
 * \param wfs_fs The filesystem.
 * \param record The record (i-node number), which filenames & data to destroy.
 * \param buf Buffer for wipe data.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
static wfs_errcode_t GCC_WARN_UNUSED_RESULT
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
destroy_record (
# ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs, const s64 record_no, unsigned char * const buf)
# else
	wfs_fs, record_no, buf)
	const wfs_fsid_t wfs_fs;
	const s64 record_no;
	unsigned char * const buf;
# endif
{
	struct ufile *file = NULL;
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
	ntfs_runlist_element *rl = NULL;
# else
	runlist_element *rl = NULL;
# endif
	ntfs_attr *mft = NULL;
	ntfs_attr_search_ctx *ctx = NULL;
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	unsigned long int pass, i;
	s64 j;
	unsigned char * a_offset;
	int selected[WFS_NPAT] = {0};
	ntfs_volume * ntfs;
	wfs_errcode_t * error_ret;
	wfs_errcode_t error = 0;
	size_t fs_block_size;
	s64 res;

	ntfs = (ntfs_volume *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( (ntfs == NULL) || (buf == NULL) )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	fs_block_size = wfs_ntfs_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	WFS_SET_ERRNO (0);
	file = (struct ufile *) malloc (sizeof (struct ufile));
	if ( file == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	WFS_NTFS_INIT_LIST_HEAD (&(file->name));
	WFS_NTFS_INIT_LIST_HEAD (&(file->data));
	file->inode = record_no;

	WFS_SET_ERRNO (0);
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
	file->mft = (NTFS_MFT_RECORD *) malloc (ntfs->mft_record_size);
# else
	file->mft = (MFT_RECORD *) malloc (ntfs->mft_record_size);
# endif
	if ( file->mft == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		free_file (file);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

# if (defined HAVE_NTFS_NTFS_VOLUME_H)
	mft = ntfs_attr_open (ntfs->mft_ni, NTFS_AT_DATA, NTFS_AT_UNNAMED, 0);
# else
	mft = ntfs_attr_open (ntfs->mft_ni, AT_DATA, AT_UNNAMED, 0);
# endif
	if ( mft == NULL )
	{
		free_file (file);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_ATTROPEN;
	}

	/* Read the MFT reocrd of the i-node */
	if ( ntfs_attr_mst_pread (mft, ntfs->mft_record_size * record_no, 1LL,
		ntfs->mft_record_size, file->mft) < 1 )
	{
		ntfs_attr_close (mft);
		free_file (file);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_ATTROPEN;
	}
	ntfs_attr_close (mft);
	mft = NULL;

	ctx = ntfs_attr_get_search_ctx (NULL, file->mft);
	if (ctx == NULL)
	{
		free_file (file);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_CTXERROR;
	}

	/* Wiping file names */
	while ( sig_recvd == 0 )
	{
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
        	if (ntfs_attr_lookup (NTFS_AT_FILE_NAME, NULL, 0, 0, 0LL, NULL, 0, ctx) != 0)
# else
        	if (ntfs_attr_lookup (AT_FILE_NAME, NULL, 0, 0, 0LL, NULL, 0, ctx) != 0)
# endif
        	{
			break;	/* None / no more of that type */
		}
		if ( ctx->attr == NULL )
		{
			break;
		}

		/* We know this will always be resident.
		   Find the offset of the data, including the MFT record. */
		a_offset = ((unsigned char *) ctx->attr + le16_to_cpu (ctx->attr->value_offset) );

		for ( pass = 0; (pass < wfs_fs.npasses) && (sig_recvd == 0); pass++ )
		{
			wfs_fill_buffer (pass, a_offset, le32_to_cpu(ctx->attr->value_length),
				selected, wfs_fs);
			if ( sig_recvd != 0 )
			{
		       		break;
			}

# if (defined HAVE_NTFS_NTFS_VOLUME_H)
			if ( ntfs_mft_records_write (ntfs, NTFS_MK_MREF (record_no, 0),
					1LL, ctx->mrec) != 0 )
# else
			if ( ntfs_mft_records_write (ntfs, MK_MREF (record_no, 0),
					1LL, ctx->mrec) != 0 )
# endif
			{
				ret_wfs = WFS_BLKWR;
				break;
			}

			/* Flush after each writing, if more than 1 overwriting needs to be done.
			   Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
			{
				error = wfs_ntfs_flush_fs (wfs_fs);
			}
		}
		if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
		{
			/* last pass with zeros: */
			WFS_MEMSET (a_offset, 0, le32_to_cpu(ctx->attr->value_length));
			if ( sig_recvd == 0 )
			{
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
				if ( ntfs_mft_records_write (ntfs, NTFS_MK_MREF (record_no, 0),
						1LL, ctx->mrec) != 0 )
# else
				if ( ntfs_mft_records_write (ntfs, MK_MREF (record_no, 0),
						1LL, ctx->mrec) != 0 )
# endif
				{
					ret_wfs = WFS_BLKWR;
					break;
				}

				/* No need to flush the last writing of a given block. *
				if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
				{
					error = wfs_ntfs_flush_fs (wfs_fs);
				}*/
			}
		}
		/* Wiping file name length */
		for ( pass = 0; (pass < wfs_fs.npasses) && (sig_recvd == 0); pass++ )
		{

			wfs_fill_buffer (pass, (unsigned char *) &(ctx->attr->value_length),
				sizeof(u32), selected, wfs_fs);
			if ( sig_recvd != 0 )
			{
		       		break;
			}

# if (defined HAVE_NTFS_NTFS_VOLUME_H)
			if ( ntfs_mft_records_write (ntfs, NTFS_MK_MREF (record_no, 0),
					1LL, ctx->mrec) != 0 )
# else
			if ( ntfs_mft_records_write (ntfs, MK_MREF (record_no, 0),
					1LL, ctx->mrec) != 0 )
# endif
			{
				ret_wfs = WFS_BLKWR;
				break;
			}

			/* Flush after each writing, if more than 1 overwriting needs to be done.
			   Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
			{
				error = wfs_ntfs_flush_fs (wfs_fs);
			}
		}
		ctx->attr->value_length = 0;
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
		if ( ntfs_mft_records_write (ntfs, NTFS_MK_MREF (record_no, 0),
				1LL, ctx->mrec) != 0 )
# else
		if ( ntfs_mft_records_write (ntfs, MK_MREF (record_no, 0),
				1LL, ctx->mrec) != 0 )
# endif
		{
			ret_wfs = WFS_BLKWR;
			break;
		}
	}

	ntfs_attr_reinit_search_ctx (ctx);

	/* Wiping file data */
	while ( sig_recvd == 0 )
	{

# if (defined HAVE_NTFS_NTFS_VOLUME_H)
        	if ( ntfs_attr_lookup (NTFS_AT_DATA, NULL, 0, 0, 0LL, NULL, 0, ctx) != 0 )
# else
        	if ( ntfs_attr_lookup (AT_DATA, NULL, 0, 0, 0LL, NULL, 0, ctx) != 0 )
# endif
        	{
			break;	/* None / no more of that type */
		}
		if ( ctx->attr == NULL )
		{
			break;
		}

		if ( (ctx->attr->non_resident == 0) && (ctx->attr->value_length != 0) )
		{	/* attribute is resident (part of MFT record) */

			/* find the offset of the data, including the MFT record */
			a_offset = ((unsigned char *) ctx->attr + le16_to_cpu (ctx->attr->value_offset) );
			/* Wiping the data itself */
			for ( pass = 0; (pass < wfs_fs.npasses) && (sig_recvd == 0); pass++ )
			{
				wfs_fill_buffer (pass, a_offset, le32_to_cpu(ctx->attr->value_length),
					selected, wfs_fs);
				if ( sig_recvd != 0 )
				{
			       		break;
				}

# if (defined HAVE_NTFS_NTFS_VOLUME_H)
				if ( ntfs_mft_records_write (ntfs, NTFS_MK_MREF (record_no, 0),
						1LL, ctx->mrec) != 0 )
# else
				if ( ntfs_mft_records_write (ntfs, MK_MREF (record_no, 0),
						1LL, ctx->mrec) != 0 )
# endif
				{
					ret_wfs = WFS_BLKWR;
					break;
				}

				/* Flush after each writing, if more than 1 overwriting needs to be done.
				   Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
				{
					error = wfs_ntfs_flush_fs (wfs_fs);
				}
			}
			if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
			{
				/* last pass with zeros: */
				WFS_MEMSET (a_offset, 0, le32_to_cpu(ctx->attr->value_length));
				if ( sig_recvd == 0 )
				{
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
					if ( ntfs_mft_records_write (ntfs, NTFS_MK_MREF (record_no, 0),
							1LL, ctx->mrec) != 0 )
# else
					if ( ntfs_mft_records_write (ntfs, MK_MREF (record_no, 0),
							1LL, ctx->mrec) != 0 )
# endif
					{
						ret_wfs = WFS_BLKWR;
						break;
					}

					/* No need to flush the last writing of a given block. *
					if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
					{
						error = wfs_ntfs_flush_fs (wfs_fs);
					}*/
				}
			}
			/* Wiping data length */
			for ( pass = 0; (pass < wfs_fs.npasses) && (sig_recvd == 0); pass++ )
			{
				wfs_fill_buffer (pass, (unsigned char *) &(ctx->attr->value_length),
					sizeof(u32), selected, wfs_fs);
				if ( sig_recvd != 0 )
				{
			       		break;
				}

# if (defined HAVE_NTFS_NTFS_VOLUME_H)
				if ( ntfs_mft_records_write (ntfs, NTFS_MK_MREF (record_no, 0),
						1LL, ctx->mrec) != 0 )
# else
				if ( ntfs_mft_records_write (ntfs, MK_MREF (record_no, 0),
						1LL, ctx->mrec) != 0 )
# endif
				{
					ret_wfs = WFS_BLKWR;
					break;
				}

				/* Flush after each writing, if more than 1 overwriting needs to be done.
				   Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
				{
					error = wfs_ntfs_flush_fs (wfs_fs);
				}
			}
			ctx->attr->value_length = 0;
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
			if ( ntfs_mft_records_write (ntfs, NTFS_MK_MREF (record_no, 0),
					1LL, ctx->mrec) != 0 )
# else
			if ( ntfs_mft_records_write (ntfs, MK_MREF (record_no, 0),
					1LL, ctx->mrec) != 0 )
# endif
			{
				ret_wfs = WFS_BLKWR;
				break;
			}

		}
		else
		{
			/* Non-resident here */
			rl = ntfs_mapping_pairs_decompress (ntfs, ctx->attr, NULL);
			if (rl == NULL)
			{
				continue;
			}

			if (rl[0].length <= 0)
			{
				free (rl);
				continue;
			}

			for (i = 0; (rl[i].length > 0) && (sig_recvd == 0)
				&& (ret_wfs == WFS_SUCCESS); i++)
			{
				if ( rl[i].lcn == -1 )
				{
					/* unallocated? */
					continue;
				}

				for (j = rl[i].lcn; (j < rl[i].lcn + rl[i].length) &&
					(sig_recvd == 0) && (ret_wfs == WFS_SUCCESS); j++)
				{
					if ( utils_cluster_in_use (ntfs, j) == 0 )
					{
						for ( pass = 0; (pass < wfs_fs.npasses)
							&& (sig_recvd == 0); pass++ )
						{
							if ( wfs_fs.no_wipe_zero_blocks != 0 )
							{
								res = ntfs_cluster_read (ntfs, j,
									1LL, buf);
								if ( res != 1LL )
								{
									ret_wfs = WFS_BLKRD;
									break;
								}
								if ( wfs_is_block_zero (buf, fs_block_size) != 0 )
								{
									/* this block is all-zeros - don't wipe, as requested */
									pass = wfs_fs.npasses * 2;
									break;
								}
							}
							wfs_fill_buffer (pass, buf /* buf OK */,
								fs_block_size,
								selected, wfs_fs);
							if ( sig_recvd != 0 )
							{
			       					break;
							}
							if (ntfs_cluster_write (ntfs, j,
								1LL, buf) < 1)
							{
								ret_wfs = WFS_BLKWR;
								break;
							}

							/* Flush after each writing, if more than 1
							   overwriting needs to be done.
							   Allow I/O bufferring (efficiency), if just
							   one pass is needed. */
							if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
							{
								error = wfs_ntfs_flush_fs (wfs_fs);
							}
						}
						if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
						{
							if ( pass != wfs_fs.npasses * 2 )
							{
								/* last pass with zeros: */
								WFS_MEMSET (buf, 0, fs_block_size);
								if ( sig_recvd == 0 )
								{
									if (ntfs_cluster_write (ntfs, j,
										1LL, buf) < 1)
									{
										ret_wfs = WFS_BLKWR;
										break;
									}
								}
							}
						}
					}
				}
			}
			/* Wipe the data length here */
			for ( pass = 0; (pass < wfs_fs.npasses) && (sig_recvd == 0); pass++ )
			{
				wfs_fill_buffer (pass, (unsigned char *) &(ctx->attr->lowest_vcn),
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
					sizeof(NTFS_VCN),
# else
					sizeof(VCN),
# endif
					selected, wfs_fs);
				wfs_fill_buffer (pass, (unsigned char *) &(ctx->attr->highest_vcn),
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
					sizeof(NTFS_VCN),
# else
					sizeof(VCN),
# endif
					selected, wfs_fs);
				wfs_fill_buffer (pass, (unsigned char *) &(ctx->attr->allocated_size),
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
					sizeof(NTFS_VCN),
# else
					sizeof(VCN),
# endif
					selected, wfs_fs);
				wfs_fill_buffer (pass, (unsigned char *) &(ctx->attr->data_size),
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
					sizeof(NTFS_VCN),
# else
					sizeof(VCN),
# endif
					selected, wfs_fs);
				wfs_fill_buffer (pass, (unsigned char *) &(ctx->attr->initialized_size),
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
					sizeof(NTFS_VCN),
# else
					sizeof(VCN),
# endif
					selected, wfs_fs);
				wfs_fill_buffer (pass, (unsigned char *) &(ctx->attr->compressed_size),
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
					sizeof(NTFS_VCN),
# else
					sizeof(VCN),
# endif
					selected, wfs_fs);
				if ( sig_recvd != 0 )
				{
			       		break;
				}

# if (defined HAVE_NTFS_NTFS_VOLUME_H)
				if ( ntfs_mft_records_write (ntfs, NTFS_MK_MREF (record_no, 0),
						1LL, ctx->mrec) != 0 )
# else
				if ( ntfs_mft_records_write (ntfs, MK_MREF (record_no, 0),
						1LL, ctx->mrec) != 0 )
# endif
				{
					ret_wfs = WFS_BLKWR;
					break;
				}

				/* Flush after each writing, if more than 1 overwriting needs to be done.
				   Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
				{
					error = wfs_ntfs_flush_fs (wfs_fs);
				}
			}
			ctx->attr->lowest_vcn = 0;
			ctx->attr->highest_vcn = 0;
			ctx->attr->allocated_size = 0;
			ctx->attr->data_size = 0;
			ctx->attr->initialized_size = 0;
			ctx->attr->compressed_size = 0;
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
			if ( ntfs_mft_records_write (ntfs, NTFS_MK_MREF (record_no, 0),
					1LL, ctx->mrec) != 0 )
# else
			if ( ntfs_mft_records_write (ntfs, MK_MREF (record_no, 0),
					1LL, ctx->mrec) != 0 )
# endif
			{
				ret_wfs = WFS_BLKWR;
				free (rl);
				break;
			}
			free (rl);
		}	/* end of resident check */
	} /* end of 'wiping file data' loop */

	ntfs_attr_put_search_ctx (ctx);
	free_file (file);

	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	if ( sig_recvd != 0 )
	{
		ret_wfs = WFS_SIGNAL;
	}

	return ret_wfs;
}

/* ======================================================================== */

# ifndef WFS_ANSIC
static wfs_errcode_t wfs_ntfs_wipe_journal WFS_PARAMS ((wfs_fsid_t wfs_fs));
# endif

/**
 * Wipes the journal (logfile) on an NTFS filesystem. Taken from ntfswipe.c. Changes:
 *	removed message printing, using own patterns instead of just 0xFF, flushing the
 *	journal.
 * \param wfs_fs The NTFS filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
static wfs_errcode_t
wfs_ntfs_wipe_journal (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_journ = WFS_SUCCESS;
	ntfs_inode *ni = NULL;
	ntfs_attr *na = NULL;
	s64 len, pos, count;
	unsigned long int j;
	int selected[WFS_NPAT] = {0};
	unsigned char * buf = NULL;
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
	NTFS_MFT_REF log_ino;
# else
	MFT_REF log_ino;
# endif
	s64 blocksize;
	unsigned int i;
	unsigned int prev_percent = 50;
	ntfs_volume * ntfs;
	wfs_errcode_t error = 0;
	wfs_errcode_t * error_ret;

	ntfs = (ntfs_volume *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( ntfs == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	blocksize = (s64) wfs_ntfs_get_block_size (wfs_fs);
	if ( blocksize == 0 )
	{
		return WFS_BADPARAM;
	}

# if (defined HAVE_NTFS_NTFS_VOLUME_H)
	log_ino = NTFS_FILE_LogFile;
# else
	log_ino = FILE_LogFile;
# endif
	ni = ntfs_inode_open (ntfs, log_ino);
	if (ni == NULL)
	{
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_INOREAD;
	}
	ntfs_inode_sync (ni);

# if (defined HAVE_NTFS_NTFS_VOLUME_H)
	na = ntfs_attr_open (ni, NTFS_AT_DATA, NTFS_AT_UNNAMED, 0);
# else
	na = ntfs_attr_open (ni, AT_DATA, AT_UNNAMED, 0);
# endif
	if (na == NULL)
	{
		ntfs_inode_close (ni);
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_ATTROPEN;
	}
	/* flush the journal (logfile): */
	ntfs_empty_logfile (na);

	/* The $DATA attribute of the $LogFile has to be non-resident. */
	if (!NAttrNonResident (na))
	{
		ntfs_attr_close (na);
		ntfs_inode_close (ni);
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_ATTROPEN;
	}

	/* Get length of $LogFile contents. */
	len = na->data_size;
	if (len == 0)
	{
		/* nothing to do. */
		ntfs_attr_close (na);
		ntfs_inode_close (ni);
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_SUCCESS;
	}

	WFS_SET_ERRNO (0);
	buf = (unsigned char *) malloc ((size_t)blocksize);
	if ( buf == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		ntfs_attr_close (na);
		ntfs_inode_close (ni);
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	/* Read $LogFile until its end. We do this as a check for correct
	   length thus making sure we are decompressing the mapping pairs
	   array correctly and hence writing below is safe as well. */
	pos = 0;
	while ( ((count = ntfs_attr_pread (na, pos, blocksize, buf)) > 0)
		&& (sig_recvd == 0) )
	{
		pos += count;
	}
	if ( sig_recvd != 0 )
	{
		free (buf);
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_SIGNAL;
	}

	if ((count == -1) || (pos != len))
	{
		/* Amount of $LogFile data read does not correspond to expected length! */
		free (buf);
		ntfs_attr_close (na);
		ntfs_inode_close (ni);
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_ATTROPEN;
	}
	for ( j = 0; (j < (unsigned long int)(wfs_fs.npasses+1)) && (sig_recvd == 0)
		/*&& (ret_journ == WFS_SUCCESS)*/; j++ )
	{
		if ( j < wfs_fs.npasses )
		{
			wfs_fill_buffer (j, buf, (size_t) blocksize,
				selected, wfs_fs);/* buf OK */
		}
		else
		{
			/* last pass with 0xff */
			WFS_MEMSET (buf, 0xff, (size_t) blocksize);
		}
		if ( sig_recvd != 0 )
		{
	       		break;
		}

		/* writing modified cluster here: */
		pos = 0;
		while ( ((count = len - pos) > 0) && (ret_journ == WFS_SUCCESS) && (sig_recvd == 0))
		{
			if (count > blocksize)
			{
				count = blocksize;
			}
			i = 1;
			if ( wfs_fs.no_wipe_zero_blocks != 0 )
			{
				if ( count != ntfs_attr_pread (na, pos, count, buf) )
				{
					ret_journ = WFS_BLKRD;
					i = 0;
				}
				else if ( wfs_is_block_zero (buf, (size_t)count) != 0 )
				{
					/* this block is all-zeros - don't wipe, as requested */
					i = 0;
				}
			}
			if ( i == 1 )
			{
				count = ntfs_attr_pwrite (na, pos, count, buf);
				if (count <= 0)
				{
					ret_journ = WFS_BLKWR;
				}
			}
			pos += count;
		}
		if ( ret_journ != WFS_SUCCESS )
		{
			break;
		}
		/* Flush after each writing, if more than 1 overwriting needs to be done.
		   Allow I/O bufferring (efficiency), if just one pass is needed. */
		if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
		{
			error = wfs_ntfs_flush_fs (wfs_fs);
		}
		wfs_show_progress (WFS_PROGRESS_UNRM,
			(unsigned int) (j / (wfs_fs.npasses+1)), &prev_percent);
	}
	free (buf);
	ntfs_attr_close(na);
	ntfs_inode_close(ni);

	wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	if ( sig_recvd != 0 )
	{
		return WFS_SIGNAL;
	}
	return ret_journ;
}
#endif /* WFS_WANT_UNRM */

/* ======================================================================== */

#ifdef WFS_WANT_PART
/**
 * Wipes the free space in partially used blocks on the given NTFS filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_ntfs_wipe_part (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	unsigned int prev_percent = 0;
	/* ntfswipe --tails --count wfs_fs.npasses --bytes */
#define WFSWIPE_PART_POS_COUNT 3
#define WFSWIPE_PART_POS_FSNAME 6
	const char * args_ntfswipe[] = { "ntfswipe", "--tails", "--count", "                      ",
		"--bytes", "0,0xFF,0x55,0xAA,0x24,0x49,0x92,0x6D,0xB6,0xDB,0x11,0x22,0x33,0x44,0x66,0x77,0x88,0x99,0xBB,0xCC,0xDD,0xEE",
		NULL, NULL };
	char ** args_ntfswipe_copy = NULL;
	child_id_t child_ntfswipe;
	u64 nr_mft_records;
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
	NTFS_MFT_REF inode_num;
# else
	MFT_REF inode_num;
# endif
	ntfs_inode *ni = NULL;
	ntfs_attr *na = NULL;
	unsigned char * buf;
	ntfs_volume * ntfs;
	wfs_errcode_t error = 0;
	wfs_errcode_t * error_ret;
	size_t fs_block_size;

	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( wfs_fs.use_dedicated != 0 )
	{
		if ( wfs_fs.fsname == NULL )
		{
			wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_BADPARAM;
		}
		WFS_SET_ERRNO (0);
		args_ntfswipe[WFSWIPE_PART_POS_FSNAME] = wfs_fs.fsname;
		args_ntfswipe_copy = wfs_deep_copy_array (args_ntfswipe,
			sizeof (args_ntfswipe) / sizeof (args_ntfswipe[0]));
		if ( args_ntfswipe_copy == NULL )
		{
			error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
			wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_MALLOC;
			/*args_ntfswipe[4] = wfs_fs.fsname;*/
		}
# ifdef HAVE_SIGNAL_H
		sigchld_recvd = 0;
# endif
# ifdef HAVE_SNPRINTF
		snprintf (args_ntfswipe_copy[WFSWIPE_PART_POS_COUNT],
			sizeof (args_ntfswipe[WFSWIPE_PART_POS_COUNT]) - 1, "%lu", wfs_fs.npasses);
# else
		sprintf (args_ntfswipe_copy[WFSWIPE_PART_POS_COUNT], "%lu", wfs_fs.npasses);
# endif
		args_ntfswipe_copy[WFSWIPE_PART_POS_COUNT][22] = '\0';
		child_ntfswipe.program_name = args_ntfswipe_copy[0];
		child_ntfswipe.args = args_ntfswipe_copy;
		child_ntfswipe.child_env = NULL;
		child_ntfswipe.stdin_fd = 0;
		child_ntfswipe.stdout_fd = 1;
		child_ntfswipe.stderr_fd = 2;
		WFS_SET_ERRNO (0);
		ret_wfs = wfs_create_child (&child_ntfswipe);
		if ( ret_wfs != WFS_SUCCESS )
		{
			/* error */
			error = WFS_GET_ERRNO_OR_DEFAULT (1L);
			wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
			wfs_free_array_deep_copy (args_ntfswipe_copy,
				sizeof (args_ntfswipe) / sizeof (args_ntfswipe[0]));
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_FORKERR;
		}
		/* parent */
		wfs_wait_for_child (&child_ntfswipe);
		wfs_free_array_deep_copy (args_ntfswipe_copy,
			sizeof (args_ntfswipe) / sizeof (args_ntfswipe[0]));
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		return WFS_SUCCESS;
	} /* if ( wfs_fs.use_dedicated != 0 ) */

	ntfs = (ntfs_volume *) wfs_fs.fs_backend;
	if ( ntfs == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_NOTHING;
	}
	if ( ntfs->mft_na == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_NOTHING;
	}
	if ( ntfs->mft_na->initialized_size <= 0 )
	{
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_NOTHING;
	}
	fs_block_size = wfs_ntfs_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	nr_mft_records = ((u64)ntfs->mft_na->initialized_size) >>
			ntfs->mft_record_size_bits;

	WFS_SET_ERRNO (0);
	buf = (unsigned char *) malloc (fs_block_size);
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
	/* 16 is the first i-node for user use. */
	for (inode_num = 16; (inode_num < nr_mft_records) && (sig_recvd==0)
		/*&& (ret_wfs == WFS_SUCCESS)*/; inode_num++ )
	{
		ret_wfs = WFS_SUCCESS;
		WFS_SET_ERRNO (0);
		ni = ntfs_inode_open (ntfs, inode_num);
		if ( ni == NULL )
		{
# ifdef HAVE_ERRNO_H
			if ( errno != ENOENT )
# endif
			{
				ret_wfs = WFS_INOREAD;
			}
			wfs_show_progress (WFS_PROGRESS_PART,
				(unsigned int) (inode_num/nr_mft_records),
				&prev_percent);
			continue;
                }
		if ( ni->mrec == NULL )
		{
			ret_wfs = WFS_INOREAD;
			wfs_show_progress (WFS_PROGRESS_PART,
				(unsigned int) (inode_num/nr_mft_records),
				&prev_percent);
			continue;
                }
		if ( sig_recvd != 0 )
		{
			break;
		}

		/* wipe only if base MFT record */
		if (ni->mrec->base_mft_record == 0)
		{
# if (defined HAVE_NTFS_NTFS_VOLUME_H)
			na = ntfs_attr_open (ni, NTFS_AT_DATA, NTFS_AT_UNNAMED, 0);
# else
			na = ntfs_attr_open (ni, AT_DATA, AT_UNNAMED, 0);
# endif
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

					if ( ret_wfs == WFS_SUCCESS )
					{
						if ( NAttrCompressed (na) != 0 )
						{
							/*wiped = */wipe_compressed_attribute
								(na, buf, wfs_fs);
						}
						else
						{
							/*wiped = */wipe_attribute
								(na, buf, wfs_fs);
						}
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
		wfs_show_progress (WFS_PROGRESS_PART,
			(unsigned int) (inode_num/nr_mft_records),
			&prev_percent);
	}
	wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
	free (buf);
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	if ( sig_recvd != 0 )
	{
		ret_wfs = WFS_SIGNAL;
	}
	return ret_wfs;
}
#endif /* WFS_WANT_PART */

/* ======================================================================== */

#ifdef WFS_WANT_WFS
/**
 * Wipes the free space on the given NTFS filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_ntfs_wipe_fs (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
# endif
{
	unsigned int prev_percent = 0;
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	/* ntfswipe --unused --count wfs_fs.npasses --bytes */
#define WFSWIPE_WFS_POS_COUNT 3
#define WFSWIPE_WFS_POS_FSNAME 6
	const char * args_ntfswipe[] = { "ntfswipe", "--unused", "--count", "                      ",
		"--bytes", "0,0xFF,0x55,0xAA,0x24,0x49,0x92,0x6D,0xB6,0xDB,0x11,0x22,0x33,0x44,0x66,0x77,0x88,0x99,0xBB,0xCC,0xDD,0xEE",
		NULL, NULL };
	char ** args_ntfswipe_copy = NULL;
	child_id_t child_ntfswipe;
	wfs_errcode_t error = 0;
	s64 i, size, result;
	unsigned long int j;
	int selected[WFS_NPAT] = {0};
	unsigned char * buf;
	ntfs_volume * ntfs;
	wfs_errcode_t * error_ret;
	size_t fs_block_size;

	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( wfs_fs.use_dedicated != 0 )
	{
		if ( wfs_fs.fsname == NULL )
		{
			wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_BADPARAM;
		}
		WFS_SET_ERRNO (0);
		args_ntfswipe[WFSWIPE_WFS_POS_FSNAME] = wfs_fs.fsname;
		args_ntfswipe_copy = wfs_deep_copy_array (args_ntfswipe,
			sizeof (args_ntfswipe) / sizeof (args_ntfswipe[0]));
		if ( args_ntfswipe_copy == NULL )
		{
			error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
			wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_MALLOC;
			/*args_ntfswipe[4] = wfs_fs.fsname;*/
		}
# ifdef HAVE_SIGNAL_H
		sigchld_recvd = 0;
# endif
# ifdef HAVE_SNPRINTF
		snprintf (args_ntfswipe_copy[WFSWIPE_WFS_POS_COUNT],
			sizeof (args_ntfswipe[WFSWIPE_WFS_POS_COUNT]) - 1, "%lu", wfs_fs.npasses);
# else
		sprintf (args_ntfswipe_copy[WFSWIPE_WFS_POS_COUNT], "%lu", wfs_fs.npasses);
# endif
		args_ntfswipe_copy[WFSWIPE_WFS_POS_COUNT][22] = '\0';
		child_ntfswipe.program_name = args_ntfswipe_copy[0];
		child_ntfswipe.args = args_ntfswipe_copy;
		child_ntfswipe.child_env = NULL;
		child_ntfswipe.stdin_fd = -1;
		child_ntfswipe.stdout_fd = -1;
		child_ntfswipe.stderr_fd = -1;
		WFS_SET_ERRNO (0);
		ret_wfs = wfs_create_child (&child_ntfswipe);
		if ( ret_wfs != WFS_SUCCESS )
		{
			/* error */
			error = WFS_GET_ERRNO_OR_DEFAULT (1L);
			wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
			/* yes, compare pointers */
			wfs_free_array_deep_copy (args_ntfswipe_copy,
				sizeof (args_ntfswipe) / sizeof (args_ntfswipe[0]));
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_FORKERR;
		}
		/* parent */
		wfs_wait_for_child (&child_ntfswipe);
		wfs_free_array_deep_copy (args_ntfswipe_copy,
			sizeof (args_ntfswipe) / sizeof (args_ntfswipe[0]));
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		return WFS_SUCCESS;
	} /* if ( wfs_fs.use_dedicated != 0 ) */

	ntfs = (ntfs_volume *) wfs_fs.fs_backend;
	if ( ntfs == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	fs_block_size = wfs_ntfs_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	WFS_SET_ERRNO (0);
	buf = (unsigned char *) malloc (fs_block_size);
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
	if ( wfs_fs.wipe_mode == WFS_WIPE_MODE_PATTERN )
	{
		for ( j = 0; (j < wfs_fs.npasses) && (sig_recvd == 0); j++ )
		{
			for (i = 0; (i < ntfs->nr_clusters) && (sig_recvd==0); i++)
			{
				/* check if cluster in use */
				if (utils_cluster_in_use (ntfs, i) != 0)
				{
					wfs_show_progress (WFS_PROGRESS_WFS,
						(unsigned int) (((ntfs->nr_clusters * (s64)j + i) * 100)/(ntfs->nr_clusters * (s64)wfs_fs.npasses)),
						&prev_percent);
					continue;
				}

				/* cluster is unused - wipe it */
				size = ntfs->cluster_size;
				if ( wfs_fs.no_wipe_zero_blocks != 0 )
				{
					result = ntfs_pread (ntfs->dev, ntfs->cluster_size * i, size, buf);
					if (result != size)
					{
						ret_wfs = WFS_BLKRD;
						break;
					}
					if ( wfs_is_block_zero (buf, (size_t)size) != 0 )
					{
						/* this block is all-zeros - don't wipe, as requested */
						break;
					}
				}
				wfs_fill_buffer (j, buf, fs_block_size, selected, wfs_fs);/* buf OK */
				if ( sig_recvd != 0 )
				{
					break;
				}

				/* writing modified cluster here: */
				result = ntfs_pwrite (ntfs->dev, ntfs->cluster_size * i, size, buf);
				if (result != size)
				{
					free (buf);
					wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
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
					error = wfs_ntfs_flush_fs (wfs_fs);
				}
				wfs_show_progress (WFS_PROGRESS_WFS,
					(unsigned int) (((ntfs->nr_clusters * (s64)j + i) * 100)/(ntfs->nr_clusters * (s64)wfs_fs.npasses)),
					&prev_percent);
			}
		}
		if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
		{
			/* last pass with zeros: */
			if ( j != wfs_fs.npasses * 2 )
			{
				if ( sig_recvd == 0 )
				{
					wfs_ntfs_flush_fs (wfs_fs);
					WFS_MEMSET (buf, 0, fs_block_size);
					size = ntfs->cluster_size;
					for (i = 0; (i < ntfs->nr_clusters) && (sig_recvd==0); i++)
					{
						/* writing modified cluster here: */
						result = ntfs_pwrite (ntfs->dev,
							ntfs->cluster_size * i, size, buf);
						if (result != size)
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
							error = wfs_ntfs_flush_fs (wfs_fs);
						}*/
					}
					wfs_ntfs_flush_fs (wfs_fs);
				}
			}
		}
	}
	else
	{
		for (i = 0; (i < ntfs->nr_clusters) && (sig_recvd==0); i++)
		{
			/* check if cluster in use */
			if (utils_cluster_in_use (ntfs, i) != 0)
			{
				wfs_show_progress (WFS_PROGRESS_WFS, (unsigned int) (i/ntfs->nr_clusters),
					&prev_percent);
				continue;
			}

			/* cluster is unused - wipe it */
			for ( j = 0; (j < wfs_fs.npasses) && (sig_recvd == 0); j++ )
			{
				size = ntfs->cluster_size;
				if ( wfs_fs.no_wipe_zero_blocks != 0 )
				{
					result = ntfs_pread (ntfs->dev, ntfs->cluster_size * i, size, buf);
					if (result != size)
					{
						ret_wfs = WFS_BLKRD;
						break;
					}
					if ( wfs_is_block_zero (buf, (size_t)size) != 0 )
					{
						/* this block is all-zeros - don't wipe, as requested */
						j = wfs_fs.npasses * 2;
						break;
					}
				}
				wfs_fill_buffer (j, buf, fs_block_size, selected, wfs_fs);/* buf OK */
				if ( sig_recvd != 0 )
				{
					break;
				}

				/* writing modified cluster here: */
				result = ntfs_pwrite (ntfs->dev, ntfs->cluster_size * i, size, buf);
				if (result != size)
				{
					free (buf);
					wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
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
					error = wfs_ntfs_flush_fs (wfs_fs);
				}
			}
			if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
			{
				/* last pass with zeros: */
				if ( j != wfs_fs.npasses * 2 )
				{
					/* this block is NOT all-zeros - wipe */
					WFS_MEMSET (buf, 0, fs_block_size);
					if ( sig_recvd == 0 )
					{
						size = ntfs->cluster_size;
						/* writing modified cluster here: */
						result = ntfs_pwrite (ntfs->dev,
							ntfs->cluster_size * i, size, buf);
						if (result != size)
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
							error = wfs_ntfs_flush_fs (wfs_fs);
						}*/
					}
				}
			}
			wfs_show_progress (WFS_PROGRESS_WFS, (unsigned int) (i/ntfs->nr_clusters), &prev_percent);
		}
	}
	wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
	free (buf);
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	if ( sig_recvd != 0 )
	{
		ret_wfs = WFS_SIGNAL;
	}
	return ret_wfs;
}
#endif /* WFS_WANT_WFS */

/* ======================================================================== */

#ifdef WFS_WANT_UNRM
/**
 * Starts search for deleted inodes and undelete data on the given NTFS filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_ntfs_wipe_unrm (
# ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
# endif
{
	unsigned int prev_percent = 0;
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	/* ntfswipe --directory --logfile --mft --pagefile --undel --count wfs_fs.npasses --bytes */
#define WFSWIPE_UNRM_POS_COUNT 6
#define WFSWIPE_UNRM_POS_FSNAME 7
	const char * args_ntfswipe[] = { "ntfswipe", "--directory", "--logfile", "--pagefile",
		"--undel", "--count", "                      ",
		/* incompatible: "--bytes", "0,0xFF,0x55,0xAA,0x24,0x49,0x92,0x6D,0xB6,0xDB,0x11,0x22,0x33,0x44,0x66,0x77,0x88,0x99,0xBB,0xCC,0xDD,0xEE",*/
		NULL, NULL };
	char ** args_ntfswipe_copy = NULL;
	child_id_t child_ntfswipe;
	int ret;
	ntfs_attr *bitmapattr = NULL;
	s64 bmpsize, size, nr_mft_records, i, j, k;
	unsigned char b;
	unsigned char * buf;
#  define MYBUF_SIZE 8192
	unsigned char *mybuf;
#  define MINIM(x, y) ( ((x)<(y))?(x):(y) )
	ntfs_volume * ntfs;
	wfs_errcode_t error = 0;
	wfs_errcode_t * error_ret;
	size_t fs_block_size;

	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( wfs_fs.use_dedicated != 0 )
	{
		if ( wfs_fs.fsname == NULL )
		{
			wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_BADPARAM;
		}
		WFS_SET_ERRNO (0);
		args_ntfswipe[WFSWIPE_UNRM_POS_FSNAME] = wfs_fs.fsname;
		args_ntfswipe_copy = wfs_deep_copy_array (args_ntfswipe,
			sizeof (args_ntfswipe) / sizeof (args_ntfswipe[0]));
		if ( args_ntfswipe_copy == NULL )
		{
			error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
			wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_MALLOC;
			/*args_ntfswipe[4] = wfs_fs.fsname;*/
		}
# ifdef HAVE_SIGNAL_H
		sigchld_recvd = 0;
# endif
# ifdef HAVE_SNPRINTF
		snprintf (args_ntfswipe_copy[WFSWIPE_UNRM_POS_COUNT],
			sizeof (args_ntfswipe[WFSWIPE_UNRM_POS_COUNT]) - 1, "%lu", wfs_fs.npasses);
# else
		sprintf (args_ntfswipe_copy[WFSWIPE_UNRM_POS_COUNT], "%lu", wfs_fs.npasses);
# endif
		args_ntfswipe_copy[WFSWIPE_UNRM_POS_COUNT][22] = '\0';
		child_ntfswipe.program_name = args_ntfswipe_copy[0];
		child_ntfswipe.args = args_ntfswipe_copy;
		child_ntfswipe.child_env = NULL;
		child_ntfswipe.stdin_fd = -1;
		child_ntfswipe.stdout_fd = -1;
		child_ntfswipe.stderr_fd = -1;
		WFS_SET_ERRNO (0);
		ret_wfs = wfs_create_child (&child_ntfswipe);
		if ( ret_wfs != WFS_SUCCESS )
		{
			/* error */
			error = WFS_GET_ERRNO_OR_DEFAULT (1L);
			wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
			wfs_free_array_deep_copy (args_ntfswipe_copy,
				sizeof (args_ntfswipe) / sizeof (args_ntfswipe[0]));
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_FORKERR;
		}
		/* parent */
		wfs_wait_for_child (&child_ntfswipe);
		wfs_free_array_deep_copy (args_ntfswipe_copy,
			sizeof (args_ntfswipe) / sizeof (args_ntfswipe[0]));
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		return WFS_SUCCESS;
	} /* if ( wfs_fs.use_dedicated != 0 ) */

	ntfs = (ntfs_volume *) wfs_fs.fs_backend;
	if ( ntfs == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
	fs_block_size = wfs_ntfs_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	WFS_SET_ERRNO (0);
	mybuf = (unsigned char *) malloc (MYBUF_SIZE);
	if (mybuf == NULL)
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		wfs_ntfs_wipe_journal (wfs_fs);
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	WFS_SET_ERRNO (0);
	buf = (unsigned char *) malloc (fs_block_size);
	if ( buf == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		free (mybuf);
		wfs_ntfs_wipe_journal (wfs_fs);
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

# if (defined HAVE_NTFS_NTFS_VOLUME_H)
	bitmapattr = ntfs_attr_open (ntfs->mft_ni, NTFS_AT_BITMAP, NTFS_AT_UNNAMED, 0);
# else
	bitmapattr = ntfs_attr_open (ntfs->mft_ni, AT_BITMAP, AT_UNNAMED, 0);
# endif
	if (bitmapattr == NULL)
	{
		free (buf);
		free (mybuf);
		wfs_ntfs_wipe_journal (wfs_fs);
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_ATTROPEN;
	}
	bmpsize = bitmapattr->initialized_size;

	nr_mft_records = ntfs->mft_na->initialized_size >> ntfs->mft_record_size_bits;

	if ( sig_recvd != 0 )
	{
		ntfs_attr_close (bitmapattr);
		free (buf);
		free (mybuf);
		wfs_ntfs_wipe_journal (wfs_fs);
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_SIGNAL;
	}

	for (i = 0; (i < bmpsize) && (sig_recvd==0) /*&& (ret_wfs==WFS_SUCCESS)*/; i += MYBUF_SIZE)
	{
		/* read a part of the file bitmap */
		size = ntfs_attr_pread (bitmapattr, i, MINIM ((bmpsize - i), MYBUF_SIZE), mybuf);
		if (size < 0)
		{
			break;
		}

		/* parse each byte of the just-read part of the bitmap */
		for (j = 0; (j < size) && (sig_recvd==0) /*&& (ret_wfs==WFS_SUCCESS)*/; j++)
		{
			b = mybuf[j];
			/* parse each bit of the byte Bit 1 means 'in use'. */
			for (k = 0; (k < CHAR_BIT) && (sig_recvd==0) /*&& (ret_wfs==WFS_SUCCESS)*/;
				k++, b>>=1)
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
				if ( sig_recvd != 0 )
				{
					break;
				}
				/* wiping the i-node here: */
				ret = destroy_record (wfs_fs, (i+j)*CHAR_BIT+k, buf);
				if ( ret != WFS_SUCCESS )
				{
					ret_wfs = ret;
				}
			}
		}
		wfs_show_progress (WFS_PROGRESS_UNRM,
			(unsigned int) ((i * 50) / (bmpsize * 8)), &prev_percent);
	}
done:
	ntfs_attr_close (bitmapattr);
	free (buf);
	free (mybuf);

	wfs_show_progress (WFS_PROGRESS_UNRM, 50, &prev_percent);
	if ( ret_wfs == WFS_SUCCESS )
	{
		ret_wfs = wfs_ntfs_wipe_journal (wfs_fs);
	}
	else if ( ret_wfs == WFS_SIGNAL )
	{
		wfs_ntfs_wipe_journal (wfs_fs);
	}
	else
	{
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
	}

	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	if ( sig_recvd != 0 )
	{
		ret_wfs = WFS_SIGNAL;
	}
	return ret_wfs;
}
#endif /* WFS_WANT_UNRM */

/* ======================================================================== */

/**
 * Opens an NTFS filesystem on the given device.
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
wfs_ntfs_open_fs (
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
	int res = 0;
	ntfs_volume *nv = NULL;
	wfs_errcode_t * error_ret;
	wfs_errcode_t error = 0;

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

	WFS_SET_ERRNO (0);
	nv = ntfs_mount (wfs_fs->fsname, 0);
	if ( (nv == NULL) && (sig_recvd == 0) )
	{
		error = WFS_OPENFS;
#ifdef HAVE_ERRNO_H
		if ( errno != 0 )
		{
			error = errno;
		}
#endif
		ret = WFS_OPENFS;
#if (defined HAVE_SYS_MOUNT_H) && (defined HAVE_UMOUNT)
		res = umount (wfs_fs->fsname);
		if ( (res == 0) && (sig_recvd == 0) )
		{
			nv = ntfs_mount (wfs_fs->fsname, 0);
			if ( nv != NULL )
			{
				error = 0;
				wfs_fs->whichfs = WFS_CURR_FS_NTFS;
				wfs_fs->fs_backend = nv;
/*				WFS_MEMCOPY (&(wfs_fs->ntfs), nv, sizeof(ntfs_volume));*/
				if ( wfs_fs->use_dedicated != 0 )
				{
					/* allow the dedicated tool to mount */
					ntfs_umount (nv, FALSE);
				}
				ret = WFS_SUCCESS;
			}
		}
#endif /* HAVE_SYS_MOUNT_H && HAVE_UMOUNT */
	}
	else if ( nv != NULL )
	{
		error = 0;
		wfs_fs->whichfs = WFS_CURR_FS_NTFS;
		wfs_fs->fs_backend = nv;
/*		WFS_MEMCOPY (&(wfs_fs->ntfs), nv, sizeof(ntfs_volume));*/
		if ( wfs_fs->use_dedicated != 0 )
		{
			/* allow the dedicated tool to mount */
			ntfs_umount (nv, FALSE);
		}
		ret = WFS_SUCCESS;
	}
	else if ( sig_recvd != 0 )
	{
		ret = WFS_SIGNAL;
	}
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}

	return ret;
}

/* ======================================================================== */

/**
 * Checks if the given NTFS filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_ntfs_chk_mount (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	unsigned long int mt_flags = 0;		/* Mount flags */
	wfs_errcode_t error = 0;
	wfs_errcode_t * error_ret;

	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( wfs_fs.fsname == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}

	/* reject if mounted for read and write (when we can't go on with our work) */
	error = ntfs_check_if_mounted (wfs_fs.fsname, &mt_flags);
	if ( error != 0 )
	{
		ret = WFS_MNTCHK;
	}

	if ( 	(ret == WFS_SUCCESS) &&
		((mt_flags & NTFS_MF_MOUNTED) != 0) &&
		((mt_flags & NTFS_MF_READONLY) == 0)
	   )
	{
		error = 1L;
		ret = WFS_MNTRW;
	}

	if ( ret == WFS_SUCCESS )
	{
		ret = wfs_check_mounted (wfs_fs);
		if ( ret == WFS_MNTRW )
		{
			error = 1L;
		}
	}

	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return ret;
}

/* ======================================================================== */

/**
 * Closes the NTFS filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_ntfs_close_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	int wfs_err;
	ntfs_volume * ntfs;
	wfs_errcode_t error = 0;
	wfs_errcode_t * error_ret;

	if ( wfs_fs.use_dedicated != 0 )
	{
		/* nothing to do, the filesystem wasn't opened in the first place */
		return WFS_SUCCESS;
	}
	ntfs = (ntfs_volume *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( ntfs != NULL )
	{
		wfs_err = ntfs_umount (ntfs, FALSE);
		if ( wfs_err != 0 )
		{
			ret = WFS_FSCLOSE;
			error = wfs_err;
		}
	}
	else
	{
		ret = WFS_BADPARAM;
	}
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return ret;
}

/* ======================================================================== */

/**
 * Checks if the NTFS filesystem has errors.
 * \param wfs_fs The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_ntfs_check_err (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs )
#else
	wfs_fs )
	const wfs_fsid_t wfs_fs;
#endif
{
	ntfs_volume * ntfs;

	if ( wfs_fs.use_dedicated != 0 )
	{
		/* nothing to do, the filesystem wasn't opened in the first place */
		return 0;
	}
	ntfs = (ntfs_volume *) wfs_fs.fs_backend;
	if ( ntfs == NULL )
	{
		return 1;
	}
	/* better than nothing... */
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	return (ntfs->flags & NTFS_VOLUME_MODIFIED_BY_CHKDSK);
#else
	return (ntfs->flags & VOLUME_MODIFIED_BY_CHKDSK);
#endif
}

/* ======================================================================== */

/**
 * Checks if the NTFS filesystem is dirty (has unsaved changes).
 * \param wfs_fs The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_ntfs_is_dirty (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs )
#else
	wfs_fs )
	const wfs_fsid_t wfs_fs;
#endif
{
	int is_dirty = 0;
	ntfs_volume * ntfs;

	if ( wfs_fs.use_dedicated != 0 )
	{
		/* nothing to do, the filesystem wasn't opened in the first place */
		return 0;
	}
	ntfs = (ntfs_volume *) wfs_fs.fs_backend;
	if ( ntfs == NULL )
	{
		return 1;
	}
#if (defined HAVE_NTFS_NTFS_VOLUME_H)
	if ( ((ntfs->flags & NTFS_VOLUME_IS_DIRTY) != 0)
		|| ((ntfs->flags & NTFS_VOLUME_MODIFIED_BY_CHKDSK) != 0)
# ifdef NVolWasDirty
		|| (NVolWasDirty (ntfs) != 0)
# endif
		)
	{
		is_dirty = 1;
	}
#else
	if ( ((ntfs->flags & VOLUME_IS_DIRTY) != 0)
		|| ((ntfs->flags & VOLUME_MODIFIED_BY_CHKDSK) != 0)
# ifdef NVolWasDirty
		|| (NVolWasDirty (ntfs) != 0)
# endif
		)
	{
		is_dirty = 1;
	}
#endif
	return is_dirty;
}

/* ======================================================================== */

/**
 * Flushes the NTFS filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return WFS_SUCCESS in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_ntfs_flush_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	ntfs_volume * ntfs;
	wfs_errcode_t error = 0;
	wfs_errcode_t * error_ret;

	if ( wfs_fs.use_dedicated != 0 )
	{
		/* nothing to do, the filesystem wasn't opened in the first place */
		return WFS_SUCCESS;
	}
	ntfs = (ntfs_volume *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( ntfs == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}
#ifdef NTFS_RICH
	error = ntfs_volume_commit (ntfs);
	if (error < 0)
	{
		ret = WFS_FLUSHFS;
	}
#endif
	error = ntfs->dev->d_ops->sync (ntfs->dev);
	if (error != 0)
	{
		ret = WFS_FLUSHFS;
	}
#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_SYNC)
	sync ();
#endif
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return ret;
}

/* ======================================================================== */

/**
 * Print the version of the current library, if applicable.
 */
void wfs_ntfs_print_version (WFS_VOID)
{
#ifndef HAVE_LIBNTFS_3G
	const char *lib_ver = NULL;

	lib_ver = ntfs_libntfs_version ();
	printf ( "LibNTFS %s, http://www.linux-ntfs.org\n",
		(lib_ver != NULL)? lib_ver : "<?>" );
#else
	printf ( "NTFS-3G: <?>\n");
#endif
}

/* ======================================================================== */

/**
 * Get the preferred size of the error variable.
 * \return the preferred size of the error variable.
 */
size_t wfs_ntfs_get_err_size (WFS_VOID)
{
	return sizeof (wfs_errcode_t);
}

/* ======================================================================== */

/**
 * Initialize the library.
 */
void wfs_ntfs_init (WFS_VOID)
{
}

/* ======================================================================== */

/**
 * De-initialize the library.
 */
void wfs_ntfs_deinit (WFS_VOID)
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
wfs_ntfs_show_error (
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
