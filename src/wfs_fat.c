/*
 * A program for secure cleaning of free space on filesystems.
 *	-- FAT12/16/32 file system-specific functions.
 *
 * Copyright (C) 2007-2009 Bogdan Drozdowski, bogdandr (at) op.pl
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
 * This code uses parts of the Tiny FAT FS library (on LGPL) by knightray@gmail.com.
 */

#include "wfs_cfg.h"

#include "wipefreespace.h"

#if (defined HAVE_TFFS_H) && (defined HAVE_LIBTFFS)
# include <tffs.h>
# include <pubstruct.h>
# include <hai_file.h>
# include <fat.h>
# include <dirent.h>
# include <dir.h>
/* compatibility with NTFS */
# undef min
# include <common.h>
#else
# error Something wrong. FAT12/16/32 requested, but tffs.h or libtffs missing.
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* sync(), read() */
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_STRING_H
# if ((!defined STDC_HEADERS) || (!STDC_HEADERS)) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>	/* strncmp() */
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>	/* for open() */
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>	/* for open() */
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>	/* open() */
#endif

#ifndef O_RDONLY
# define O_RDONLY	0
#endif

#include "wfs_fat.h"
#include "wfs_signal.h"
#include "wfs_util.h"

static unsigned short WFS_ATTR ((nonnull))
_get_fat_entry_len (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	const tfat_t * const pfat)
#else
	pfat)
	const tfat_t * const pfat;
#endif
{
	if ( pfat == NULL )
	{
		return 0;
	}
	if ( pfat->ptffs == NULL )
	{
		return 0;
	}

	switch (pfat->ptffs->fat_type)
	{
		case FT_FAT12:
			return 12;
		case FT_FAT16:
			return 16;
		case FT_FAT32:
			return 32;
	}
	return 0;
}

static unsigned int
_get_fat_entry (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	const tfat_t * const pfat, const unsigned int clus)
#else
	pfat, clus)
	const tfat_t * const pfat;
	const unsigned int clus;
#endif
{
	tffs_t * ptffs;
	void * pclus;
	unsigned int entry_val = 0x0FFFFFFF;
	unsigned short fat_entry;

	/*
	if ( pfat == NULL )
	{
		return 0;
	}*/
	if ( (pfat->ptffs == NULL) || (pfat->secbuf == NULL) )
	{
		return 0;
	}
	if ( pfat->ptffs->pbs == NULL )
	{
		return 0;
	}
	ptffs = pfat->ptffs;
	if ( ptffs->pbs->byts_per_sec == 0 ) return 0;

	pclus = pfat->secbuf + ((clus * _get_fat_entry_len (pfat)) / 8) % ptffs->pbs->byts_per_sec;

	if (ptffs->fat_type == FT_FAT12)
	{
		fat_entry = *((unsigned short *)pclus);
		if ((clus & 1) != 0)
		{
			entry_val = (fat_entry >> 4) & 0x0FFF;
		}
		else
		{
			entry_val = fat_entry & 0x0FFF;
		}
	}
	else if (ptffs->fat_type == FT_FAT16)
	{
		entry_val = *((unsigned short *)pclus);
	}
	else if (ptffs->fat_type == FT_FAT32)
	{
		entry_val = *((unsigned int *)pclus) & 0x0FFFFFFF;
	}

	return entry_val;
}

static int WFS_ATTR ((nonnull))
_read_fat_sector (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	tfat_t * pfat, int fat_sec)
#else
	pfat, fat_sec)
	tfat_t * pfat;
	int fat_sec;
#endif
{
	tffs_t * ptffs;

	if ( pfat == NULL )
	{
		return 0;
	}
	if ( pfat->ptffs == NULL )
	{
		return 0;
	}

	ptffs = pfat->ptffs;
	if ( (ptffs->hdev == NULL) || (pfat->secbuf == NULL) ) return 0;
	if (HAI_readsector (ptffs->hdev, fat_sec, pfat->secbuf) != HAI_OK)
	{
		return FALSE;
	}

	if ((ptffs->fat_type == FT_FAT12) && (ptffs->pbs != NULL))
	{
		/* This cluster access spans a sector boundary in the FAT      */
		/* There are a number of strategies to handling this. The      */
		/* easiest is to always load FAT sectors into memory           */
		/* in pairs if the volume is FAT12 (if you want to load        */
		/* FAT sector N, you also load FAT sector N+1 immediately      */
		/* following it in memory unless sector N is the last FAT      */
		/* sector). It is assumed that this is the strategy used here  */
		/* which makes this if test for a sector boundary span         */
		/* unnecessary.                                                */
		if (HAI_readsector (ptffs->hdev, fat_sec + 1,
			pfat->secbuf + ptffs->pbs->byts_per_sec) != HAI_OK)
		{
			return FALSE;
		}
	}
	pfat->cur_fat_sec = fat_sec;
	return TRUE;
}

static int WFS_ATTR ((nonnull))
_write_fat_sector (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	tfat_t * pfat, int fat_sec)
#else
	pfat, fat_sec)
	tfat_t * pfat;
	int fat_sec;
#endif
{
	tffs_t * ptffs;

	/*
	if ( pfat == NULL )
	{
		return 0;
	}*/
	if ( pfat->ptffs == NULL )
	{
		return 0;
	}

	ptffs = pfat->ptffs;
	if ( (ptffs->hdev == NULL) || (pfat->secbuf == NULL) ) return 0;
	if (HAI_writesector (ptffs->hdev, fat_sec, pfat->secbuf) != HAI_OK)
	{
		return FALSE;
	}

	if ((ptffs->fat_type == FT_FAT12) && (ptffs->pbs != NULL))
	{
		if (HAI_writesector (ptffs->hdev, fat_sec + 1,
			pfat->secbuf + ptffs->pbs->byts_per_sec) != HAI_OK)
		{
			return FALSE;
		}
	}
	return TRUE;
}

static int
_is_entry_free (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	const tfat_t * const pfat, const unsigned int entry_val)
#else
	pfat, entry_val)
	const tfat_t * const pfat;
	const unsigned int entry_val;
#endif
{
	/*
	if ( pfat == NULL )
	{
		return 0;
	}*/

	if ( pfat->ptffs == NULL )
	{
		return 0;
	}

	if (pfat->ptffs->fat_type == FT_FAT12)
	{
		return !(entry_val & 0x0FFF);
	}
	else if (pfat->ptffs->fat_type == FT_FAT16)
	{
		return !(entry_val & 0xFFFF);
	}
	else if (pfat->ptffs->fat_type == FT_FAT32)
	{
		return !(entry_val & 0x0FFFFFFF);
	}
	return FALSE;
}

static int WFS_ATTR ((nonnull))
_clus2fatsec (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	tfat_t * pfat, unsigned int clus)
#else
	pfat, clus)
	tfat_t * pfat;
	unsigned int clus;
#endif
{
	if ( pfat == NULL )
	{
		return 0;
	}
	if ( pfat->ptffs == NULL )
	{
		return 0;
	}
	if ( pfat->ptffs->pbs == NULL )
	{
		return 0;
	}
	if ( pfat->ptffs->pbs->byts_per_sec == 0 ) return 0;

	return (pfat->ptffs->sec_fat + ((clus * _get_fat_entry_len (pfat)) / 8)
		/ pfat->ptffs->pbs->byts_per_sec);
}

static int WFS_ATTR ((nonnull))
_lookup_free_clus (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	tfat_t * pfat, unsigned int * pfree_clus)
#else
	pfat, pfree_clus)
	tfat_t * pfat;
	uint32 * pfree_clus;
#endif
{
	tffs_t * ptffs;
	unsigned int cur_clus;
	int ret;

	/*
	if ( (pfat == NULL) || (pfree_clus == NULL) )
	{
		return 0;
	}*/

	if ( pfat->ptffs == NULL )
	{
		return 0;
	}

	ptffs = pfat->ptffs;
	ret = FAT_OK;
	cur_clus = pfat->last_free_clus;
	if (_read_fat_sector (pfat, _clus2fatsec (pfat, pfat->last_free_clus)) == FALSE)
		return ERR_FAT_DEVICE_FAIL;

	while (sig_recvd == 0)
	{
		if (_is_entry_free (pfat, _get_fat_entry (pfat, cur_clus)) != 0)
		{
			*pfree_clus = cur_clus;
			pfat->last_free_clus = cur_clus;
			break;
		}

		cur_clus++;
		if (cur_clus > ptffs->total_clusters)
		{
			cur_clus = 0;
		}

		if (cur_clus == pfat->last_free_clus)
		{
			ret = ERR_FAT_NO_FREE_CLUSTER;
			break;
		}

		if (_clus2fatsec (pfat, cur_clus - 1) != _clus2fatsec (pfat, cur_clus))
		{
			if (_read_fat_sector (pfat, _clus2fatsec (pfat, cur_clus)) == FALSE)
			{
				ret = ERR_FAT_DEVICE_FAIL;
				break;
			}
		}
	}

	return ret;
}

static void WFS_ATTR ((nonnull))
_file_seek (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	tfile_t * pfile, unsigned int offset)
#else
	pfile, offset)
	tfile_t * pfile;
	unsigned int offset;
#endif
{
	int cur_offset = offset;
	if ( pfile == NULL )
	{
		return;
	}
	if ( pfile->ptffs == NULL )
	{
		return;
	}
	if ( pfile->ptffs->pbs == NULL )
	{
		return;
	}
	if ( pfile->ptffs->pbs->byts_per_sec == 0 ) return;

	while ( (cur_offset - pfile->ptffs->pbs->byts_per_sec > 0) &&
		(fat_get_next_sec (pfile->ptffs->pfat, &pfile->cur_clus, &pfile->cur_sec) != 0)
		&& (sig_recvd == 0) )
	{
		cur_offset -= pfile->ptffs->pbs->byts_per_sec;
	}
	pfile->cur_sec_offset = cur_offset;
}

static int
_get_dirent (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	tdir_t * pdir, dir_entry_t * pdirent)
#else
	pdir, pdirent)
	tdir_t * pdir;
	dir_entry_t * pdirent;
#endif
{
	int ret = DIRENTRY_OK;
#ifndef HAVE_MEMCPY
	size_t j;
#endif
	/*
	if ( (pdir == NULL) || (pdirent == NULL) )
	{
		return ERR_DIRENTRY_NOMORE_ENTRY;
	}*/
	if ( (pdir->ptffs == NULL) || (pdir->secbuf == NULL) )
	{
		return ERR_DIRENTRY_NOMORE_ENTRY;
	}
	if ( pdir->ptffs->pbs == NULL )
	{
		return ERR_DIRENTRY_NOMORE_ENTRY;
	}
	if ( pdir->ptffs->pbs->byts_per_sec == 0 ) return ERR_DIRENTRY_NOMORE_ENTRY;

	if (pdir->cur_dir_entry < (pdir->ptffs->pbs->byts_per_sec / sizeof (dir_entry_t)))
	{
#ifdef HAVE_MEMCPY
		memcpy (pdirent, (dir_entry_t *)pdir->secbuf + pdir->cur_dir_entry, sizeof (dir_entry_t));
#else
		for ( j=0; j < sizeof (dir_entry_t); j++ )
		{
			((char *)pdirent)[j] =
				((char *)((dir_entry_t *)pdir->secbuf + pdir->cur_dir_entry))[j];
		}
#endif
		pdir->cur_dir_entry++;
	}
	else
	{
		if ( pdir->ptffs->pfat == NULL )
		{
			return ERR_DIRENTRY_NOMORE_ENTRY;
		}
		if (fat_get_next_sec (pdir->ptffs->pfat, &pdir->cur_clus, &pdir->cur_sec) != 0)
		{
			pdir->cur_dir_entry = 0;
			if ((ret = dir_read_sector (pdir)) == DIR_OK)
			{
#ifdef HAVE_MEMCPY
				memcpy (pdirent, (dir_entry_t *)pdir->secbuf + pdir->cur_dir_entry,
					sizeof (dir_entry_t));
#else
				for ( j=0; j < sizeof (dir_entry_t); j++ )
				{
					((char *)pdirent)[j] =
						((char *)((dir_entry_t *)pdir->secbuf
							+ pdir->cur_dir_entry))[j];
				}
#endif
				pdir->cur_dir_entry++;
			}
			else
			{
				ret = ERR_DIRENTRY_DEVICE_FAIL;
			}
		}
		else
		{
			ret = ERR_DIRENTRY_NOMORE_ENTRY;
		}
	}
	return ret;
}

static int WFS_ATTR ((nonnull))
wfs_fat_dirent_find (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	const wfs_fsid_t FS, tdir_t * pdir, error_type * const error)
#else
	FS, pdir, error)
	const wfs_fsid_t FS;
	tdir_t * pdir;
	error_type * const error;
#endif
{
	int ret;
	dir_entry_t dirent;
	unsigned long int j;
	int selected[NPAT];

	if ( (pdir == NULL) || (FS.fat == NULL) || (error == NULL) )
	{
		return ERR_DIRENTRY_NOT_FOUND;
	}
	if ( pdir->secbuf == NULL ) return ERR_DIRENTRY_NOT_FOUND;

	pdir->cur_clus = pdir->start_clus;
	pdir->cur_sec = 0;
	pdir->cur_dir_entry = 0;
	if (dir_read_sector (pdir) != DIR_OK) return ERR_DIRENTRY_NOT_FOUND;

	ret = DIRENTRY_OK;
	while (sig_recvd == 0)
	{
		ret = _get_dirent (pdir, &dirent);
		if (ret == DIRENTRY_OK)
		{

			if (dirent.dir_name[0] == 0x00)
			{
				ret = ERR_DIRENTRY_NOT_FOUND;
				break;
			}
			else if (dirent.dir_name[0] == 0xE5)
			{
				/* wipe the name here */
				for ( j = 0; (j < npasses) && (sig_recvd == 0); j++ )
				{
					if ( dirent.dir_attr == ATTR_LONG_NAME )
					{
						fill_buffer ( j, (unsigned char *)(
							(dir_entry_t *)pdir->secbuf
							+ pdir->cur_dir_entry-1),
							13 /*dirent.h->long_dir_entry_t*/
							* 2 /*sizeof UTF-16 character */, selected, FS );
					}
					else
					{
						fill_buffer ( j, (unsigned char *)(
							(dir_entry_t *)pdir->secbuf
							+ pdir->cur_dir_entry-1),
							sizeof (dirent.dir_name), selected, FS );
					}
					if ( sig_recvd != 0 )
					{
						break;
					}
					/* write the wiped name: */
					error->errcode.gerror = dir_write_sector (pdir);
					if ( error->errcode.gerror != DIR_OK )
					{
						show_error ( *error, err_msg_wrtblk, FS.fsname, FS );
						break;
					}
					/* Flush after each writing, if more than 1 overwriting
					   needs to be done. Allow I/O bufferring (efficiency),
					   if just one pass is needed. */
					if ( (npasses > 1) && (sig_recvd == 0) )
					{
						error->errcode.gerror = wfs_fat_flush_fs ( FS, error );
					}
				}
				/* last pass with zeros: */
				if ( dirent.dir_attr == ATTR_LONG_NAME )
				{
#ifdef HAVE_MEMSET
					memset ((dir_entry_t *)pdir->secbuf + pdir->cur_dir_entry-1,
						'\0', 13 /*dirent.h->long_dir_entry_t*/
							* 2 /*sizeof UTF-16 character */);
#else
					for ( j=0; j < 13 /*dirent.h->long_dir_entry_t*/
							* 2 /*sizeof UTF-16 character */; j++ )
					{
						(char*)((dir_entry_t*)pdir->secbuf
							+pdir->cur_dir_entry-1)[j]='\0';
					}
#endif
				}
				else
				{
#ifdef HAVE_MEMSET
					memset ((dir_entry_t *)pdir->secbuf + pdir->cur_dir_entry-1,
						'\0', sizeof (dirent.dir_name));
#else
					for ( j=0; j < sizeof (dirent.dir_name); j++ )
					{
						(char*)((dir_entry_t*)pdir->secbuf
							+pdir->cur_dir_entry-1)[j]='\0';
					}
#endif
				}
				if ( sig_recvd != 0 )
				{
					break;
				}
				/* write the wiped name: */
				error->errcode.gerror = dir_write_sector (pdir);
				if ( error->errcode.gerror != DIR_OK )
				{
					show_error ( *error, err_msg_wrtblk, FS.fsname, FS );
					break;
				}
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( (npasses > 1) && (sig_recvd == 0) )
				{
					error->errcode.gerror = wfs_fat_flush_fs ( FS, error );
				}
				continue;
			}
		}
		else if (ret == ERR_DIRENTRY_NOMORE_ENTRY)
		{
			ret = ERR_DIRENTRY_NOT_FOUND;
			break;
		}
		else
		{
			break;
		}
	}
	return ret;
}


/**
 * Returns the buffer size needed to work on the smallest physical unit on a FAT filesystem.
 * \param FS The filesystem.
 * \return Block size on the filesystem.
 */
static size_t WFS_ATTR ((warn_unused_result))
wfs_fat_get_block_size (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	const wfs_fsid_t FS )
#else
	FS)
	const wfs_fsid_t FS;
#endif
{
	if ( FS.fat == NULL )
	{
		return 512;
	}
	if ( ((tffs_t *)(FS.fat))->pbs == NULL )
	{
		return 512;
	}
	/* this is required, because space for files is allocated in clusters, not in sectors */
	return ((tffs_t *)(FS.fat))->pbs->byts_per_sec * ((tffs_t *)(FS.fat))->pbs->sec_per_clus;
}

/**
 * Wipes the free space after the given file's data.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \param file The file to wipe data after.
 * \param buf The buffer to use.
 */
static errcode_enum WFS_ATTR ((nonnull))
wfs_fat_wipe_file_tail (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	wfs_fsid_t FS, error_type * const error, tfile_handle_t file, unsigned char * buf)
#else
	FS, error, file, buf)
	wfs_fsid_t FS;
	error_type * const error;
	tfile_handle_t file;
	unsigned char * buf;
#endif
{
	unsigned long int j;
	int selected[NPAT];
	tfile_t * fh = (tfile_t *) file;
	unsigned int file_len;
	size_t bufsize;
	int written;
	errcode_enum ret_tail = WFS_SUCCESS;

	if ( (error == NULL) || (FS.fat == NULL) || (file == NULL) || (buf == NULL) )
	{
		return WFS_BADPARAM;
	}

	file_len = dirent_get_file_size (fh->pdir_entry);
	bufsize = wfs_fat_get_block_size (FS) -	(file_len % wfs_fat_get_block_size (FS));

	for ( j = 0; (j < npasses) && (sig_recvd == 0); j++ )
	{
		fill_buffer ( j, buf, bufsize, selected, FS );
		if ( sig_recvd != 0 )
		{
			ret_tail = WFS_SIGNAL;
			break;
		}
		/* wipe the space after the file */
		_file_seek (fh, file_len);
		written = TFFS_fwrite (file, bufsize, buf);
		if ( written != (int)bufsize )
		{
			show_error ( *error, err_msg_wrtblk, FS.fsname, FS );
			ret_tail = WFS_BLKWR;
			break;
		}
		/* workaround a bug in tffs? */
		if ( written > 0 ) fh->file_size -= written;
		/* Flush after each writing, if more than 1 overwriting needs to be done.
		Allow I/O bufferring (efficiency), if just one pass is needed. */
		if ( (npasses > 1) && (sig_recvd == 0) )
		{
			error->errcode.gerror = wfs_fat_flush_fs ( FS, error );
		}
	}
	if ( (FS.zero_pass != 0) && (sig_recvd == 0) )
	{
		/* last pass with zeros: */
#ifdef HAVE_MEMSET
		memset ( buf, 0, bufsize );
#else
		for ( j=0; j < bufsize; j++ )
		{
			buf[j] = '\0';
		}
#endif
		if ( sig_recvd == 0 )
		{
			/* wipe the space after the file */
			_file_seek (fh, file_len);
			written = TFFS_fwrite (file, bufsize, buf);
			if ( written != (int)bufsize )
			{
				show_error ( *error, err_msg_wrtblk, FS.fsname, FS );
				ret_tail = WFS_BLKWR;
			}
			/* workaround a bug in tffs? */
			if ( written > 0 ) fh->file_size -= written;
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (npasses > 1) && (sig_recvd == 0) )
			{
				error->errcode.gerror = wfs_fat_flush_fs ( FS, error );
			}
		}
	}
	/* restore file's original size */
	dirent_set_file_size (fh->pdir_entry, file_len);

	if ( sig_recvd != 0 )
	{
		return WFS_SIGNAL;
	}
	return ret_tail;
}

/**
 * Recurisvely wipes the free space after the files in the given directory.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \param dir The directory to browse for files.
 * \param buf The buffer to use.
 */
static errcode_enum WFS_ATTR ((nonnull))
wfs_fat_wipe_file_tails_in_dir (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	wfs_fsid_t FS, error_type * const error, tdir_handle_t dir, unsigned char * buf)
#else
	FS, error, dir, buf)
	wfs_fsid_t FS;
	error_type * const error;
	tdir_handle_t dir;
	unsigned char * buf;
#endif
{
	int dir_res = TFFS_OK;
	errcode_enum ret_part_dir = WFS_SUCCESS;
	dirent_t entry;
	tfile_handle_t fh;
	unsigned int prev_percent = 0;
	unsigned int curr_direlem = 0;

	if ( (error == NULL) || (FS.fat == NULL) || (dir == NULL) || (buf == NULL) )
	{
		return WFS_BADPARAM;
	}

	do
	{
		dir_res = TFFS_readdir (dir, &entry);
		if ( (dir_res == ERR_TFFS_LAST_DIRENTRY) || (dir_res != TFFS_OK) ) break;
		if ( ((unsigned char)(entry.d_name[0]) == 0xE5)
			|| ((unsigned char)(entry.d_name_short[0]) == 0xE5) )
		{
			/* deleted element - don't wipe */
			continue;
		}
		/* skip 'current dir' and 'parent dir' */
		if ( (entry.d_name[0] == 0x2E) || (entry.d_name_short[0] == 0x2E) )
		{
			/* deleted element - don't wipe */
			continue;
		}
		if ( (strncmp (entry.d_name, ".", 1) == 0)
			|| (strncmp (entry.d_name_short, ".", 1) == 0)
			|| (strncmp (entry.d_name, "..", 2) == 0)
			|| (strncmp (entry.d_name_short, "..", 2) == 0)
		)
		{
			continue;
		}
		if ( entry.dir_attr == DIR_ATTR_DIRECTORY )
		{
			/* recurse into the directory */
			dir_res = TFFS_chdir (FS.fat, entry.d_name);
			if ( dir_res != TFFS_OK )
			{
				ret_part_dir = WFS_DIRITER;
				continue;
			}
			ret_part_dir = wfs_fat_wipe_file_tails_in_dir
				(FS, error, (tdir_handle_t) (((tffs_t *)(FS.fat))->cur_dir), buf);
			TFFS_chdir (FS.fat, "..");
		}
		else if ( (entry.dir_attr & DIR_ATTR_VOLUME_ID) != DIR_ATTR_VOLUME_ID )
		{
			/* wipe this file's last sector's free space */
			dir_res = TFFS_fopen (FS.fat, entry.d_name, "a", &fh);
			if ( dir_res != TFFS_OK )
			{
				continue;
			}
			wfs_fat_wipe_file_tail (FS, error, fh, buf);
			TFFS_fclose (fh);
		}
		if ( (dir == (tdir_handle_t) ((tffs_t *)(FS.fat))->root_dir)
			&& (((tffs_t *)(FS.fat))->pbs != NULL) )
		{
			curr_direlem++;
			show_progress (PROGRESS_PART,
				curr_direlem/((tffs_t *)(FS.fat))->pbs->root_ent_cnt, &prev_percent);
		}
	}
	while ( sig_recvd == 0 );
	if ( dir_res != TFFS_OK ) ret_part_dir = WFS_DIRITER;

	return ret_part_dir;
}

/**
 * Wipes the free space in partially used blocks on the given FAT filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_fat_wipe_part (
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
	errcode_enum ret_part = WFS_SUCCESS;
	tdir_handle_t dirh;
	unsigned char * buf = NULL;
	unsigned int prev_percent = 0;

	if ( (error == NULL) || (FS.fat == NULL) )
	{
		show_progress (PROGRESS_PART, 100, &prev_percent);
		return WFS_BADPARAM;
	}

	/* init dirh */
	dirh = (tdir_handle_t) ((tffs_t *)(FS.fat))->root_dir;
	if ( dirh == NULL )
	{
		show_progress (PROGRESS_PART, 100, &prev_percent);
		return WFS_DIRITER;
	}

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	buf = (unsigned char *) malloc ( wfs_fat_get_block_size (FS) );
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
        ret_part = wfs_fat_wipe_file_tails_in_dir (FS, error, dirh, buf);
	show_progress (PROGRESS_PART, 100, &prev_percent);
	free (buf);
	return ret_part;
}

/**
 * Wipes the free space on the given FAT filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_fat_wipe_fs (
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
	unsigned int cluster = 0;
	unsigned long int j;
	int selected[NPAT];
	tfat_t * pfat;
	tffs_t * ptffs;
	int sec_per_clus = 1;
	unsigned int bytes_per_sector = 512;
	int sec_iter;
	unsigned int prev_percent = 0;
	unsigned int curr_sector = 0;

	if ( (error == NULL) || (FS.fat == NULL) )
	{
		show_progress (PROGRESS_WFS, 100, &prev_percent);
		return WFS_BADPARAM;
	}

	ptffs = (tffs_t *) FS.fat;
	pfat = ptffs->pfat;
	if ( ptffs->pbs != NULL )
	{
		sec_per_clus = ptffs->pbs->sec_per_clus;
		bytes_per_sector = ptffs->pbs->byts_per_sec;
	}
	if ( sec_per_clus == 0 ) sec_per_clus = 1;
	if ( bytes_per_sector == 0 ) sec_per_clus = 512;
	pfat->last_free_clus = 0;
	cluster = 0;
	while (sig_recvd == 0)
	{
		if ( _lookup_free_clus (pfat, &cluster) != FAT_OK ) break;
		/* better not wipe anything before the first data sector, even if marked unused */
		if ( clus2sec (ptffs, cluster) < ptffs->sec_first_data )
		{
			pfat->last_free_clus = (pfat->last_free_clus+1) % (ptffs->total_clusters);
			cluster = (cluster+1) % (ptffs->total_clusters);
			if ( cluster == 0 ) break;
			continue;
		}
		/* save the sector after the last wiped in a cluster (FAT12 reads/writes two at a time):*/
		_read_fat_sector (pfat, (int)clus2sec (ptffs, cluster) + sec_per_clus-1);
		for ( j = 0; (j < npasses) && (sig_recvd == 0); j++ )
		{
			fill_buffer ( j, pfat->secbuf, bytes_per_sector, selected, FS );
			if ( sig_recvd != 0 )
			{
				ret_wfs = WFS_SIGNAL;
				break;
			}
			error->errcode.gerror = 0;
			/* wipe all sectors of cluster 'cluster' */
			for ( sec_iter = 0; sec_iter < sec_per_clus; sec_iter++ )
			{
				error->errcode.gerror = _write_fat_sector (pfat,
					(int)clus2sec (ptffs, cluster) + sec_iter);
				if ( error->errcode.gerror == 0 ) break;
			}
			if ( error->errcode.gerror == 0 /* _write_fat_sector returns 1 on success */ )
			{
				show_error ( *error, err_msg_wrtblk, FS.fsname, FS );
				ret_wfs = WFS_BLKWR;
				break;
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (npasses > 1) && (sig_recvd == 0) )
			{
				error->errcode.gerror = wfs_fat_flush_fs ( FS, error );
			}
		}
		if ( (FS.zero_pass != 0) && (sig_recvd == 0) )
		{
			/* last pass with zeros: */
#ifdef HAVE_MEMSET
			memset ( pfat->secbuf, 0, bytes_per_sector );
#else
			for ( j=0; j < bytes_per_sector; j++ )
			{
				pfat->secbuf[j] = '\0';
			}
#endif
			if ( sig_recvd != 0 )
			{
				ret_wfs = WFS_SIGNAL;
				break;
			}
			error->errcode.gerror = 0;
			/* wipe all sectors of cluster 'cluster' */
			for ( sec_iter = 0; sec_iter < sec_per_clus; sec_iter++ )
			{
				error->errcode.gerror = _write_fat_sector (pfat,
					(int)clus2sec (ptffs, cluster) + sec_iter);
				if ( error->errcode.gerror == 0 ) break;
			}
			if ( error->errcode.gerror == 0 /* _write_fat_sector returns 1 on success */ )
			{
				show_error ( *error, err_msg_wrtblk, FS.fsname, FS );
				ret_wfs = WFS_BLKWR;
				break;
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( (npasses > 1) && (sig_recvd == 0) )
			{
				error->errcode.gerror = wfs_fat_flush_fs ( FS, error );
			}
		}
		curr_sector++;
		show_progress (PROGRESS_WFS, (curr_sector * 100)/ptffs->total_clusters, &prev_percent);
		pfat->last_free_clus = (pfat->last_free_clus+1) % (ptffs->total_clusters);
		cluster = (cluster+1) % (ptffs->total_clusters);
		if ( cluster == 0 ) break;
	}
	show_progress (PROGRESS_WFS, 100, &prev_percent);
	if ( sig_recvd != 0 ) return WFS_SIGNAL;
	return ret_wfs;
}

/**
 * Recurisvely wipes the deleted files' names in the given directory.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \param dir The directory to browse for deleted files.
 * \param buf The buffer to use.
 */
static errcode_enum WFS_ATTR ((nonnull))
wfs_fat_wipe_unrm_dir (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	wfs_fsid_t FS, error_type * const error, tdir_handle_t dir, unsigned char * buf)
#else
	FS, error, dir, buf)
	wfs_fsid_t FS;
	error_type * const error;
	tdir_handle_t dir;
	unsigned char * buf;
#endif
{
	errcode_enum ret_unrm_dir = WFS_SUCCESS;
	int dir_res = TFFS_OK;
	dirent_t entry;
	unsigned int prev_percent = 0;
	unsigned int curr_direlem = 0;

	if ( (error == NULL) || (FS.fat == NULL) || (dir == NULL) || (buf == NULL) )
	{
		return WFS_BADPARAM;
	}

	/* first recurse into subdirectories: */
	while (sig_recvd == 0)
	{
		dir_res = TFFS_readdir (dir, &entry);
		if ( (dir_res == ERR_TFFS_LAST_DIRENTRY) || (dir_res != TFFS_OK) ) break;
		if ( (strncmp (entry.d_name, ".", 1) == 0)
			|| (strncmp (entry.d_name_short, ".", 1) == 0)
			|| (strncmp (entry.d_name, "..", 2) == 0)
			|| (strncmp (entry.d_name_short, "..", 2) == 0)
		)
		{
			continue;
		}
		if ( entry.dir_attr == DIR_ATTR_DIRECTORY )
		{
			/* recurse into the directory */
			dir_res = TFFS_chdir (FS.fat, entry.d_name_short);
			if ( dir_res != TFFS_OK )
			{
				ret_unrm_dir = WFS_DIRITER;
				continue;
			}
			ret_unrm_dir = wfs_fat_wipe_unrm_dir
				(FS, error, (tdir_handle_t) (((tffs_t *)(FS.fat))->cur_dir), buf);
			TFFS_chdir (FS.fat, "..");
		}
	}

	if ( dir_res != TFFS_OK ) ret_unrm_dir = WFS_DIRITER;
	/* now take care of this directory: */
	while (sig_recvd == 0)
	{
		dir_res = wfs_fat_dirent_find (FS, (tdir_t *)dir, error);
		if ( (dir_res == ERR_TFFS_LAST_DIRENTRY) || (dir_res != TFFS_OK) ) break;
		if ( (dir == (tdir_handle_t) ((tffs_t *)(FS.fat))->root_dir)
			&& (((tffs_t *)(FS.fat))->pbs != NULL) )
		{
			curr_direlem++;
			show_progress (PROGRESS_UNRM,
				curr_direlem/((tffs_t *)(FS.fat))->pbs->root_ent_cnt, &prev_percent);
		}
	}

	return ret_unrm_dir;
}

/**
 * Starts recursive directory search for deleted files and undelete data on the given FAT fs.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_fat_wipe_unrm (
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
	tdir_handle_t dirh;
	unsigned char * buf = NULL;
	unsigned int prev_percent = 0;

	if ( (error == NULL) || (FS.fat == NULL) )
	{
		show_progress (PROGRESS_UNRM, 100, &prev_percent);
		return WFS_BADPARAM;
	}

	/* init dirh */
	dirh = (tdir_handle_t) ((tffs_t *)(FS.fat))->root_dir;
	if ( dirh == NULL )
	{
		show_progress (PROGRESS_UNRM, 100, &prev_percent);
		return WFS_DIRITER;
	}

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	buf = (unsigned char *) malloc ( wfs_fat_get_block_size (FS) );
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
        ret_unrm = wfs_fat_wipe_unrm_dir (FS, error, dirh, buf);
	show_progress (PROGRESS_UNRM, 100, &prev_percent);
	free (buf);

	return ret_unrm;
}

/**
 * Opens a FAT filesystem on the given device.
 * \param devname Device name, like /dev/hdXY
 * \param FS Pointer to where the result will be put.
 * \param whichfs Pointer to an int saying which fs is curently in use.
 * \param data Pointer to fsdata structure containing information which may be needed to
 *	open the filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_fat_open_fs (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	const char * const dev_name, wfs_fsid_t * const FS, CURR_FS * const whichfs,
	const fsdata * const data WFS_ATTR ((unused)), error_type * const error )
#else
	dev_name, FS, whichfs, data WFS_ATTR ((unused)), error )
	const char * const dev_name;
	wfs_fsid_t * const FS;
	CURR_FS * const whichfs;
	const fsdata * const data;
	error_type * const error;
#endif
{
	errcode_enum ret = WFS_SUCCESS;
	char * dev_name_copy;
#ifndef HAVE_MEMCPY
	unsigned int i;
#endif
	int fs_fd;
	ssize_t boot_read;
	union bootsec
	{
		boot_sector_t pbs;
		unsigned char bytes[512];
	} bsec;

	if ((dev_name == NULL) || (FS == NULL) || (whichfs == NULL) || (error == NULL))
	{
		return WFS_BADPARAM;
	}

	*whichfs = CURR_NONE;
	FS->fat = NULL;

#ifdef HAVE_FCNTL_H
	/* first check some basic things, to save resources if different filesystem */
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	fs_fd = open (dev_name, O_RDONLY
# ifdef O_BINARY
		| O_BINARY
# endif
		);
	if ( (fs_fd < 0)
# ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
# endif
	   )
	{
		return WFS_OPENFS;
	}
	boot_read = read (fs_fd, &bsec, 512);
	close (fs_fd);
	if ( boot_read != 512 )
	{
		return WFS_OPENFS;
	}
	if ( (bsec.pbs.byts_per_sec < 512) || (bsec.pbs.sec_per_clus < 1)
		|| ((bsec.pbs.byts_per_sec & 0x1ff) != 0) )
	{
		return WFS_OPENFS;
	}

#endif /* HAVE_FCNTL_H */
	/* malloc a new array for dev_name */
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	dev_name_copy = (char *) malloc ( strlen (dev_name) + 1 );
	if ( dev_name_copy == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		return WFS_MALLOC;
	}

#ifdef HAVE_MEMCPY
	memcpy ( dev_name_copy, dev_name, strlen (dev_name) + 1 );
#else
	for ( i=0; i < strlen (dev_name) + 1; i++ )
	{
		dev_name_copy[i] = dev_name[i];
	}
#endif

	error->errcode.gerror = TFFS_mount ( dev_name_copy, & (FS->fat) );
	free (dev_name_copy);
	if ( error->errcode.gerror != TFFS_OK )
	{
		ret = WFS_OPENFS;
	}
	else
	{
		*whichfs = CURR_FATFS;
		ret = WFS_SUCCESS;
	}
	return ret;
}

/**
 * Checks if the given FAT filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_fat_chk_mount (
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
 * Closes the FAT filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((nonnull))
wfs_fat_close_fs (
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
	errcode_enum ret = WFS_SUCCESS;

	if ( FS.fat == NULL )
	{
		return WFS_BADPARAM;
	}

	if ( error != NULL )
	{
		error->errcode.gerror = TFFS_umount ( FS.fat );
		if ( error->errcode.gerror != TFFS_OK )
		{
			show_error ( *error, err_msg_close, FS.fsname, FS );
			ret = WFS_FSCLOSE;
		}
	}
	else TFFS_umount ( FS.fat );
	FS.fat = NULL;
	return ret;
}

/**
 * Checks if the FAT filesystem has errors.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_fat_check_err (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	const wfs_fsid_t FS WFS_ATTR ((unused)) )
#else
	FS WFS_ATTR ((unused)) )
	const wfs_fsid_t FS;
#endif
{
	/* The filesystem itself does not contain this information. */
	return 0;
}


/**
 * Checks if the FAT filesystem is dirty (has unsaved changes).
 * \param FS The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_fat_is_dirty (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	const wfs_fsid_t FS WFS_ATTR ((unused)) )
#else
	FS WFS_ATTR ((unused)) )
	const wfs_fsid_t FS;
#endif
{
	/*
	 * The filesystem itself does not contain this information.
	 * FS.fat.pcache is our cache, created during mount, so it's not interesting.
	 */
	return 0;
}

/**
 * Flushes the FAT filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((nonnull))
wfs_fat_flush_fs (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
	wfs_fsid_t FS
# if (defined __STRICT_ANSI__) || (!defined HAVE_UNISTD_H) || (!defined HAVE_FSYNC)
		WFS_ATTR ((unused))
# endif
	, error_type * const error
# if (defined __STRICT_ANSI__) || (!defined HAVE_UNISTD_H) || (!defined HAVE_FSYNC)	\
	|| (!defined HAVE_ERRNO_H)
		WFS_ATTR ((unused))
# endif
	)
#else
	FS
# if (defined __STRICT_ANSI__) || (!defined HAVE_UNISTD_H) || (!defined HAVE_FSYNC)
		WFS_ATTR ((unused))
# endif
	, error
# if (defined __STRICT_ANSI__) || (!defined HAVE_UNISTD_H) || (!defined HAVE_FSYNC)	\
	|| (!defined HAVE_ERRNO_H)
		WFS_ATTR ((unused))
# endif
	)
	wfs_fsid_t FS;
	error_type * const error;
#endif
{
	errcode_enum ret = WFS_SUCCESS;
#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_FSYNC)
	tdev_t * dev;
#endif

	if (
#if (defined __STRICT_ANSI__) || (!defined HAVE_UNISTD_H) || (!defined HAVE_FSYNC)	\
	|| (!defined HAVE_ERRNO_H)
		(error == NULL) ||
#endif
		(FS.fat == NULL) )
	{
		return WFS_BADPARAM;
	}

#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H)
# if (defined HAVE_FSYNC)
	dev = (tdev_t *) ((tffs_t *)(FS.fat))->hdev;
	if ( dev != NULL )
	{
#  ifdef HAVE_ERRNO_H
		errno = 0;
#  endif
		fsync (dev->fd);
#  ifdef HAVE_ERRNO_H
		if ( errno != 0 )
		{
			if ( error != NULL ) error->errcode.gerror = errno;
			ret = WFS_FLUSHFS;
		}
#  endif
	}
# endif
# if (defined HAVE_SYNC)
	sync ();
# endif
#endif
	return ret;
}
