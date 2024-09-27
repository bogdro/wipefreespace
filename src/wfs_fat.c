/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- FAT12/16/32 file system-specific functions.
 *
 * Copyright (C) 2007-2024 Bogdan Drozdowski, bogdro (at) users.sourceforge.net
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
 *
 * This code uses parts of the Tiny FAT FS library (on LGPL) by knightray@gmail.com.
 */

#include "wfs_cfg.h"

#include <stdio.h>

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
/* make a syntax error, because not all compilers treat #error as an error */
Something wrong. FAT12/16/32 requested, but tffs.h or libtffs missing.
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

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#ifndef O_RDONLY
# define O_RDONLY	0
#endif

#include "wfs_fat.h"
#include "wfs_signal.h"
#include "wfs_util.h"
#include "wfs_wiping.h"
#include "wfs_mount_check.h"

#define WFS_IS_NAME_CURRENT_DIR(x) (((x)[0]) == '.' && ((x)[1]) == '\0')
#define WFS_IS_NAME_PARENT_DIR(x) (((x)[0]) == '.' && ((x)[1]) == '.' && ((x)[2]) == '\0')

#ifdef TEST_COMPILE
# undef WFS_ANSIC
#endif

/*#define WFS_DEBUG 1*/
/* ============================================================= */

#ifdef WFS_WANT_WFS
# ifndef WFS_ANSIC
static unsigned short int _get_fat_entry_len WFS_PARAMS ((const tfat_t * const pfat));
# endif

static unsigned short int
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
_get_fat_entry_len (
# ifdef WFS_ANSIC
	const tfat_t * const pfat)
# else
	pfat)
	const tfat_t * const pfat;
# endif
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

/* ======================================================================== */

# ifndef WFS_ANSIC
static unsigned int _get_fat_entry WFS_PARAMS ((const tfat_t * const pfat, const unsigned int clus));
# endif

static unsigned int
_get_fat_entry (
# ifdef WFS_ANSIC
	const tfat_t * const pfat, const unsigned int clus)
# else
	pfat, clus)
	const tfat_t * const pfat;
	const unsigned int clus;
# endif
{
	tffs_t * ptffs;
	void * pclus;
	unsigned int entry_val = 0x0FFFFFFF;
	unsigned short int fat_entry;

	if ( pfat == NULL )
	{
		return 0;
	}

	if ( (pfat->ptffs == NULL) || (pfat->secbuf == NULL) )
	{
		return 0;
	}
	if ( pfat->ptffs->pbs == NULL )
	{
		return 0;
	}
	ptffs = pfat->ptffs;
	if ( ptffs->pbs->byts_per_sec == 0 )
	{
		return 0;
	}

	pclus = pfat->secbuf +
		((clus * _get_fat_entry_len (pfat)) / 8) % ptffs->pbs->byts_per_sec;

	if (ptffs->fat_type == FT_FAT12)
	{
		fat_entry = *((unsigned short int *)pclus);
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
		entry_val = *((unsigned short int *)pclus);
	}
	else if (ptffs->fat_type == FT_FAT32)
	{
		entry_val = *((unsigned int *)pclus) & 0x0FFFFFFF;
	}

	return entry_val;
}

/* ======================================================================== */

# ifndef WFS_ANSIC
static int _read_fat_sector WFS_PARAMS ((tfat_t * pfat, int fat_sec));
# endif

static int
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
_read_fat_sector (
# ifdef WFS_ANSIC
	tfat_t * pfat, int fat_sec)
# else
	pfat, fat_sec)
	tfat_t * pfat;
	int fat_sec;
# endif
{
	tffs_t * ptffs;

	if ( pfat == NULL )
	{
		return FALSE;
	}
	if ( pfat->ptffs == NULL )
	{
		return FALSE;
	}

	ptffs = pfat->ptffs;
	if ( (ptffs->hdev == NULL) || (pfat->secbuf == NULL) )
	{
		return FALSE;
	}
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
	pfat->cur_fat_sec = (uint32)fat_sec;
	return TRUE;
}

/* ======================================================================== */

# ifndef WFS_ANSIC
static int _write_fat_sector WFS_PARAMS ((tfat_t * pfat, int fat_sec));
# endif

static int
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
_write_fat_sector (
# ifdef WFS_ANSIC
	tfat_t * pfat, int fat_sec)
# else
	pfat, fat_sec)
	tfat_t * pfat;
	int fat_sec;
# endif
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
	if ( (ptffs->hdev == NULL) || (pfat->secbuf == NULL) )
	{
		return 0;
	}
	if ( HAI_writesector (ptffs->hdev, fat_sec, pfat->secbuf) != HAI_OK )
	{
		return FALSE;
	}

	if ( (ptffs->fat_type == FT_FAT12) && (ptffs->pbs != NULL) )
	{
		if ( HAI_writesector (ptffs->hdev, fat_sec + 1,
			pfat->secbuf + ptffs->pbs->byts_per_sec) != HAI_OK )
		{
			return FALSE;
		}
	}
	return TRUE;
}

/* ======================================================================== */

# ifndef WFS_ANSIC
static int _is_entry_free WFS_PARAMS ((const tfat_t * const pfat, const unsigned int entry_val));
# endif

static int
_is_entry_free (
# ifdef WFS_ANSIC
	const tfat_t * const pfat, const unsigned int entry_val)
# else
	pfat, entry_val)
	const tfat_t * const pfat;
	const unsigned int entry_val;
# endif
{
	if ( pfat == NULL )
	{
		return 0;
	}

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

/* ======================================================================== */

# ifndef WFS_ANSIC
static int _clus2fatsec WFS_PARAMS ((tfat_t * pfat, unsigned int clus));
# endif

static int
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
_clus2fatsec (
# ifdef WFS_ANSIC
	tfat_t * pfat, unsigned int clus)
# else
	pfat, clus)
	tfat_t * pfat;
	unsigned int clus;
# endif
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
	if ( pfat->ptffs->pbs->byts_per_sec == 0 )
	{
		return 0;
	}

	return (int)(pfat->ptffs->sec_fat + ((clus * _get_fat_entry_len (pfat)) / 8)
		/ pfat->ptffs->pbs->byts_per_sec);
}

/* ======================================================================== */

# ifndef WFS_ANSIC
static int _lookup_free_clus WFS_PARAMS ((tfat_t * pfat, unsigned int * pfree_clus));
# endif

static int
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
_lookup_free_clus (
# ifdef WFS_ANSIC
	tfat_t * pfat, unsigned int * pfree_clus)
# else
	pfat, pfree_clus)
	tfat_t * pfat;
	uint32 * pfree_clus;
# endif
{
	tffs_t * ptffs;
	unsigned int cur_clus;
	int ret;

	if ( (pfat == NULL) || (pfree_clus == NULL) )
	{
		return 0;
	}

	if ( pfat->ptffs == NULL )
	{
		return 0;
	}

	ptffs = pfat->ptffs;
	ret = FAT_OK;
	cur_clus = pfat->last_free_clus;
	if (_read_fat_sector (pfat, _clus2fatsec (pfat, pfat->last_free_clus)) == FALSE)
	{
		return ERR_FAT_DEVICE_FAIL;
	}

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
#endif /* WFS_WANT_WFS */

/* ======================================================================== */

#ifdef WFS_WANT_PART
# ifndef WFS_ANSIC
static void _file_seek WFS_PARAMS ((tfile_t * pfile, int offset));
# endif

static void
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
_file_seek (
# ifdef WFS_ANSIC
	tfile_t * pfile, int offset)
# else
	pfile, offset)
	tfile_t * pfile;
	int offset;
# endif
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
	if ( pfile->ptffs->pbs->byts_per_sec == 0 )
	{
		return;
	}
	if ( cur_offset - pfile->ptffs->pbs->byts_per_sec <= 0 )
	{
		pfile->cur_sec_offset = (unsigned int)cur_offset;
		return;
	}

	while ( (cur_offset - pfile->ptffs->pbs->byts_per_sec > 0) &&
		(fat_get_next_sec (pfile->ptffs->pfat, &pfile->cur_clus, &pfile->cur_sec) != 0)
		&& (sig_recvd == 0) )
	{
		cur_offset -= pfile->ptffs->pbs->byts_per_sec;
	}
	pfile->cur_sec_offset = (unsigned int)cur_offset;
}
#endif /* WFS_WANT_PART */

/* ======================================================================== */

#ifdef WFS_WANT_UNRM
# ifndef WFS_ANSIC
static int _get_dirent WFS_PARAMS ((tdir_t * pdir, dir_entry_t * pdirent));
# endif

static int
_get_dirent (
# ifdef WFS_ANSIC
	tdir_t * pdir, dir_entry_t * pdirent)
# else
	pdir, pdirent)
	tdir_t * pdir;
	dir_entry_t * pdirent;
# endif
{
	int ret = DIRENTRY_OK;

	if ( (pdir == NULL) || (pdirent == NULL) )
	{
		return ERR_DIRENTRY_NOMORE_ENTRY;
	}
	if ( (pdir->ptffs == NULL) || (pdir->secbuf == NULL) )
	{
		return ERR_DIRENTRY_NOMORE_ENTRY;
	}
	if ( pdir->ptffs->pbs == NULL )
	{
		return ERR_DIRENTRY_NOMORE_ENTRY;
	}
	if ( pdir->ptffs->pbs->byts_per_sec == 0 )
	{
		return ERR_DIRENTRY_NOMORE_ENTRY;
	}

	if (pdir->cur_dir_entry < (pdir->ptffs->pbs->byts_per_sec / sizeof (dir_entry_t)))
	{
		WFS_MEMCOPY (pdirent,
			(dir_entry_t *)pdir->secbuf + pdir->cur_dir_entry,
			sizeof (dir_entry_t));
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
				WFS_MEMCOPY (pdirent,
					(dir_entry_t *)pdir->secbuf + pdir->cur_dir_entry,
					sizeof (dir_entry_t));
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

/* ======================================================================== */

# ifndef WFS_ANSIC
static int wfs_fat_dirent_find WFS_PARAMS ((const wfs_fsid_t wfs_fs, tdir_t * pdir));
# endif

static int
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_fat_dirent_find (
# ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs, tdir_t * pdir)
# else
	wfs_fs, pdir)
	const wfs_fsid_t wfs_fs;
	tdir_t * pdir;
# endif
{
	int ret;
	dir_entry_t dirent;
	unsigned long int j;
	int selected[WFS_NPAT] = {0};
	wfs_errcode_t error = 0;
	tffs_handle_t fat;
	wfs_errcode_t * error_ret;
	unsigned char * fname;

	fat = (tffs_handle_t) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( (pdir == NULL) || (fat == NULL) )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return ERR_DIRENTRY_NOT_FOUND;
	}
	if ( pdir->secbuf == NULL )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return ERR_DIRENTRY_NOT_FOUND;
	}

	pdir->cur_clus = pdir->start_clus;
	pdir->cur_sec = 0;
	pdir->cur_dir_entry = 0;
#ifdef WFS_DEBUG
	printf("wfs_fat_dirent_find: read sector\n");
	fflush(stdout);
#endif
	if (dir_read_sector (pdir) != DIR_OK)
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return ERR_DIRENTRY_NOT_FOUND;
	}

	ret = DIRENTRY_OK;
	while (sig_recvd == 0)
	{
#ifdef WFS_DEBUG
		printf("wfs_fat_dirent_find: get dir entry\n");
		fflush(stdout);
#endif
		ret = _get_dirent (pdir, &dirent);
#ifdef WFS_DEBUG
		printf("wfs_fat_dirent_find: get dir entry done, result=%d, should be %d\n", ret, DIRENTRY_OK);
		fflush(stdout);
#endif
		if (ret == DIRENTRY_OK)
		{
#ifdef WFS_DEBUG
			printf("wfs_fat_dirent_find: got dir entry name: '%s', first byte=0x%x\n",
				dirent.dir_name, dirent.dir_name[0]);
			fflush(stdout);
#endif
			if (dirent.dir_name[0] == 0x00)
			{
				ret = ERR_DIRENTRY_NOT_FOUND;
				break;
			}
			else if (dirent.dir_name[0] == 0xE5)
			{
				/* Pointer to the filename. Skip the first byte
				- it can't be 0, because that's the end-of-dir marker */
				fname = (unsigned char *)
					((dir_entry_t *)pdir->secbuf
					+ pdir->cur_dir_entry - 1) + 1;
#ifdef WFS_DEBUG
				printf("wfs_fat_dirent_find: found deleted entry with name '%s'\n",
					fname);
				fflush(stdout);
#endif
				/* wipe the name here */
				for ( j = 0; (j < wfs_fs.npasses) && (sig_recvd == 0); j++ )
				{
					if ( (dirent.dir_attr & ATTR_LONG_NAME) == ATTR_LONG_NAME )
					{
#ifdef WFS_DEBUG
						printf("wfs_fat_dirent_find: deleted entry has long name\n");
						fflush(stdout);
#endif
						wfs_fill_buffer ( j, fname,
							13 /*dirent.h->long_dir_entry_t*/
							/* 2 / *sizeof UTF-16 character */
							-1 /* the first marker byte */,
							selected, wfs_fs );
					}
					else
					{
#ifdef WFS_DEBUG
						printf("wfs_fat_dirent_find: deleted entry has short name\n");
						fflush(stdout);
#endif
						wfs_fill_buffer ( j, fname,
							sizeof (dirent.dir_name) - 1 /* the first marker byte */,
							selected, wfs_fs );
					}
					if ( sig_recvd != 0 )
					{
						break;
					}
					/* write the wiped name: */
#ifdef WFS_DEBUG
					printf("wfs_fat_dirent_find: writing new sector contents\n");
					fflush(stdout);
#endif
					error = dir_write_sector (pdir);
#ifdef WFS_DEBUG
					printf("wfs_fat_dirent_find: writing new sector contents, result=%d, should be %d\n",
						error, DIR_OK);
					fflush(stdout);
#endif
					if ( error != DIR_OK )
					{
						break;
					}
					/* Flush after each writing, if more than 1 overwriting
					   needs to be done. Allow I/O bufferring (efficiency),
					   if just one pass is needed. */
					if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
					{
						error = wfs_fat_flush_fs (wfs_fs);
					}
				}
				if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
				{
					/* last pass with zeros: */
					if ( (dirent.dir_attr & ATTR_LONG_NAME) == ATTR_LONG_NAME )
					{
#ifdef WFS_DEBUG
						printf("wfs_fat_dirent_find: wiping long name with zeros\n");
						fflush(stdout);
#endif
						WFS_MEMSET (fname,
							'\0', 13 /*dirent.h->long_dir_entry_t*/
								/* 2 / *sizeof UTF-16 character */
								-1 /* the first marker byte */
								);
					}
					else
					{
#ifdef WFS_DEBUG
						printf("wfs_fat_dirent_find: wiping short name with zeros\n");
						fflush(stdout);
#endif
						WFS_MEMSET (fname, '\0', sizeof (dirent.dir_name) - 1);
					}
					if ( sig_recvd != 0 )
					{
						break;
					}
					/* write the wiped name: */
#ifdef WFS_DEBUG
					printf("wfs_fat_dirent_find: writing new sector contents (2)\n");
					fflush(stdout);
#endif
					error = dir_write_sector (pdir);
#ifdef WFS_DEBUG
					printf("wfs_fat_dirent_find: writing new sector contents (2), result=%d, should be %d\n",
						error, DIR_OK);
					fflush(stdout);
#endif
					if ( error != DIR_OK )
					{
						break;
					}
					/* No need to flush the last writing of a given block. *
					if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
					{
						error = wfs_fat_flush_fs (wfs_fs);
					} */
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
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
#ifdef WFS_DEBUG
	printf("wfs_fat_dirent_find: return %d\n", ret);
	fflush(stdout);
#endif
	return ret;
}
#endif /* WFS_WANT_UNRM */

/* ======================================================================== */

#ifndef WFS_ANSIC
static size_t GCC_WARN_UNUSED_RESULT wfs_fat_get_block_size WFS_PARAMS ((const wfs_fsid_t wfs_fs));
#endif

/**
 * Returns the buffer size needed to work on the smallest physical unit on a FAT filesystem.
 * \param wfs_fs The filesystem.
 * \return Block size on the filesystem.
 */
static size_t GCC_WARN_UNUSED_RESULT
wfs_fat_get_block_size (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs )
#else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
#endif
{
	tffs_handle_t fat;

	fat = (tffs_handle_t) wfs_fs.fs_backend;
	if ( fat == NULL )
	{
		return 512;
	}
	if ( ((tffs_t *)fat)->pbs == NULL )
	{
		return 512;
	}
	/* this is required, because space for files is allocated in clusters, not in sectors */
	return (size_t)(((tffs_t *)fat)->pbs->byts_per_sec
		* ((tffs_t *)fat)->pbs->sec_per_clus);
}

/* ======================================================================== */

#ifdef WFS_WANT_PART
# ifndef WFS_ANSIC
static wfs_errcode_t wfs_fat_wipe_file_tail WFS_PARAMS ((wfs_fsid_t wfs_fs,
	tfile_handle_t file, unsigned char * buf));
# endif

/**
 * Wipes the free space after the given file's data.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \param file The file to wipe data after.
 * \param buf The buffer to use.
 */
static wfs_errcode_t
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_fat_wipe_file_tail (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs, tfile_handle_t file, unsigned char * buf)
# else
	wfs_fs, file, buf)
	wfs_fsid_t wfs_fs;
	tfile_handle_t file;
	unsigned char * buf;
# endif
{
	unsigned long int j;
	int selected[WFS_NPAT] = {0};
	tfile_t * fh = (tfile_t *) file;
	unsigned int file_len;
	size_t bufsize;
	int written;
	wfs_errcode_t ret_tail = WFS_SUCCESS;
	wfs_errcode_t error = 0;
	tffs_handle_t fat;
	wfs_errcode_t * error_ret;
	size_t fs_block_size;

	fat = (tffs_handle_t) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;

	if ( (fat == NULL) || (file == NULL) || (buf == NULL) )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}

#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_file_tail: get file size\n");
	fflush(stdout);
#endif
	file_len = dirent_get_file_size (fh->pdir_entry);
#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_file_tail: got file size: %u\n", file_len);
	fflush(stdout);
#endif
	if ( (int)file_len <= 0 /*|| (file_len >= (unsigned int)0x80000000)*/ )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_SUCCESS;
	}

	fs_block_size = wfs_fat_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	if ( file_len % fs_block_size == 0 )
	{
		/* file fills the whole block - nothing to do */
		return WFS_SUCCESS;
	}
	bufsize = fs_block_size -
		(file_len % fs_block_size);
#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_file_tail: size to wipe: %lu\n", bufsize);
	fflush(stdout);
#endif
	for ( j = 0; (j < wfs_fs.npasses) && (sig_recvd == 0); j++ )
	{
		wfs_fill_buffer ( j, buf, bufsize, selected, wfs_fs );
		if ( sig_recvd != 0 )
		{
			ret_tail = WFS_SIGNAL;
			break;
		}
		/* wipe the space after the file */
#ifdef WFS_DEBUG
		printf("wfs_fat_wipe_file_tail: seek to size\n");
		fflush(stdout);
#endif
		_file_seek (fh, (int)file_len);
#ifdef WFS_DEBUG
		printf("wfs_fat_wipe_file_tail: seek to size done. writing\n");
		fflush(stdout);
#endif
		written = TFFS_fwrite (file, (uint32)(bufsize & 0x0FFFFFFFF), buf);
#ifdef WFS_DEBUG
		printf("wfs_fat_wipe_file_tail: writing done, size: %d\n", written);
		fflush(stdout);
#endif
		if ( written != (int)bufsize )
		{
			ret_tail = WFS_BLKWR;
			break;
		}
		/* workaround a bug in tffs? */
		if ( written > 0 )
		{
			dirent_set_file_size (fh->pdir_entry, file_len);
			fh->file_size -= (uint32)written;
		}
		/* Flush after each writing, if more than 1 overwriting needs to be done.
		Allow I/O bufferring (efficiency), if just one pass is needed. */
		if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
		{
			error = wfs_fat_flush_fs (wfs_fs);
		}
	}
#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_file_tail: marker 1\n");
	fflush(stdout);
#endif
	if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
	{
		/* last pass with zeros: */
		WFS_MEMSET (buf, 0, bufsize);
		if ( sig_recvd == 0 )
		{
			/* wipe the space after the file */
			_file_seek (fh, (int)file_len);
			written = TFFS_fwrite (file, (uint32)(bufsize & 0x0FFFFFFFF), buf);
			if ( written != (int)bufsize )
			{
				ret_tail = WFS_BLKWR;
			}
			/* workaround a bug in tffs? */
			if ( written > 0 )
			{
				dirent_set_file_size (fh->pdir_entry, file_len);
				fh->file_size -= (uint32)written;
			}
			/* No need to flush the last writing of a given block. *
			if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
			{
				error = wfs_fat_flush_fs (wfs_fs);
			}*/
		}
	}
#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_file_tail: restore file size\n");
	fflush(stdout);
#endif
	/* restore file's original size */
	dirent_set_file_size (fh->pdir_entry, file_len);
#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_file_tail: restore file size done\n");
	fflush(stdout);
#endif

	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	if ( sig_recvd != 0 )
	{
		return WFS_SIGNAL;
	}
#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_file_tail: return %d\n", ret_tail);
	fflush(stdout);
#endif
	return ret_tail;
}

/* ======================================================================== */

# ifndef WFS_ANSIC
static wfs_errcode_t wfs_fat_wipe_file_tails_in_dir WFS_PARAMS ((wfs_fsid_t wfs_fs,
	byte dirname[], unsigned char * buf));
# endif

/**
 * Recurisvely wipes the free space after the files in the given directory.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \param dir The directory to browse for files.
 * \param buf The buffer to use.
 */
static wfs_errcode_t
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_fat_wipe_file_tails_in_dir (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs, byte dirname[], unsigned char * buf)
# else
	wfs_fs, dirname, buf)
	wfs_fsid_t wfs_fs;
	byte dirname[];
	unsigned char * buf;
# endif
{
	int dir_res = TFFS_OK;
	wfs_errcode_t ret_part_dir = WFS_SUCCESS;
	dirent_t entry;
	tfile_handle_t fh;
	unsigned int prev_percent = 0;
	unsigned int curr_direlem = 0;
	wfs_errcode_t error = 0;
	tffs_handle_t fat;
	wfs_errcode_t * error_ret;
	tdir_handle_t dirh;
	byte wfs_fat_parent_dir[] = ".."; /* use a local copy, even if constant */
	byte wfs_fat_fopen_mode[] = "a"; /* use a local copy, even if constant */

	fat = (tffs_handle_t) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( (fat == NULL) || (dirname == NULL) || (buf == NULL) )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}

#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_file_tails_in_dir: open directory '%s'\n", dirname);
	fflush(stdout);
#endif
	/* init dirh */
	dir_res = TFFS_opendir (fat, dirname, &dirh);
#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_file_tails_in_dir: open directory '%s': result=%d, should be %d\n",
		dirname, dir_res, TFFS_OK);
	fflush(stdout);
#endif
	/*dirh = (tdir_handle_t) ((tffs_t *)fat)->root_dir;
	if ( dirh == NULL )*/
	if ( dir_res != TFFS_OK )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_DIRITER;
	}

	do
	{
		WFS_MEMSET (&entry, '\0', sizeof (dirent_t));
#ifdef WFS_DEBUG
		printf("wfs_fat_wipe_file_tails_in_dir: read directory\n");
		fflush(stdout);
#endif
		dir_res = TFFS_readdir (dirh, &entry);
#ifdef WFS_DEBUG
		printf("wfs_fat_wipe_file_tails_in_dir: read directory '%s': result=%d, got name '%s'\n",
			dirname, dir_res, entry.d_name);
		fflush(stdout);
#endif
		if ( (dir_res == ERR_TFFS_LAST_DIRENTRY) || (dir_res != TFFS_OK) )
		{
			break;
		}
#ifdef WFS_DEBUG
		printf("wfs_fat_wipe_file_tails_in_dir: marker 1\n");
		fflush(stdout);
#endif
		if ( ((unsigned char)(entry.d_name[0]) == 0xE5)
			|| ((unsigned char)(entry.d_name_short[0]) == 0xE5)
			|| (entry.d_name[0] == 0x2E)
			|| (entry.d_name_short[0] == 0x2E) )
		{
			/* deleted element - don't wipe */
			/* update progress bar */
			if ( (dirh == (tdir_handle_t) ((tffs_t *)fat)->root_dir)
				&& (((tffs_t *)fat)->pbs != NULL) )
			{
				curr_direlem++;
				wfs_show_progress (WFS_PROGRESS_PART,
					(curr_direlem * 100)/((tffs_t *)fat)->pbs->root_ent_cnt,
					&prev_percent);
			}
			continue;
		}

#ifdef WFS_DEBUG
		printf("wfs_fat_wipe_file_tails_in_dir: marker 2\n");
		fflush(stdout);
#endif
		/* skip 'current dir' and 'parent dir' */
		if ( WFS_IS_NAME_PARENT_DIR (entry.d_name)
			|| WFS_IS_NAME_PARENT_DIR (entry.d_name_short)
			|| WFS_IS_NAME_CURRENT_DIR (entry.d_name)
			|| WFS_IS_NAME_CURRENT_DIR (entry.d_name_short)
		)
		{
			continue;
		}

#ifdef WFS_DEBUG
		printf("wfs_fat_wipe_file_tails_in_dir: marker 3\n");
		fflush(stdout);
#endif
		if ( (entry.dir_attr & DIR_ATTR_DIRECTORY) == DIR_ATTR_DIRECTORY )
		{
			/* recurse into THIS directory, so that
			subdirectories can be opened inside the
			called function */
#ifdef WFS_DEBUG
			printf("wfs_fat_wipe_file_tails_in_dir: change to directory '%s'\n", dirname);
			fflush(stdout);
#endif
			dir_res = TFFS_chdir (fat, dirname);
#ifdef WFS_DEBUG
			printf("wfs_fat_wipe_file_tails_in_dir: change to directory '%s': result=%d, should be %d\n",
				dirname, dir_res, TFFS_OK);
			fflush(stdout);
#endif
			if ( dir_res == TFFS_OK )
			{
#ifdef WFS_DEBUG
				printf("wfs_fat_wipe_file_tails_in_dir: descending into directory '%s'\n",
					 entry.d_name);
				fflush(stdout);
#endif
				ret_part_dir = wfs_fat_wipe_file_tails_in_dir
					(wfs_fs, entry.d_name, buf);
#ifdef WFS_DEBUG
				printf("wfs_fat_wipe_file_tails_in_dir: descending into directory '%s': result=%d\n",
					dirname, ret_part_dir);
				fflush(stdout);
#endif
#ifdef WFS_DEBUG
				printf("wfs_fat_wipe_file_tails_in_dir: change back to parent directory\n");
				fflush(stdout);
#endif
				TFFS_chdir (fat, wfs_fat_parent_dir);
#ifdef WFS_DEBUG
				printf("wfs_fat_wipe_file_tails_in_dir: change back to parent directory done\n");
				fflush(stdout);
#endif
			}
			else
			{
				ret_part_dir = WFS_DIRITER;
				error = dir_res;
			}
		}
		else if ( (entry.dir_attr & DIR_ATTR_VOLUME_ID) != DIR_ATTR_VOLUME_ID )
		{
#ifdef WFS_DEBUG
			printf("wfs_fat_wipe_file_tails_in_dir: opening file to wipe: '%s'\n", entry.d_name);
			fflush(stdout);
#endif
			/* wipe this file's last sector's free space */
			dir_res = TFFS_fopen (fat, entry.d_name,
				wfs_fat_fopen_mode, &fh);
#ifdef WFS_DEBUG
			printf("wfs_fat_wipe_file_tails_in_dir: opening file '%s' result=%d\n",
				entry.d_name, dir_res);
			fflush(stdout);
#endif
			if ( dir_res == TFFS_OK )
			{
#ifdef WFS_DEBUG
				printf("wfs_fat_wipe_file_tails_in_dir: starting to wipe file '%s'\n",
					entry.d_name);
				fflush(stdout);
#endif

				wfs_fat_wipe_file_tail (wfs_fs, fh, buf);
#ifdef WFS_DEBUG
				printf("wfs_fat_wipe_file_tails_in_dir: wiping file '%s' finished\n",
					entry.d_name);
				fflush(stdout);
#endif
#ifdef WFS_DEBUG
				printf("wfs_fat_wipe_file_tails_in_dir: closing file '%s'\n",
					entry.d_name);
				fflush(stdout);
#endif
				TFFS_fclose (fh);
#ifdef WFS_DEBUG
				printf("wfs_fat_wipe_file_tails_in_dir: closing file '%s' done\n",
					entry.d_name);
				fflush(stdout);
#endif
			}
			else
			{
				error = dir_res;
			}
		}
#ifdef WFS_DEBUG
		printf("wfs_fat_wipe_file_tails_in_dir: marker 4\n");
		fflush(stdout);
#endif

		if ( (dirh == (tdir_handle_t) ((tffs_t *)fat)->root_dir)
			&& (((tffs_t *)fat)->pbs != NULL) )
		{
			curr_direlem++;
			wfs_show_progress (WFS_PROGRESS_PART,
				(curr_direlem * 100)/((tffs_t *)fat)->pbs->root_ent_cnt,
				&prev_percent);
		}
	}
	while ( sig_recvd == 0 );
#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_file_tails_in_dir: close directory '%s'\n", dirname);
	fflush(stdout);
#endif
	TFFS_closedir (dirh);
#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_file_tails_in_dir: close directory done\n");
	fflush(stdout);
#endif

	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	if ( (dir_res != TFFS_OK) && (dir_res != ERR_TFFS_LAST_DIRENTRY) )
	{
		ret_part_dir = WFS_DIRITER;
	}

#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_file_tails_in_dir: return %d\n", ret_part_dir);
	fflush(stdout);
#endif
	return ret_part_dir;
}

/* ======================================================================== */

/**
 * Wipes the free space in partially used blocks on the given FAT filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_fat_wipe_part (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_part = WFS_SUCCESS;
	unsigned char * buf = NULL;
	unsigned int prev_percent = 0;
	wfs_errcode_t error = 0;
	wfs_errcode_t * error_ret;
	byte root_dir_name[] = "/";
	size_t fs_block_size;

	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( wfs_fs.fs_backend == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}

	fs_block_size = wfs_fat_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	WFS_SET_ERRNO (0);
	buf = (unsigned char *) malloc ( fs_block_size );
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

#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_part: descend into root directory\n");
	fflush(stdout);
#endif
	ret_part = wfs_fat_wipe_file_tails_in_dir (wfs_fs, root_dir_name, buf);
#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_part: root directory done\n");
	fflush(stdout);
#endif

	wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
	free (buf);

	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return ret_part;
}
#endif /* WFS_WANT_PART */

/* ======================================================================== */

#ifdef WFS_WANT_WFS
/**
 * Wipes the free space on the given FAT filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_fat_wipe_fs (
# ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	unsigned int cluster = 0;
	unsigned int prev_cluster = 0;
	unsigned long int j;
	int selected[WFS_NPAT] = {0};
	tfat_t * pfat;
	tffs_t * ptffs;
	int sec_per_clus = 1;
	unsigned int bytes_per_sector = 512;
	int sec_iter;
	unsigned int prev_percent = 0;
	wfs_errcode_t error = 0;
	tffs_handle_t fat;
	wfs_errcode_t * error_ret;
	size_t fs_block_size;
	int sec_num;

	fat = (tffs_handle_t) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( fat == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}

	fs_block_size = wfs_fat_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	ptffs = (tffs_t *) fat;
	pfat = ptffs->pfat;
	if ( ptffs->total_clusters == 0 )
	{
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
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
	if ( ptffs->pbs != NULL )
	{
		sec_per_clus = ptffs->pbs->sec_per_clus;
		bytes_per_sector = ptffs->pbs->byts_per_sec;
	}
	if ( sec_per_clus == 0 )
	{
		sec_per_clus = 1;
	}
	if ( bytes_per_sector == 0 )
	{
		bytes_per_sector = 512;
	}
	if ( wfs_fs.wipe_mode == WFS_WIPE_MODE_PATTERN )
	{
		for ( j = 0; (j < wfs_fs.npasses) && (sig_recvd == 0); j++ )
		{
			pfat->last_free_clus = 0;
			cluster = 0;
			prev_cluster = 0;
			while (sig_recvd == 0)
			{
				if ( _lookup_free_clus (pfat, &cluster) != FAT_OK )
				{
					break;
				}
				sec_num = (int)clus2sec (ptffs, cluster);
				/* better not wipe anything before the first data sector, even if marked unused */
				if ( (unsigned int)sec_num < ptffs->sec_first_data )
				{
					wfs_show_progress (WFS_PROGRESS_WFS,
						(unsigned int)(((ptffs->total_clusters * j + cluster) * 100)/(ptffs->total_clusters * wfs_fs.npasses)),
						&prev_percent);
					pfat->last_free_clus = (pfat->last_free_clus+1) % (ptffs->total_clusters);
					cluster = (cluster+1) % (ptffs->total_clusters);
					if ( (cluster == 0)
						|| (pfat->last_free_clus == 0) )
					{
						break;
					}
					continue;
				}
				if ( cluster < prev_cluster )
				{
					/* started from the beginning - means all clusters are done */
					break;
				}
				prev_cluster = cluster;
				if ( ptffs->fat_type == FT_FAT12 )
				{
					/* save the sector after the last wiped in a cluster
					(FAT12 reads/writes two at a time): */
					_read_fat_sector (pfat, sec_num + sec_per_clus-1);
				}
				wfs_fill_buffer ( j, pfat->secbuf, bytes_per_sector, selected, wfs_fs );
				if ( sig_recvd != 0 )
				{
					ret_wfs = WFS_SIGNAL;
					break;
				}
				error = 0;
				/* wipe all sectors of cluster 'cluster' */
				for ( sec_iter = 0; sec_iter < sec_per_clus; sec_iter++ )
				{
					if ( wfs_fs.no_wipe_zero_blocks != 0 )
					{
						error = _read_fat_sector (pfat,
							sec_num + sec_iter);
						if ( error == 0 )
						{
							ret_wfs = WFS_BLKRD;
							break;
						}
						if ( wfs_is_block_zero (pfat->secbuf,
							fs_block_size) != 0 )
						{
							/* this block is all-zeros -
							don't wipe, as requested */
							continue;
						}
					}
					error = _write_fat_sector (pfat,
						sec_num + sec_iter);
					if ( error == 0 )
					{
						break;
					}
				}
				if ( error == 0 /* _write_fat_sector returns 1 on success */ )
				{
					ret_wfs = WFS_BLKWR;
					break;
				}
				wfs_show_progress (WFS_PROGRESS_WFS,
					(unsigned int)(((ptffs->total_clusters * j + cluster) * 100)/(ptffs->total_clusters * wfs_fs.npasses)),
					&prev_percent);
				pfat->last_free_clus = (pfat->last_free_clus+1) % (ptffs->total_clusters);
				cluster = (cluster+1) % (ptffs->total_clusters);
				if ( (cluster == 0)
					|| (pfat->last_free_clus == 0) )
				{
					break;
				}
			}
			/* Flush after each writing, if more than 1 overwriting needs to be done.
			Allow I/O bufferring (efficiency), if just one pass is needed. */
			if ( WFS_IS_SYNC_NEEDED_PAT(wfs_fs) )
			{
				error = wfs_fat_flush_fs (wfs_fs);
			}
		}
		if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
		{
			wfs_fat_flush_fs (wfs_fs);
			/* last pass with zeros: */
			pfat->last_free_clus = 0;
			cluster = 0;
			prev_cluster = 0;
			while (sig_recvd == 0)
			{
				if ( _lookup_free_clus (pfat, &cluster) != FAT_OK )
				{
					break;
				}
				sec_num = (int)clus2sec (ptffs, cluster);
				/* better not wipe anything before the first data sector, even if marked unused */
				if ( (unsigned int)sec_num < ptffs->sec_first_data )
				{
					pfat->last_free_clus = (pfat->last_free_clus+1) % (ptffs->total_clusters);
					cluster = (cluster+1) % (ptffs->total_clusters);
					if ( (cluster == 0)
						|| (pfat->last_free_clus == 0) )
					{
						break;
					}
					continue;
				}
				if ( cluster < prev_cluster )
				{
					/* started from the beginning - means all clusters are done */
					break;
				}
				prev_cluster = cluster;
				if ( ptffs->fat_type == FT_FAT12 )
				{
					/* save the sector after the last wiped in a cluster
					(FAT12 reads/writes two at a time): */
					_read_fat_sector (pfat, sec_num + sec_per_clus-1);
				}
				if ( sig_recvd != 0 )
				{
					ret_wfs = WFS_SIGNAL;
					break;
				}
				error = 0;
				/* wipe all sectors of cluster 'cluster' */
				WFS_MEMSET (pfat->secbuf, 0, bytes_per_sector);
				for ( sec_iter = 0; sec_iter < sec_per_clus; sec_iter++ )
				{
					error = _write_fat_sector (pfat,
						sec_num + sec_iter);
					if ( error == 0 )
					{
						break;
					}
				}
				if ( error == 0 /* _write_fat_sector returns 1 on success */ )
				{
					ret_wfs = WFS_BLKWR;
					break;
				}
				pfat->last_free_clus = (pfat->last_free_clus+1) % (ptffs->total_clusters);
				cluster = (cluster+1) % (ptffs->total_clusters);
				if ( (cluster == 0)
					|| (pfat->last_free_clus == 0) )
				{
					break;
				}
			}
			wfs_fat_flush_fs (wfs_fs);
		}
	}
	else /* block-order */
	{
		pfat->last_free_clus = 0;
		cluster = 0;
		prev_cluster = 0;

		while (sig_recvd == 0)
		{
			if ( _lookup_free_clus (pfat, &cluster) != FAT_OK )
			{
				break;
			}
			sec_num = (int)clus2sec (ptffs, cluster);
			/* better not wipe anything before the first data sector, even if marked unused */
			if ( (unsigned int)sec_num < ptffs->sec_first_data )
			{
				wfs_show_progress (WFS_PROGRESS_WFS,
					(cluster * 100)/ptffs->total_clusters,
					&prev_percent);
				pfat->last_free_clus = (pfat->last_free_clus+1) % (ptffs->total_clusters);
				cluster = (cluster+1) % (ptffs->total_clusters);
				if ( (cluster == 0)
					|| (pfat->last_free_clus == 0) )
				{
					break;
				}
				continue;
			}
			if ( cluster < prev_cluster )
			{
				/* started from the beginning - means all clusters are done */
				break;
			}
			prev_cluster = cluster;
			if ( ptffs->fat_type == FT_FAT12 )
			{
				/* save the sector after the last wiped in a cluster
				(FAT12 reads/writes two at a time): */
				_read_fat_sector (pfat, sec_num + sec_per_clus-1);
			}
			for ( j = 0; (j < wfs_fs.npasses) && (sig_recvd == 0); j++ )
			{
				wfs_fill_buffer ( j, pfat->secbuf, bytes_per_sector, selected, wfs_fs );
				if ( sig_recvd != 0 )
				{
					ret_wfs = WFS_SIGNAL;
					break;
				}
				error = 0;
				/* wipe all sectors of cluster 'cluster' */
				for ( sec_iter = 0; sec_iter < sec_per_clus; sec_iter++ )
				{
					if ( wfs_fs.no_wipe_zero_blocks != 0 )
					{
						error = _read_fat_sector (pfat,
							sec_num + sec_iter);
						if ( error == 0 )
						{
							ret_wfs = WFS_BLKRD;
							break;
						}
						if ( wfs_is_block_zero (pfat->secbuf,
							fs_block_size) != 0 )
						{
							/* this block is all-zeros -
							don't wipe, as requested */
							continue;
						}
					}
					error = _write_fat_sector (pfat,
						sec_num + sec_iter);
					if ( error == 0 )
					{
						break;
					}
				}
				if ( error == 0 /* _write_fat_sector returns 1 on success */ )
				{
					ret_wfs = WFS_BLKWR;
					break;
				}
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
				{
					error = wfs_fat_flush_fs (wfs_fs);
				}
			}
			if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
			{
				/* last pass with zeros: */
				error = 0;
				/* wipe all sectors of cluster 'cluster' */
				for ( sec_iter = 0; sec_iter < sec_per_clus; sec_iter++ )
				{
					if ( sig_recvd != 0 )
					{
						ret_wfs = WFS_SIGNAL;
						break;
					}
					if ( wfs_fs.no_wipe_zero_blocks != 0 )
					{
						error = _read_fat_sector (pfat,
							sec_num + sec_iter);
						if ( error == 0 )
						{
							ret_wfs = WFS_BLKRD;
							break;
						}
						if ( wfs_is_block_zero (pfat->secbuf,
							fs_block_size) == 0 )
						{
							/* this block is all-zeros -
							don't wipe, as requested */
							continue;
						}
					}
					WFS_MEMSET (pfat->secbuf, 0, bytes_per_sector);
					error = _write_fat_sector (pfat,
						sec_num + sec_iter);
					if ( error == 0 )
					{
						break;
					}
				}
				if ( error == 0 /* _write_fat_sector returns 1 on success */ )
				{
					ret_wfs = WFS_BLKWR;
					break;
				}
				/* No need to flush the last writing of a given block. *
				if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
				{
					error = wfs_fat_flush_fs (wfs_fs);
				}*/
				if ( sig_recvd != 0 )
				{
					ret_wfs = WFS_SIGNAL;
					break;
				}
			}
			wfs_show_progress (WFS_PROGRESS_WFS,
				(cluster * 100)/ptffs->total_clusters,
				&prev_percent);
			pfat->last_free_clus = (pfat->last_free_clus+1) % (ptffs->total_clusters);
			cluster = (cluster+1) % (ptffs->total_clusters);
			if ( (cluster == 0)
				|| (pfat->last_free_clus == 0) )
			{
				break;
			}
		}
	}
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
# ifndef WFS_ANSIC
static wfs_errcode_t wfs_fat_wipe_unrm_dir WFS_PARAMS ((wfs_fsid_t wfs_fs,
	byte dirname[], unsigned char * buf));
# endif

/**
 * Recurisvely wipes the deleted files' names in the given directory.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \param dir The directory to browse for deleted files.
 * \param buf The buffer to use.
 */
static wfs_errcode_t
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_fat_wipe_unrm_dir (
# ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs, byte dirname[], unsigned char * buf)
# else
	wfs_fs, dirname, buf)
	wfs_fsid_t wfs_fs;
	byte dirname[];
	unsigned char * buf;
# endif
{
	wfs_errcode_t ret_unrm_dir = WFS_SUCCESS;
	int dir_res = TFFS_OK;
	dirent_t entry;
	unsigned int prev_percent = 0;
	unsigned int curr_direlem = 0;
	wfs_errcode_t error = 0;
	tffs_handle_t fat;
	wfs_errcode_t * error_ret;
	tdir_handle_t dirh;
	byte wfs_fat_parent_dir[] = ".."; /* use a local copy, even if constant */

	fat = (tffs_handle_t) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( (fat == NULL) || (dirname == NULL) || (buf == NULL) )
	{
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}

#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_unrm_dir: open directory '%s'\n", dirname);
	fflush(stdout);
#endif
	/* init dirh */
	dir_res = TFFS_opendir (fat, dirname, &dirh);
#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_unrm_dir: open directory '%s': result=%d, should be: %d\n",
		dirname, dir_res, TFFS_OK);
	fflush(stdout);
#endif
	/*dirh = (tdir_handle_t) ((tffs_t *)fat)->root_dir;
	if ( dirh == NULL )*/
	if ( dir_res != TFFS_OK )
	{
		return WFS_DIRITER;
	}

	/* first recurse into subdirectories: */
	while (sig_recvd == 0)
	{
		WFS_MEMSET (&entry, '\0', sizeof (dirent_t));
#ifdef WFS_DEBUG
		printf("wfs_fat_wipe_unrm_dir: read directory '%s'\n", dirname);
		fflush(stdout);
#endif
		dir_res = TFFS_readdir (dirh, &entry);
#ifdef WFS_DEBUG
		printf("wfs_fat_wipe_unrm_dir: read directory '%s': result=%d, got name '%s'\n",
			dirname, dir_res, entry.d_name);
		fflush(stdout);
#endif
		if ( (dir_res == ERR_TFFS_LAST_DIRENTRY) || (dir_res != TFFS_OK) )
		{
			break;
		}
		if ( WFS_IS_NAME_PARENT_DIR (entry.d_name)
			|| WFS_IS_NAME_PARENT_DIR (entry.d_name_short)
			|| WFS_IS_NAME_CURRENT_DIR (entry.d_name)
			|| WFS_IS_NAME_CURRENT_DIR (entry.d_name_short)
		)
		{
			continue;
		}
		if ( (entry.dir_attr & DIR_ATTR_DIRECTORY) == DIR_ATTR_DIRECTORY )
		{
			/* recurse into THIS directory, so that
			subdirectories can be opened inside the
			called function */
#ifdef WFS_DEBUG
			printf("wfs_fat_wipe_unrm_dir: change to directory '%s'\n", dirname);
			fflush(stdout);
#endif
			dir_res = TFFS_chdir (fat, dirname);
#ifdef WFS_DEBUG
			printf("wfs_fat_wipe_unrm_dir: change to directory '%s': result=%d, should be %d\n",
				dirname, dir_res, TFFS_OK);
			fflush(stdout);
#endif
			if ( dir_res != TFFS_OK )
			{
				ret_unrm_dir = WFS_DIRITER;
				continue;
			}
#ifdef WFS_DEBUG
			printf("wfs_fat_wipe_unrm_dir: descending into directory '%s'\n",
				 entry.d_name);
			fflush(stdout);
#endif
			ret_unrm_dir = wfs_fat_wipe_unrm_dir
				(wfs_fs, entry.d_name, buf);
#ifdef WFS_DEBUG
			printf("wfs_fat_wipe_unrm_dir: descending into directory '%s': result=%d\n",
				dirname, ret_unrm_dir);
			fflush(stdout);
#endif
#ifdef WFS_DEBUG
			printf("wfs_fat_wipe_unrm_dir: change back to parent directory\n");
			fflush(stdout);
#endif
			TFFS_chdir (fat, wfs_fat_parent_dir);
#ifdef WFS_DEBUG
			printf("wfs_fat_wipe_unrm_dir: change back to parent directory done\n");
			fflush(stdout);
#endif
			if ( (dirh == (tdir_handle_t) ((tffs_t *)fat)->root_dir)
				&& (((tffs_t *)fat)->pbs != NULL) )
			{
				curr_direlem++;
				wfs_show_progress (WFS_PROGRESS_UNRM,
					(curr_direlem * 100)/((tffs_t *)fat)->pbs->root_ent_cnt,
					&prev_percent);
			}
		}
	}

	if ( (dir_res != TFFS_OK) && (dir_res != ERR_TFFS_LAST_DIRENTRY) )
	{
		ret_unrm_dir = WFS_DIRITER;
	}
#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_unrm_dir: process this directory\n");
	fflush(stdout);
#endif
	/* now take care of this directory: */
	while (sig_recvd == 0)
	{
#ifdef WFS_DEBUG
		printf("wfs_fat_wipe_unrm_dir: find & wipe next entry\n");
		fflush(stdout);
#endif
		dir_res = wfs_fat_dirent_find (wfs_fs, (tdir_t *)dirh);
#ifdef WFS_DEBUG
		printf("wfs_fat_wipe_unrm_dir: find & wipe next entry: result=%d\n", dir_res);
		fflush(stdout);
#endif
		if ( (dir_res == ERR_TFFS_LAST_DIRENTRY) || (dir_res != TFFS_OK) )
		{
			break;
		}
		if ( (dirh == (tdir_handle_t) ((tffs_t *)fat)->root_dir)
			&& (((tffs_t *)fat)->pbs != NULL) )
		{
			curr_direlem++;
			wfs_show_progress (WFS_PROGRESS_UNRM,
				(curr_direlem * 100)/((tffs_t *)fat)->pbs->root_ent_cnt,
				&prev_percent);
		}
	}
#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_unrm_dir: close this directory\n");
	fflush(stdout);
#endif
	TFFS_closedir (dirh);
#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_unrm_dir: close this directory done\n");
	fflush(stdout);
#endif

	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_unrm_dir: return %d\n", ret_unrm_dir);
	fflush(stdout);
#endif
	return ret_unrm_dir;
}

/* ======================================================================== */

/**
 * Starts recursive directory search for deleted files and undelete data on the given FAT fs.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_fat_wipe_unrm (
# ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
# endif
{
	wfs_errcode_t ret_unrm = WFS_SUCCESS;
	unsigned char * buf = NULL;
	unsigned int prev_percent = 0;
	wfs_errcode_t error = 0;
	wfs_errcode_t * error_ret;
	byte root_dir_name[] = "/";
	size_t fs_block_size;

	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( wfs_fs.fs_backend == NULL )
	{
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_BADPARAM;
	}

	fs_block_size = wfs_fat_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	WFS_SET_ERRNO (0);
	buf = (unsigned char *) malloc (fs_block_size);
	if ( buf == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}
#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_unrm: descend into root directory\n");
	fflush(stdout);
#endif
        ret_unrm = wfs_fat_wipe_unrm_dir (wfs_fs, root_dir_name, buf);
#ifdef WFS_DEBUG
	printf("wfs_fat_wipe_unrm: root directory done\n");
	fflush(stdout);
#endif
	wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
	free (buf);

	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return ret_unrm;
}
#endif /* WFS_WANT_UNRM */

/* ======================================================================== */

/**
 * Opens a FAT filesystem on the given device.
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
wfs_fat_open_fs (
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
	char * dev_name_copy;
	int fs_fd;
	ssize_t boot_read;
	union bootsec
	{
		boot_sector_t pbs;
		unsigned char bytes[512]; /* to make sure we have at leat 512 bytes in "union bootsec" */
	} bsec;
	wfs_errcode_t error = 0;
	tffs_handle_t fat;
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
			*error_ret = WFS_BADPARAM;
		}
		return WFS_BADPARAM;
	}

	wfs_fs->whichfs = WFS_CURR_FS_NONE;
	wfs_fs->fs_backend = NULL;

#ifdef HAVE_FCNTL_H
	/* first check some basic things, to save resources if different filesystem */
	WFS_SET_ERRNO (0);
	fs_fd = open (wfs_fs->fsname, O_RDONLY
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
		error = WFS_GET_ERRNO_OR_DEFAULT (1L);	/* EPERM */
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_OPENFS;
	}
	boot_read = read (fs_fd, &bsec, 512);
	close (fs_fd);
	if ( boot_read != 512 )
	{
		if ( error_ret != NULL )
		{
			*error_ret = WFS_OPENFS;
		}
		return WFS_OPENFS;
	}
	if ( (bsec.pbs.byts_per_sec < 512) || (bsec.pbs.sec_per_clus < 1)
		|| ((bsec.pbs.byts_per_sec & 0x1ff) != 0) )
	{
		if ( error_ret != NULL )
		{
			*error_ret = WFS_OPENFS;
		}
		return WFS_OPENFS;
	}

#endif /* HAVE_FCNTL_H */
	/* malloc a new array for dev_name */
	WFS_SET_ERRNO (0);
	dev_name_copy = WFS_STRDUP (wfs_fs->fsname);
	if ( dev_name_copy == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	error = TFFS_mount (dev_name_copy, &fat);
	free (dev_name_copy);
	if ( error != TFFS_OK )
	{
		ret = WFS_OPENFS;
	}
	else
	{
		wfs_fs->whichfs = WFS_CURR_FS_FATFS;
		wfs_fs->fs_backend = fat;
		ret = WFS_SUCCESS;
	}
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	return ret;
}

/* ======================================================================== */

/**
 * Checks if the given FAT filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_fat_chk_mount (
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
 * Closes the FAT filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_fat_close_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
	int wfs_err;
	tffs_handle_t fat;
	wfs_errcode_t * error_ret;

	fat = (tffs_handle_t) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( fat == NULL )
	{
		return WFS_BADPARAM;
	}

	wfs_err = TFFS_umount (fat);
	if ( wfs_err != TFFS_OK )
	{
		ret = WFS_FSCLOSE;
		if ( error_ret != NULL )
		{
			*error_ret = (wfs_errcode_t)wfs_err;
		}
	}
	return ret;
}

/* ======================================================================== */

/**
 * Checks if the FAT filesystem has errors.
 * \param wfs_fs The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_fat_check_err (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs WFS_ATTR ((unused)) )
#else
	wfs_fs )
	const wfs_fsid_t wfs_fs WFS_ATTR ((unused));
#endif
{
	/* The filesystem itself does not contain this information. */
	return 0;
}


/* ======================================================================== */

/**
 * Checks if the FAT filesystem is dirty (has unsaved changes).
 * \param wfs_fs The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_fat_is_dirty (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs WFS_ATTR ((unused)) )
#else
	wfs_fs )
	const wfs_fsid_t wfs_fs WFS_ATTR ((unused));
#endif
{
	/*
	 * The filesystem itself does not contain this information.
	 * fat.pcache is our cache, created during mount, so it's not interesting.
	 */
	return 0;
}

/* ======================================================================== */

#if (defined __STRICT_ANSI__) || (!defined HAVE_UNISTD_H) || (!defined HAVE_FSYNC)
# define WFS_ONLY_WITH_FSYNC WFS_ATTR ((unused))
#else
# define WFS_ONLY_WITH_FSYNC
#endif

/**
 * Flushes the FAT filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_fat_flush_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs WFS_ONLY_WITH_FSYNC)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs WFS_ONLY_WITH_FSYNC;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;
#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_FSYNC)
	tdev_t * dev;
#endif
	tffs_handle_t fat;
	wfs_errcode_t error = 0;
	wfs_errcode_t * error_ret;

	fat = (tffs_handle_t) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( fat == NULL )
	{
		return WFS_BADPARAM;
	}

#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H)
# if (defined HAVE_FSYNC)
	dev = (tdev_t *) ((tffs_t *)fat)->hdev;
	if ( dev != NULL )
	{
		WFS_SET_ERRNO (0);
		fsync (dev->fd);
#  ifdef HAVE_ERRNO_H
		if ( errno != 0 )
		{
			error = errno;
			ret = WFS_FLUSHFS;
		}
#  endif
	}
# endif
# if (defined HAVE_SYNC)
	sync ();
# endif
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
void wfs_fat_print_version (WFS_VOID)
{
	printf ( "FAT (TFFS): <?>\n");
}

/* ======================================================================== */

/**
 * Get the preferred size of the error variable.
 * \return the preferred size of the error variable.
 */
size_t wfs_fat_get_err_size (WFS_VOID)
{
	return sizeof (wfs_errcode_t);
}

/* ======================================================================== */

/**
 * Initialize the library.
 */
void wfs_fat_init (WFS_VOID)
{
}

/* ======================================================================== */

/**
 * De-initialize the library.
 */
void wfs_fat_deinit (WFS_VOID)
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
wfs_fat_show_error (
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
