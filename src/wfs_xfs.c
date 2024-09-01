/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- XFS file system-specific functions.
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
 */

#include "wfs_cfg.h"

#define _FILE_OFFSET_BITS 64
#define _LARGEFILE64_SOURCE 1
/* used for fsync(), but this makes BSD's select() impossible. Same for _POSIX_SOURCE - don't define. */
/*#define _XOPEN_SOURCE*/

#include <stdio.h>	/* sscanf() */

#if (!defined __USE_FILE_OFFSET64) && (!defined __USE_LARGEFILE64)
# ifndef lseek64
#  define lseek64	lseek
# endif
# ifndef open64
#  define open64	open
# endif
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

/*
#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif
*/

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>	/* S_ISREG */
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>	/* probably needed before anything with "select" */
#endif

/* time headers for select() (the old way) */
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#ifdef HAVE_TIME_H
# include <time.h>
#endif

/* select () - the new way */
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#ifdef HAVE_STRING_H
# if ((!defined STDC_HEADERS) || (!STDC_HEADERS)) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>	/* strncpy() */
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* close(), open(), sync(), select() (the old way) */
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifdef HAVE_LIMITS_H
# include <limits.h>	/* PIPE_BUF */
#endif

#include "wipefreespace.h"
#include "wfs_xfs.h"
#include "wfs_signal.h"
#include "wfs_util.h"
#include "wfs_wiping.h"

#define PIPE_R 0
#define PIPE_W 1
#define WFS_XFSBUFSIZE 240

#ifndef O_RDONLY
# define O_RDONLY	0
#endif
#ifndef O_WRONLY
# define O_WRONLY 	1
#endif
#ifndef O_EXCL
# define O_EXCL		0200
#endif

#ifndef PIPE_BUF
# define PIPE_BUF	4096
#endif

#define WFS_XFS_MAX_SELECT_FAILS 5
#define WFS_XFS_MAX_SELECT_SECONDS 10

/*#define XFS_HAS_SHARED_BLOCKS 1 */

#if (((defined HAVE_SYS_SELECT_H) || (((defined TIME_WITH_SYS_TIME)	\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))		\
	&& (defined HAVE_UNISTD_H)))				\
	&& (defined HAVE_SELECT))
# define WFS_XFS_HAVE_SELECT 1
#else
# undef WFS_XFS_HAVE_SELECT
#endif

struct wfs_xfs
{
	/* size of 1 block is from sector size to 65536. Max is system page size */
	size_t wfs_xfs_blocksize;
	unsigned long long int wfs_xfs_agblocks;
	char * dev_name;
	char * mnt_point;
	unsigned long long int inodes_used;
	unsigned long long int free_blocks;
};

#ifdef TEST_COMPILE
# undef WFS_ANSIC
#endif

/* ======================================================================== */

#ifndef WFS_ANSIC
static int WFS_ATTR ((nonnull)) GCC_WARN_UNUSED_RESULT wfs_xfs_read_line
	WFS_PARAMS ((int fd, char * const buf, child_id_t * const child, const size_t bufsize));
#endif

/**
 * Reads a line of text from the given file descriptor and puts it in the buffer. Waits at most
 *	WFS_XFS_MAX_SELECT_SECONDS seconds for data.
 * @param fd The file descriptor to read the line from.
 * @param buf The buffer to put the line into.
 * @param child The child process that is supposed to produce the data.
 * @param bufsize The size of the given buffer.
 * @return the number of bytes read, excluding the trailing newline (negative in case of error).
 */
static int GCC_WARN_UNUSED_RESULT
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_xfs_read_line (
#ifdef WFS_ANSIC
	int fd, char * const buf, child_id_t * const child, const size_t bufsize)
#else
	fd, buf, child, bufsize)
	int fd;
	char * const buf;
	child_id_t * const child;
	const size_t bufsize;
#endif
{
	/* read just 1 line */
	int res = 0;
	int select_fails = 0;
	ssize_t bytes_read = -1;
#ifdef WFS_XFS_HAVE_SELECT
	struct timeval tv;
	fd_set set;
#endif

	if ( (buf == NULL) || (child == NULL) || (bufsize == 0) || (fd < 0) )
	{
		return -1;
	}

	WFS_MEMSET (buf, 0, bufsize);
	do
	{
		WFS_SET_ERRNO (0);
#ifdef WFS_XFS_HAVE_SELECT
		/* select() can destroy the descriptor sets */
		FD_ZERO (&set);
		FD_SET (fd, &set);	/* warnings are inside this macro */
		tv.tv_sec = WFS_XFS_MAX_SELECT_SECONDS;
		tv.tv_usec = 0;
		if ( select (fd+1, &set, NULL, NULL, &tv) > 0 )
		{
#endif
			bytes_read = read (fd, &(buf[res]), 1);
			if ( (buf[res] == '\n') || (buf[res] == '\r') )
			{
				break;
			}
			res++;
			select_fails = 0;
#ifdef WFS_XFS_HAVE_SELECT
		}
		else
		{
			bytes_read = 1;	/* just a marker */
			if ( /*(sigchld_recvd != 0) ||*/
				(wfs_has_child_exited (child) == 1) )
			{
				res = -2;
				break;
			}
			select_fails++;
			if ( select_fails > WFS_XFS_MAX_SELECT_FAILS )
			{
				res = -3;
				break;
			}
		}
#endif
	}
	while (    ((size_t)res < bufsize)
		&& (bytes_read == 1)
		&& (sig_recvd == 0)
		&& (select_fails <= WFS_XFS_MAX_SELECT_FAILS)
		);
	if ( bytes_read < 0 )
	{
		res = -4;
	}
	return res;
}

/* ======================================================================== */

#ifdef WFS_WANT_PART

# ifndef WFS_ANSIC
static void flush_pipe_output WFS_PARAMS ((const int fd));
# endif

/**
 * Flushes the given pipe so that hopefully the data sent will be
 *  received at the other end.
 * @param fd The pipe file descriptor to flush.
 */
static void
flush_pipe_output (
# ifdef WFS_ANSIC
	const int fd)
# else
	fd )
	const int fd;
# endif
{
	int i;
	for (i=0; i < PIPE_BUF; i++)
	{
		if ( write (fd, "\n", 1) != 1 )
		{
			break;
		}
	}
# if (defined HAVE_FSYNC) && (defined HAVE_UNISTD_H)
	fsync (fd);
# endif
}

#endif /* WFS_WANT_PART */

/* ======================================================================== */

#ifdef WFS_WANT_UNRM
/**
 * Starts recursive directory search for deleted inodes
 *	and undelete data on the given XFS filesystem.
 * \param wfs_fs The filesystem.
 * \param node Filesystem element at which to start.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_xfs_wipe_unrm (
# ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs WFS_ATTR ((unused)) )
# else
	wfs_fs )
	const wfs_fsid_t wfs_fs WFS_ATTR ((unused));
# endif
{
	unsigned int prev_percent = 0;
	/*
	 * The XFS has no undelete capability.
	 * Directories' sizes are multiples of block size, so can't wipe
	 *  unused space in these blocks.
	 */
	wfs_show_progress (WFS_PROGRESS_UNRM, 100, &prev_percent);
	return WFS_SUCCESS;
}
#endif /* WFS_WANT_UNRM */

/* ======================================================================== */

#if (defined WFS_WANT_WFS) || (defined WFS_WANT_PART)

# ifndef WFS_ANSIC
static size_t GCC_WARN_UNUSED_RESULT wfs_xfs_get_block_size
	WFS_PARAMS ((const wfs_fsid_t wfs_fs));
# endif

/**
 * Returns the buffer size needed to work on the
 *	smallest physical unit on a XFS filesystem.
 * \param wfs_fs The filesystem.
 * \return Block size on the filesystem.
 */
static size_t GCC_WARN_UNUSED_RESULT
wfs_xfs_get_block_size (
# ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs )
# else
	wfs_fs )
	const wfs_fsid_t wfs_fs;
# endif
{
	struct wfs_xfs * xxfs;

	xxfs = (struct wfs_xfs *) wfs_fs.fs_backend;
	if ( xxfs == NULL )
	{
		return 0;
	}
	return xxfs->wfs_xfs_blocksize;
}
#endif /* (defined WFS_WANT_WFS) || (defined WFS_WANT_PART) */


/* ======================================================================== */

#ifdef WFS_WANT_WFS
/**
 * Wipes the free space on the given XFS filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_xfs_wipe_fs	(
# ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
# else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
# endif
{
	unsigned long int i;
	int res;
	int pipe_fd[2];
	int fs_fd;
	child_id_t child_freeze, child_unfreeze, child_xfsdb;
	wfs_errcode_t ret_child;
	/* 	 xfs_freeze -f (freeze) | -u (unfreeze) mount-point */
# define FSNAME_POS_FREEZE 2
	const char * args_freeze[] = { "xfs_freeze", "-f", NULL, NULL };
	char ** args_freeze_copy = NULL;
# define FSNAME_POS_UNFREEZE 2
	const char * args_unfreeze[] = { "xfs_freeze", "-u", NULL, NULL };
	char ** args_unfreeze_copy = NULL;
	/*	 xfs_db  -c 'freesp -d' dev_name */
# define FSNAME_POS_FREESP 7
	const char * args_db[] = { "xfs_db", "-i", "-c",
		"freesp -d", "-c", "quit",
		"--", NULL, NULL };
	char ** args_db_copy = NULL;
	const char * const wfs_xfs_xfs_db_env[] = { "LC_ALL=C", NULL };
	char ** wfs_xfs_xfs_db_env_copy = NULL;
	char read_buffer[WFS_XFSBUFSIZE];
	unsigned long long int agno, agoff, length;
	unsigned char * buffer;
	unsigned long long int j;
	int selected[WFS_NPAT] = {0};
	wfs_errcode_t ret_wfs = WFS_SUCCESS;
	unsigned int prev_percent = 0;
	unsigned long long int curr_block = 0;
	wfs_errcode_t error = 0;
	struct wfs_xfs * xxfs;
	wfs_errcode_t * error_ret;
	size_t fs_block_size;
	off64_t file_offset;

	xxfs = (struct wfs_xfs *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( xxfs == NULL )
	{
		return WFS_BADPARAM;
	}

	fs_block_size = wfs_xfs_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}
	/* Copy the file system name into the right places */
	WFS_SET_ERRNO (0);
	args_db[FSNAME_POS_FREESP] = xxfs->dev_name;
	args_db_copy = deep_copy_array (args_db, sizeof (args_db) / sizeof (args_db[0]));
	
	if ( args_db_copy == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}
	/* we need the mount point here, not the wfs_fs device */
	if ( xxfs->mnt_point != NULL )
	{
		WFS_SET_ERRNO (0);
		args_freeze[FSNAME_POS_FREEZE] = xxfs->mnt_point;
		args_freeze_copy = deep_copy_array (args_freeze,
			sizeof (args_freeze) / sizeof (args_freeze[0]));
		if ( args_freeze_copy == NULL )
		{
			error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
			free_array_deep_copy (args_db_copy,
				sizeof (args_db) / sizeof (args_db[0]));
			wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_MALLOC;
		}
		WFS_SET_ERRNO (0);
		args_unfreeze[FSNAME_POS_UNFREEZE] = xxfs->mnt_point;
		args_unfreeze_copy = deep_copy_array (args_unfreeze,
			sizeof (args_unfreeze) / sizeof (args_unfreeze[0]));
		if ( args_unfreeze_copy == NULL )
		{
			error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
			free_array_deep_copy (args_freeze_copy,
				sizeof (args_freeze) / sizeof (args_freeze[0]));
			free_array_deep_copy (args_db_copy,
				sizeof (args_db) / sizeof (args_db[0]));
			wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_MALLOC;
		}
	}
	WFS_SET_ERRNO (0);
	buffer = (unsigned char *) malloc ( fs_block_size );
	if ( buffer == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		free_array_deep_copy (args_unfreeze_copy,
			sizeof (args_unfreeze) / sizeof (args_unfreeze[0]));
		free_array_deep_copy (args_freeze_copy,
			sizeof (args_freeze) / sizeof (args_freeze[0]));
		free_array_deep_copy (args_db_copy,
			sizeof (args_db) / sizeof (args_db[0]));
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	WFS_SET_ERRNO (0);
	wfs_xfs_xfs_db_env_copy = deep_copy_array (wfs_xfs_xfs_db_env,
		sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
	if ( wfs_xfs_xfs_db_env_copy == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		free (buffer);
		free_array_deep_copy (args_unfreeze_copy,
			sizeof (args_unfreeze) / sizeof (args_unfreeze[0]));
		free_array_deep_copy (args_freeze_copy,
			sizeof (args_freeze) / sizeof (args_freeze[0]));
		free_array_deep_copy (args_db_copy,
			sizeof (args_db) / sizeof (args_db[0]));
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	WFS_SET_ERRNO (0);
	res = pipe (pipe_fd);
	if ( (res < 0)
# ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
# endif
		 )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (1L);
		free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
			sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
		free (buffer);
		free_array_deep_copy (args_unfreeze_copy,
			sizeof (args_unfreeze) / sizeof (args_unfreeze[0]));
		free_array_deep_copy (args_freeze_copy,
			sizeof (args_freeze) / sizeof (args_freeze[0]));
		free_array_deep_copy (args_db_copy,
			sizeof (args_db) / sizeof (args_db[0]));
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_PIPEERR;
	}
	/* In case of child error the parent process
	   will hang waiting for data from a closed pipe.
	*/
	/* NOTE: we shouldn't do this. The child should wait with printing
	   while we are processing the data. Non-blocking mode should be enabled only
	   when no output is an option.
	fcntl (pipe_fd[PIPE_R], F_SETFL, fcntl (pipe_fd[PIPE_R], F_GETFL) | O_NONBLOCK );
	fcntl (pipe_fd[PIPE_W], F_SETFL, fcntl (pipe_fd[PIPE_W], F_GETFL) | O_NONBLOCK );
	*/

	if ( xxfs->mnt_point != NULL )
	{
		/* Freeze the filesystem */
# ifdef HAVE_SIGNAL_H
		sigchld_recvd = 0;
# endif
		child_freeze.program_name = args_freeze_copy[0];
		child_freeze.args = args_freeze_copy;
		child_freeze.child_env = NULL;
		child_freeze.stdin_fd = -1;
		child_freeze.stdout_fd = -1;
		child_freeze.stderr_fd = -1;
		ret_child = wfs_create_child (&child_freeze);
		if ( ret_child != WFS_SUCCESS )
		{
			/* error */
			error = WFS_GET_ERRNO_OR_DEFAULT (1L);
			close (pipe_fd[PIPE_R]);
			close (pipe_fd[PIPE_W]);
			free (buffer);
			free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
				sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
			free_array_deep_copy (args_unfreeze_copy,
				sizeof (args_unfreeze) / sizeof (args_unfreeze[0]));
			free_array_deep_copy (args_freeze_copy,
				sizeof (args_freeze) / sizeof (args_freeze[0]));
			free_array_deep_copy (args_db_copy,
				sizeof (args_db) / sizeof (args_db[0]));
			wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_FORKERR;
		}
		/* parent */
		wfs_wait_for_child (&child_freeze);
	}	/* if ( xxfs->mnt_point != NULL )  */

	/* parent, continued */
	WFS_SET_ERRNO (0);
# ifdef HAVE_SIGNAL_H
	sigchld_recvd = 0;
# endif
	child_xfsdb.program_name = args_db_copy[0];
	child_xfsdb.args = args_db_copy;
	child_xfsdb.child_env = wfs_xfs_xfs_db_env_copy;
	child_xfsdb.stdin_fd = -1;
	child_xfsdb.stdout_fd = pipe_fd[PIPE_W];
	child_xfsdb.stderr_fd = pipe_fd[PIPE_W];
	ret_child = wfs_create_child (&child_xfsdb);
	if ( ret_child != WFS_SUCCESS )
	{
		/* error */
		error = WFS_GET_ERRNO_OR_DEFAULT (1L);
		/* can't return from here - have to un-freeze first */
		ret_wfs = WFS_FORKERR;
	}
	/* parent */
# ifdef HAVE_SLEEP
	sleep (1);
# else
	for (i=0; (i < (1<<30)) && (sig_recvd == 0); i++ );
# endif
	/* open the wfs_fs */
	WFS_SET_ERRNO (0);
	fs_fd = open64 (xxfs->dev_name, O_RDWR | O_EXCL
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
		/* can't return from here - have to un-freeze first */
		ret_wfs = WFS_OPENFS;
	}

	while ( (sig_recvd == 0) && (fs_fd >= 0) /*&& (ret_wfs == WFS_SUCCESS)*/ )
	{
		/* read just 1 line */
		res = wfs_xfs_read_line (pipe_fd[PIPE_R], read_buffer,
			&child_xfsdb, sizeof (read_buffer) );
# ifdef HAVE_ERRNO_H
		/*if ( errno == EAGAIN ) continue;*/
# endif
		if ( (res < 0) || (sig_recvd != 0) /*|| (sigchld_recvd != 0)*/
# ifdef HAVE_ERRNO_H
/*			|| ( errno != 0 )*/
# endif
			)
		{
			/* can't return from here - have to un-freeze first */
			ret_wfs = WFS_INOREAD;
			break;
		}
		read_buffer[sizeof (read_buffer)-1] = '\0';

			/*
				xfs_db output format is:
				xfs_db> freesp -d -h1
					0     1204        1
					0     1205        1
					0     1206        1
					0     1207        1
					0     1212     2884
					from      to extents  blocks    pct
					1    4096       5    2888 100.00
				It's a tabbed column output of AG #,
				AG offset and length in blocks.

				Disk offset = (AG # * sb.agblocks + AG offset) * sb.blocksize.
				*/

		res = sscanf ( read_buffer, " %llu %llu %llu", &agno, &agoff, &length );
		if ( res != 3 )
		{
			/* "from ... to ..." line probably reached */
			break;
		}
		/* Disk offset = (agno * xxfs->wfs_xfs_agblocks + agoff ) * \
			xxfs->wfs_xfs_blocksize */
		file_offset = (off64_t) ((agno * xxfs->wfs_xfs_agblocks + agoff) *
			fs_block_size);
		/* Wiping loop */
		for ( i = 0; (i < wfs_fs.npasses) && (sig_recvd == 0); i++ )
		{
			/* NOTE: this must be inside */
			if ( lseek64 (fs_fd, file_offset, SEEK_SET) != file_offset )
			{
				break;
			}
			for ( j = 0; (j < length) && (sig_recvd == 0); j++ )
			{
				if ( wfs_fs.no_wipe_zero_blocks != 0 )
				{
					if ( read (fs_fd, buffer, fs_block_size)
						!= (ssize_t) fs_block_size )
					{
						ret_wfs = WFS_BLKRD;
						break;
					}
					if ( wfs_is_block_zero (buffer, fs_block_size) != 0 )
					{
						/* this block is all-zeros - don't wipe, as requested */
						i = wfs_fs.npasses * 2;
					}
					/* NOTE: this must be inside also after read() */
					if ( lseek64 (fs_fd, file_offset, SEEK_SET) != file_offset )
					{
						break;
					}
				}
				if ( i != wfs_fs.npasses * 2 )
				{
					fill_buffer ( i, buffer, fs_block_size, selected, wfs_fs );
					if ( write (fs_fd, buffer, fs_block_size)
						!= (ssize_t) fs_block_size )
					{
						ret_wfs = WFS_BLKWR;
						break;
					}
					/* Flush after each writing, if more than 1 overwriting
						needs to be done. Allow I/O bufferring (efficiency),
						if just one pass is needed. */
					if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
					{
						error = wfs_xfs_flush_fs (wfs_fs);
					}
				}
				file_offset += (off64_t) fs_block_size;
			}
			if ( j < length )
			{
				break;
			}
		}
		if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
		{
			file_offset = (off64_t) ((agno * xxfs->wfs_xfs_agblocks + agoff) *
				fs_block_size);
			/* NOTE: this must be inside */
			if ( lseek64 (fs_fd, file_offset, SEEK_SET) != file_offset )
			{
				break;
			}
			/* last pass with zeros: */
			if ( sig_recvd == 0 )
			{
				for ( j = 0; (j < length) && (sig_recvd == 0); j++ )
				{
					i = 1;
					if ( wfs_fs.no_wipe_zero_blocks != 0 )
					{
						if ( read (fs_fd, buffer, fs_block_size)
							!= (ssize_t) fs_block_size )
						{
							ret_wfs = WFS_BLKRD;
							break;
						}
						if ( wfs_is_block_zero (buffer, fs_block_size) != 0 )
						{
							/* this block is all-zeros - don't wipe, as requested */
							i = 0;
						}
						/* NOTE: this must be inside also after read() */
						if ( lseek64 (fs_fd, file_offset, SEEK_SET) != file_offset )
						{
							break;
						}
					}
					if ( i == 1 )
					{
						WFS_MEMSET ( buffer, 0, fs_block_size );
						if ( write (fs_fd, buffer, fs_block_size)
							!= (ssize_t) fs_block_size
						)
						{
							ret_wfs = WFS_BLKWR;
							break;
						}
						/* No need to flush the last writing of a given block. *
						if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
						{
							error = wfs_xfs_flush_fs (wfs_fs);
						} */
					}
					file_offset += (off64_t) fs_block_size;
				}
				if ( j < length )
				{
					break;
				}
			}
		}
		curr_block += length;
		if ( xxfs->free_blocks > 0 )
		{
			wfs_show_progress (WFS_PROGRESS_WFS, (unsigned int) ((curr_block * 100)
				/(xxfs->free_blocks)), &prev_percent);
		}
		if ( i < wfs_fs.npasses )
		{
			break;
		}
	}
	/* child stopped writing? something went wrong?
	close the wfs_fs and kill the child process
	*/

	close (fs_fd);
	wfs_wait_for_child (&child_xfsdb);
	wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);

	if ( xxfs->mnt_point != NULL )
	{
		/* un-freeze the filesystem */
# ifdef HAVE_SIGNAL_H
		sigchld_recvd = 0;
# endif
		child_unfreeze.program_name = args_unfreeze_copy[0];
		child_unfreeze.args = args_unfreeze_copy;
		child_unfreeze.child_env = NULL;
		child_unfreeze.stdin_fd = -1;
		child_unfreeze.stdout_fd = -1;
		child_unfreeze.stderr_fd = -1;
		ret_child = wfs_create_child (&child_unfreeze);
		if ( ret_child != WFS_SUCCESS )
		{
			/* error */
			error = WFS_GET_ERRNO_OR_DEFAULT (1L);
			ret_wfs = WFS_FORKERR;
		}
		/* parent */
		wfs_wait_for_child (&child_unfreeze);
	} /* if ( xxfs->mnt_point != NULL ) */

	close (pipe_fd[PIPE_R]);
	close (pipe_fd[PIPE_W]);

	free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
		sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
	free (buffer);
	free_array_deep_copy (args_unfreeze_copy,
		sizeof (args_unfreeze) / sizeof (args_unfreeze[0]));
	free_array_deep_copy (args_freeze_copy,
		sizeof (args_freeze) / sizeof (args_freeze[0]));
	free_array_deep_copy (args_db_copy,
		sizeof (args_db) / sizeof (args_db[0]));
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	if (sig_recvd != 0)
	{
		return WFS_SIGNAL;
	}
	return ret_wfs;
}
#endif /* WFS_WANT_WFS */

/* ======================================================================== */

#ifdef WFS_WANT_PART

# ifdef XFS_HAS_SHARED_BLOCKS
#  define WFS_ONLY_WITH_XFS_SHARED_BLOCKS WFS_ATTR ((unused))
# else
#  define WFS_ONLY_WITH_XFS_SHARED_BLOCKS
# endif

/**
 * Wipes the free space in partially used blocks on the given XFS filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_xfs_wipe_part (
# ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs WFS_ONLY_WITH_XFS_SHARED_BLOCKS)
# else
	wfs_fs)
	const wfs_fsid_t wfs_fs WFS_ONLY_WITH_XFS_SHARED_BLOCKS;
# endif
{
	/*
	xfs_db> blockget -n
	xfs_db> ncheck
	      19331 test-A
	      19332 test-B
	      19333 test-C
	xfs_db> inode 19333
	xfs_db> print
		core.mode = 100600
		core.size = 28671
		core.nblocks = 7
		== check mode ==
	xfs_db> bmap -d
		data offset 0 startblock 1214 (0/1214) count 1 flag 0
	xfs_db> inode 19334
	xfs_db> bmap -d
		data offset 0 startblock 1215 (0/1215) count 7 flag 0
	 */
	wfs_errcode_t ret_part = WFS_SUCCESS;
# ifndef XFS_HAS_SHARED_BLOCKS

	unsigned long int i;
	int res;
	ssize_t write_res;
	int pipe_from_ino_db[2];
	int pipe_from_blk_db[2], pipe_to_blk_db[2];
	int fs_fd;
	child_id_t child_ncheck, child_xfsdb;
	wfs_errcode_t ret_child;
	/*	 xfs_db   dev_name */
#  define FSNAME_POS_PART_NCHECK 9
	const char * args_db_ncheck[] = { "xfs_db", "-i", "-c",
		"blockget -n", "-c", "ncheck",
		"-c", "quit", "--", NULL, NULL };
#  define FSNAME_POS_PART_DB 3
	char ** args_db_ncheck_copy = NULL;
	const char * args_db[] = { "xfs_db", "-i", "--", NULL, NULL };
	char ** args_db_copy = NULL;
	const char * const wfs_xfs_xfs_db_env[] = { "LC_ALL=C", NULL };
	char ** wfs_xfs_xfs_db_env_copy = NULL;
	char read_buffer[WFS_XFSBUFSIZE];
	char * pos1 = NULL;
	char * pos2 = NULL;
	unsigned char * buffer;
	int selected[WFS_NPAT] = {0};
	unsigned long long int inode, inode_size, start_block, number_of_blocks;
	int length_to_wipe;
	unsigned long long int trash;
	int got_mode_line, got_size_line;
	unsigned int mode;
	unsigned int offset;
	char inode_cmd[40];
	unsigned int prev_percent = 0;
	unsigned long long int curr_inode = 0;
	wfs_errcode_t error = 0;
	struct wfs_xfs * xxfs;
	wfs_errcode_t * error_ret;
	size_t fs_block_size;
	off64_t file_offset;

	xxfs = (struct wfs_xfs *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( xxfs == NULL )
	{
		return WFS_BADPARAM;
	}

	fs_block_size = wfs_xfs_get_block_size (wfs_fs);
	if ( fs_block_size == 0 )
	{
		return WFS_BADPARAM;
	}

	/* Copy the file system name into the right places */
	WFS_SET_ERRNO (0);
	args_db[FSNAME_POS_PART_DB] = xxfs->dev_name;
	args_db_copy = deep_copy_array (args_db, sizeof (args_db) / sizeof (args_db[0]));
	if ( args_db_copy == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	WFS_SET_ERRNO (0);
	args_db_ncheck[FSNAME_POS_PART_NCHECK] = xxfs->dev_name;
	args_db_ncheck_copy = deep_copy_array (args_db_ncheck,
		sizeof (args_db_ncheck) / sizeof (args_db_ncheck[0]));
	if ( args_db_ncheck_copy == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		free_array_deep_copy (args_db_copy,
			sizeof (args_db) / sizeof (args_db[0]));
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	WFS_SET_ERRNO (0);
	buffer = (unsigned char *) malloc ( fs_block_size );
	if ( buffer == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		free_array_deep_copy (args_db_ncheck_copy,
			sizeof (args_db_ncheck) / sizeof (args_db_ncheck[0]));
		free_array_deep_copy (args_db_copy,
			sizeof (args_db) / sizeof (args_db[0]));
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	WFS_SET_ERRNO (0);
	wfs_xfs_xfs_db_env_copy = deep_copy_array (wfs_xfs_xfs_db_env,
		sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
	if ( wfs_xfs_xfs_db_env_copy == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		free (buffer);
		free_array_deep_copy (args_db_ncheck_copy,
			sizeof (args_db_ncheck) / sizeof (args_db_ncheck[0]));
		free_array_deep_copy (args_db_copy,
			sizeof (args_db) / sizeof (args_db[0]));
		wfs_show_progress (WFS_PROGRESS_WFS, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	WFS_SET_ERRNO (0);
	res = pipe (pipe_from_ino_db);
	if ( (res < 0)
#  ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
#  endif
		 )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (1L);
		free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
			sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
		free (buffer);
		free_array_deep_copy (args_db_ncheck_copy,
			sizeof (args_db_ncheck) / sizeof (args_db_ncheck[0]));
		free_array_deep_copy (args_db_copy,
			sizeof (args_db) / sizeof (args_db[0]));
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_PIPEERR;
	}

	WFS_SET_ERRNO (0);
	res = pipe (pipe_to_blk_db);
	if ( (res < 0)
#  ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
#  endif
		 )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (1L);
		close (pipe_from_ino_db[PIPE_R]);
		close (pipe_from_ino_db[PIPE_W]);
		free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
			sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
		free (buffer);
		free_array_deep_copy (args_db_ncheck_copy,
			sizeof (args_db_ncheck) / sizeof (args_db_ncheck[0]));
		free_array_deep_copy (args_db_copy,
			sizeof (args_db) / sizeof (args_db[0]));
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_PIPEERR;
	}

	WFS_SET_ERRNO (0);
	res = pipe (pipe_from_blk_db);
	if ( (res < 0)
#  ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
#  endif
		 )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (1L);
		close (pipe_from_ino_db[PIPE_R]);
		close (pipe_from_ino_db[PIPE_W]);
		close (pipe_to_blk_db[PIPE_R]);
		close (pipe_to_blk_db[PIPE_W]);
		free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
			sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
		free (buffer);
		free_array_deep_copy (args_db_ncheck_copy,
			sizeof (args_db_ncheck) / sizeof (args_db_ncheck[0]));
		free_array_deep_copy (args_db_copy,
			sizeof (args_db) / sizeof (args_db[0]));
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_PIPEERR;
	}

	/* open the first xfs_db process - it will read used inode's numbers */
	WFS_SET_ERRNO (0);
#  ifdef HAVE_SIGNAL_H
	sigchld_recvd = 0;
#  endif
	child_ncheck.program_name = args_db_ncheck_copy[0];
	child_ncheck.args = args_db_ncheck_copy;
	child_ncheck.child_env = wfs_xfs_xfs_db_env_copy;
	child_ncheck.stdin_fd = -1;
	child_ncheck.stdout_fd = pipe_from_ino_db[PIPE_W];
	child_ncheck.stderr_fd = -1;
	ret_child = wfs_create_child (&child_ncheck);
	if ( ret_child != WFS_SUCCESS )
	{
		/* error */
		error = WFS_GET_ERRNO_OR_DEFAULT (1L);
		close (pipe_from_ino_db[PIPE_R]);
		close (pipe_from_ino_db[PIPE_W]);
		close (pipe_to_blk_db[PIPE_R]);
		close (pipe_to_blk_db[PIPE_W]);
		close (pipe_from_blk_db[PIPE_R]);
		close (pipe_from_blk_db[PIPE_W]);
		free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
			sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
		free (buffer);
		free_array_deep_copy (args_db_ncheck_copy,
			sizeof (args_db_ncheck) / sizeof (args_db_ncheck[0]));
		free_array_deep_copy (args_db_copy,
			sizeof (args_db) / sizeof (args_db[0]));
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_FORKERR;
	}
	/* parent */
	/* open a second xfs_db process - this one will read inodes' block info */
	WFS_SET_ERRNO (0);
#  ifdef HAVE_SIGNAL_H
	sigchld_recvd = 0;
#  endif
	child_xfsdb.program_name = args_db_copy[0];
	child_xfsdb.args = args_db_copy;
	child_xfsdb.child_env = wfs_xfs_xfs_db_env_copy;
	child_xfsdb.stdin_fd = pipe_to_blk_db[PIPE_R];
	child_xfsdb.stdout_fd = pipe_from_blk_db[PIPE_W];
	child_xfsdb.stderr_fd = pipe_from_blk_db[PIPE_W];
	ret_child = wfs_create_child (&child_xfsdb);
	if ( ret_child != WFS_SUCCESS )
	{
		/* error */
		error = WFS_GET_ERRNO_OR_DEFAULT (1L);
		close (pipe_from_ino_db[PIPE_R]);
		close (pipe_from_ino_db[PIPE_W]);
		wfs_wait_for_child (&child_ncheck);
		close (pipe_to_blk_db[PIPE_R]);
		close (pipe_to_blk_db[PIPE_W]);
		close (pipe_from_blk_db[PIPE_R]);
		close (pipe_from_blk_db[PIPE_W]);
		free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
			sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
		free (buffer);
		free_array_deep_copy (args_db_ncheck_copy,
			sizeof (args_db_ncheck) / sizeof (args_db_ncheck[0]));
		free_array_deep_copy (args_db_copy,
			sizeof (args_db) / sizeof (args_db[0]));
		wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_FORKERR;
	}
	/* parent */
	/* open the wfs_fs */
	WFS_SET_ERRNO (0);
	fs_fd = open64 (xxfs->dev_name, O_RDWR | O_EXCL
#  ifdef O_BINARY
		| O_BINARY
#  endif
		);
	if ( (fs_fd < 0)
#  ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
#  endif
	   )
	{
		ret_part = WFS_OPENFS;
	}
	while ( (sig_recvd == 0) && (fs_fd >= 0) /*&& (ret_part == WFS_SUCCESS)*/ )
	{
		/* read just 1 line with inode-file pair */
		res = wfs_xfs_read_line (pipe_from_ino_db[PIPE_R], read_buffer,
			&child_ncheck, sizeof (read_buffer) );
#  ifdef HAVE_ERRNO_H
		/*if ( errno == EAGAIN ) continue;*/
#  endif
		if ( (res < 0) || (sig_recvd != 0) /*|| (sigchld_recvd != 0)*/
#  ifdef HAVE_ERRNO_H
/*			|| ( errno != 0 )*/
#  endif
		   )
		{
			/* NOTE: don't return an error here. The child process
			has probably stopped after displaying everything. */
			/*ret_part = WFS_INOREAD;*/
			break;
		}
		read_buffer[sizeof (read_buffer)-1] = '\0';
		res = sscanf ( read_buffer, " %llu", &inode );
		if ( res != 1 )
		{
			continue;	/* stop only when child stops writing */
		}
		/* request inode data from the second xfs_db */
#  ifdef HAVE_SNPRINTF
		snprintf (inode_cmd, sizeof (inode_cmd)-1, "inode %llu\nprint\n", inode);
#  else
		sprintf (inode_cmd, "inode %llu\nprint\n", inode);
#  endif
		inode_cmd[sizeof (inode_cmd)-1] = '\0';
		/* flush input to get rid of the rest of inode info and 'xfs_db>' trash */
		wfs_flush_pipe_input (pipe_from_blk_db[PIPE_R]);
		write_res = write (pipe_to_blk_db[PIPE_W], inode_cmd, strlen (inode_cmd));
		if ( write_res <= 0 )
		{
			break;
		}
		flush_pipe_output (pipe_to_blk_db[PIPE_W]);
		/* read the inode info. Look for "core.mode = " and "core.size = " */
		got_mode_line = 0;
		got_size_line = 0;
		mode = 01000;	/* any mode that isn't a regular file's mode */
		inode_size = 0;
		while (((got_mode_line == 0) || (got_size_line == 0)) && (sig_recvd == 0))
		{
			/* read just 1 line */
			res = wfs_xfs_read_line (pipe_from_blk_db[PIPE_R], read_buffer,
				&child_xfsdb, sizeof (read_buffer) );
#  ifdef HAVE_ERRNO_H
			/*if ( errno == EAGAIN ) continue;*/
#  endif
			if ( (res < 0) || (sig_recvd != 0) /*|| (sigchld_recvd != 0)*/
#  ifdef HAVE_ERRNO_H
/*				|| ( errno != 0 )*/
#  endif
			   )
			{
				break;
			}
#  define modeline "core.mode = "
#  define sizeline "core.size = "
			read_buffer[sizeof (read_buffer)-1] = '\0';
			pos1 = strstr (read_buffer, modeline);
			pos2 = strstr (read_buffer, sizeline);
			/* get inode mode */
			if ( pos1 != NULL )
			{
				res = sscanf (pos1, modeline "%o", &mode);
				if ( res != 1 )
				{
					/* line found, but cannot be parsed */
					break;
				}
				got_mode_line = 1;
			}
			/* get inode size */
			else if ( pos2 != NULL )
			{
				res = sscanf (pos2, sizeline "%llu", &inode_size);
				if ( res != 1 )
				{
					/* line found, but cannot be parsed */
					break;
				}
				got_size_line = 1;
			}
		} /* while - looking for modeline & sizeline */
		if (sig_recvd != 0)
		{
			break;
		}
		/* flush input to get rid of the rest of inode info and 'xfs_db>' trash */
		wfs_flush_pipe_input (pipe_from_blk_db[PIPE_R]);
		if ( (got_mode_line == 0) || (got_size_line == 0) )
		{
			ret_part = WFS_INOREAD;
			continue;
		}
		/* check inode mode */
		if ( ! S_ISREG (mode) )
		{
			continue;
		}
		/* send "bmap -d" */
		write_res = write (pipe_to_blk_db[PIPE_W], "bmap -d\n", 8);
		if ( write_res <= 0 )
		{
			break;
		}
		flush_pipe_output (pipe_to_blk_db[PIPE_W]);
		res = 0;
		do
		{
			/* read just 1 line */
			res = wfs_xfs_read_line (pipe_from_blk_db[PIPE_R], &read_buffer[res],
				&child_xfsdb, sizeof (read_buffer) - (size_t)res );
#  ifdef HAVE_ERRNO_H
			/*if ( errno == EAGAIN ) continue;*/
#  endif
			if ( (res < 0) || (sig_recvd != 0) /*|| (sigchld_recvd != 0)*/
#  ifdef HAVE_ERRNO_H
/*				|| ( errno != 0 )*/
#  endif
			   )
			{
				break;
			}
			read_buffer[sizeof (read_buffer)-1] = '\0';
			/* parse line into block numbers. Read line has data:
				data offset 0 startblock 1215 (0/1215) count 7 flag 0
			 */
			/* check for first line element */
			pos1 = strstr (read_buffer, "da");
			if ( pos1 == NULL )
			{
				pos1 = strstr (read_buffer, " d");
			}
			if ( pos1 == NULL )
			{
				pos1 = strstr (read_buffer, "\rd");
			}
			if ( pos1 == NULL )
			{
				pos1 = strstr (read_buffer, "\nd");
			}
			if ( pos1 == NULL )
			{
				/* if missing, start reading again */
				res = 0;
				continue;
			}
			/* check for last line element */
			if ( strstr (read_buffer, "flag") == NULL )
			{
				/* if missing, but first is present, join this reading
				   with the next one. Strncpy requires non-overlapping
				   buffers. */
				for ( i = 0; i < (size_t)(&read_buffer[sizeof (read_buffer) - 1] - pos1); i++ )
				{
					read_buffer[i] = pos1[i];
				}
				res = (int)((&read_buffer[sizeof (read_buffer) - 1] - pos1) & 0x0FFFFFFFF);
				read_buffer[res] = '\0';
				continue;
			}
			start_block = 0;
			number_of_blocks = 0;
			res = sscanf (pos1,
				"data offset %u startblock %llu (%llu/%llu) count %llu flag %u",
				&offset, &start_block, &trash, &trash, &number_of_blocks, &mode );

			/* flush input to get rid of the rest of inode info and 'xfs_db>' trash */
			wfs_flush_pipe_input (pipe_from_blk_db[PIPE_R]);
			if ( res != 6 )
			{
				/* line found, but cannot be parsed */
				break;
			}
			if ( (start_block == 0) /* probably parsed incorrectly */
				|| (offset > fs_block_size) )
			{
				res = 0;
				continue;
			}

			/* wipe the last block
			 * The length of the last part of the file in the last block is
			 * (inode_size+offset)%block_size, so we need to wipe
			 * block_size - [(inode_size+offset)%block_size] bytes
			 */
			/* NOTE: 'offset' is probably NOT the offset within a block at all */
			length_to_wipe = (int)fs_block_size
				- (int)((inode_size/*+offset*/) % fs_block_size);
			if ( length_to_wipe <= 0 )
			{
				res = 0;
				continue;
			}
			file_offset = (off64_t) (start_block * fs_block_size
				+ inode_size);
			for ( i = 0; (i < wfs_fs.npasses) && (sig_recvd == 0); i++ )
			{
				/* go back to writing position - NOTE: this must be inside! */
				if ( lseek64 (fs_fd, file_offset, SEEK_SET)
					!= file_offset )
				{
					break;
				}
				if ( wfs_fs.no_wipe_zero_blocks != 0 )
				{
					if ( read (fs_fd, buffer, fs_block_size)
						!= (ssize_t) fs_block_size )
					{
						ret_part = WFS_BLKRD;
						break;
					}
					if ( wfs_is_block_zero (buffer, fs_block_size) != 0 )
					{
						/* this block is all-zeros - don't wipe, as requested */
						i = wfs_fs.npasses * 2;
					}
					/* NOTE: this must be inside also after read() */
					if ( lseek64 (fs_fd, file_offset, SEEK_SET)
						!= file_offset )
					{
						break;
					}
				}
				if ( i != wfs_fs.npasses * 2 )
				{
					fill_buffer ( i, buffer, fs_block_size, selected, wfs_fs );
					if ( write (fs_fd, buffer, (size_t)length_to_wipe) != length_to_wipe )
					{
						ret_part = WFS_BLKWR;
						break;
					}
					/* Flush after each writing, if more than 1 overwriting needs to be done.
					Allow I/O bufferring (efficiency), if just one pass is needed. */
					if ( WFS_IS_SYNC_NEEDED(wfs_fs) )
					{
						error = wfs_xfs_flush_fs (wfs_fs);
					}
				}
			}
			if ( (wfs_fs.zero_pass != 0) && (sig_recvd == 0) )
			{
				/* last pass with zeros: */
				/* NOTE: this must be inside */
				if ( lseek64 (fs_fd, file_offset, SEEK_SET)
					!= file_offset )
				{
					break;
				}
				if ( i != wfs_fs.npasses * 2 )
				{
					/* this block is NOT all-zeros - wipe */
					WFS_MEMSET ( buffer, 0, fs_block_size );
					if ( sig_recvd == 0 )
					{
						if ( write (fs_fd, buffer, (size_t)length_to_wipe)
							!= length_to_wipe )
						{
							ret_part = WFS_BLKWR;
							break;
						}
						/* No need to flush the last
						 * writing of a given block. *
						if ( (wfs_fs.npasses > 1) && (sig_recvd == 0) )
						{
							error = wfs_xfs_flush_fs (wfs_fs);
						} */
					}
				}
			}
			curr_inode++;
			if ( xxfs->inodes_used > 0 )
			{
				wfs_show_progress (WFS_PROGRESS_PART, (unsigned int) ((curr_inode * 100)
					/(xxfs->inodes_used)), &prev_percent);
			}
			break;
		} while (sig_recvd == 0);
	} /* while: reading inode-file */
	wfs_show_progress (WFS_PROGRESS_PART, 100, &prev_percent);
	write_res = write (pipe_to_blk_db[PIPE_W], "quit\n", 5);
	close (pipe_to_blk_db[PIPE_R]);
	close (pipe_to_blk_db[PIPE_W]);

	/* child stopped writing? something went wrong?
	   close the wfs_fs and kill the child process
	 */
	if ( fs_fd >= 0 )
	{
		close (fs_fd);
	}
	wfs_wait_for_child (&child_xfsdb);
	wfs_wait_for_child (&child_ncheck);

	close (pipe_from_ino_db[PIPE_R]);
	close (pipe_from_ino_db[PIPE_W]);
	close (pipe_from_blk_db[PIPE_R]);
	close (pipe_from_blk_db[PIPE_W]);

	free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
		sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
	free (buffer);
	free_array_deep_copy (args_db_ncheck_copy,
		sizeof (args_db_ncheck) / sizeof (args_db_ncheck[0]));
	free_array_deep_copy (args_db_copy,
		sizeof (args_db) / sizeof (args_db[0]));
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	if ( sig_recvd != 0 )
	{
		return WFS_SIGNAL;
	}
# endif /* XFS_HAS_SHARED_BLOCKS */
	return ret_part;
}
#endif /* WFS_WANT_PART */

/* ======================================================================== */

/**
 * Checks if the XFS filesystem has errors.
 * \param wfs_fs The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_xfs_check_err (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
#endif
{
	/* Requires xfs_db! No output expected.	*/
	int res;
	int pipe_fd[2];
	child_id_t child_xfschk;
	wfs_errcode_t ret_child;
#define FSNAME_POS_CHECK_DEV 1
#define FSNAME_POS_CHECK_FILE 2
	const char * args[] = { "xfs_check", NULL,
		NULL, NULL }; /* xfs_check [-f] dev/file */
	char ** args_copy = NULL;
	char buffer[WFS_XFSBUFSIZE];
	wfs_errcode_t error = 0;
	struct wfs_xfs * xxfs;
	wfs_errcode_t * error_ret;
#ifdef HAVE_STAT_H
# ifdef HAVE_STAT64
	struct stat64 s;
# else
	struct stat s;
# endif
#endif

	xxfs = (struct wfs_xfs *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	if ( xxfs == NULL )
	{
		return WFS_BADPARAM;
	}

	res = 0;
#ifdef HAVE_STAT_H
# ifdef HAVE_STAT64
	if ( stat64 (xxfs->dev_name, &s) >= 0 )
# else
	if ( stat (xxfs->dev_name, &s) >= 0 )
# endif
	{
		if ( S_ISREG (s.st_mode) )
		{
			res = 1;
		}
	}
#endif
	
	/* Copy the file system name into the right places */
	WFS_SET_ERRNO (0);
	if ( res == 0 )
	{
		/* device or cannot check */
		args[FSNAME_POS_CHECK_DEV] = xxfs->dev_name;
	}
	else
	{
		/* regular file: 'xfs_check -f xxx' */
		args[FSNAME_POS_CHECK_DEV] = "-f";
		args[FSNAME_POS_CHECK_FILE] = xxfs->dev_name;
	}
	args_copy = deep_copy_array (args, sizeof (args) / sizeof (args[0]));
	if ( args_copy == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}
	WFS_SET_ERRNO (0);
	res = pipe (pipe_fd);
	if ( (res < 0)
#ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
#endif
		 )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (1L);
		free_array_deep_copy (args_copy,
			sizeof (args) / sizeof (args[0]));
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_PIPEERR;
	}

	/* This is required. In case of child error the parent process
	   will hang waiting for data from a closed pipe.
	   NOTE: no output is possible, so non-blocking mode is required.
	*/
	fcntl (pipe_fd[PIPE_R], F_SETFL, fcntl (pipe_fd[PIPE_R], F_GETFL) | O_NONBLOCK );
	fcntl (pipe_fd[PIPE_W], F_SETFL, fcntl (pipe_fd[PIPE_W], F_GETFL) | O_NONBLOCK );

	WFS_SET_ERRNO (0);
#ifdef HAVE_SIGNAL_H
	sigchld_recvd = 0;
#endif
	child_xfschk.program_name = args_copy[0];
	child_xfschk.args = args_copy;
	child_xfschk.child_env = NULL;
	child_xfschk.stdin_fd = -1;
	child_xfschk.stdout_fd = pipe_fd[PIPE_W];
	child_xfschk.stderr_fd = pipe_fd[PIPE_W];
	ret_child = wfs_create_child (&child_xfschk);
	if ( ret_child != WFS_SUCCESS )
	{
		/* error */
		error = WFS_GET_ERRNO_OR_DEFAULT (1L);
		close (pipe_fd[PIPE_R]);
		close (pipe_fd[PIPE_W]);
		free_array_deep_copy (args_copy,
			sizeof (args) / sizeof (args[0]));
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_FORKERR;
	}
	/* Any output means error. Read just 1 line */
	/* NOTE: do NOT wait for the child here. It may be stuck writing to
	   the pipe and WFS will hang
	  */
	res = wfs_xfs_read_line (pipe_fd[PIPE_R], buffer, &child_xfschk, sizeof (buffer) );

	close (pipe_fd[PIPE_R]);
	close (pipe_fd[PIPE_W]);
	wfs_wait_for_child (&child_xfschk);
	free_array_deep_copy (args_copy,
		sizeof (args) / sizeof (args[0]));
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	if ( res > 0 )
	{
		/* something was read. Filesystem is inconsistent. */
		return WFS_FSHASERROR;
	}

	if ( sig_recvd != 0 )
	{
		return WFS_SIGNAL;
	}
	return WFS_SUCCESS;
}

/* ======================================================================== */

/**
 * Checks if the XFS filesystem is dirty (has unsaved changes).
 * \param wfs_fs The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_xfs_is_dirty (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
#endif
{
	/* Don't know how to get this information *
	return WFS_SUCCESS;*/
	return wfs_xfs_check_err (wfs_fs);
}

/* ======================================================================== */

/**
 * Checks if the given XFS filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_xfs_chk_mount (
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
 * Opens a XFS filesystem on the given device.
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
wfs_xfs_open_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t * const wfs_fs,
	const wfs_fsdata_t * const data WFS_ATTR ((unused)))
#else
	wfs_fs, data)
	wfs_fsid_t* const wfs_fs;
	const wfs_fsdata_t * const data WFS_ATTR ((unused));
#endif
{
	int res = 0;
	wfs_errcode_t mnt_ret;
	int pipe_fd[2];
	child_id_t child_xfsdb;
	wfs_errcode_t ret_child;
	int fs_fd;
	unsigned char xfs_sig[4];
	ssize_t sig_read;
#define FSNAME_POS_OPEN 9
	const char * args[] = { "xfs_db", "-i", "-c",
		"sb 0", "-c",
		"print", "-c", "quit",
		"--", NULL, NULL }; /* xfs_db -c 'sb 0' -c print dev_name */
	char ** args_copy = NULL;
	const char * const wfs_xfs_xfs_db_env[] = { "LC_ALL=C", NULL };
	char ** wfs_xfs_xfs_db_env_copy = NULL;
	char buffer[WFS_XFSBUFSIZE];
	int blocksize_set = 0, agblocks_set = 0, inprogress_found = 0,
		used_inodes_set = 0, free_blocks_set = 0;
	char *pos1 = NULL, *pos2 = NULL, *pos3 = NULL, *pos4 = NULL, *pos5 = NULL;
	int is_rw;
	unsigned long long int inprogress;
	size_t namelen;
	wfs_errcode_t error = 0;
	struct wfs_xfs * xxfs;
	wfs_errcode_t * error_ret;
	wfs_errcode_t mnt_error;

	if ( wfs_fs == NULL )
	{
		return WFS_BADPARAM;
	}
	if ( wfs_fs->fsname == NULL )
	{
		return WFS_BADPARAM;
	}
	error_ret = (wfs_errcode_t *) wfs_fs->fs_error;
	wfs_fs->whichfs = WFS_CURR_FS_NONE;

	WFS_SET_ERRNO (0);
	xxfs = (struct wfs_xfs *) malloc (sizeof (struct wfs_xfs));
	if ( xxfs == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}
	xxfs->mnt_point = NULL;
	namelen = strlen (wfs_fs->fsname);

	/* first check if 0x58465342 signature present, to save resources if different filesystem */
	WFS_SET_ERRNO (0);
	fs_fd = open64 (wfs_fs->fsname, O_RDONLY
#ifdef O_BINARY
		| O_BINARY
#endif
		);
	if ( (fs_fd < 0)
#ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
#endif
	   )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		free (xxfs);
		return WFS_OPENFS;
	}
	sig_read = read (fs_fd, xfs_sig, 4);
	close (fs_fd);
	if ( sig_read != 4 )
	{
		free (xxfs);
		return WFS_OPENFS;
	}
	if ((xfs_sig[0] != 0x58) || (xfs_sig[1] != 0x46)
		|| (xfs_sig[2] != 0x53) || (xfs_sig[3] != 0x42))
	{
		free (xxfs);
		return WFS_OPENFS;
	}

	WFS_SET_ERRNO (0);
	xxfs->dev_name = WFS_STRDUP (wfs_fs->fsname);
	if ( xxfs->dev_name == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		free (xxfs);
		return WFS_MALLOC;
	}
	/* Copy the file system name into the right places */
	WFS_SET_ERRNO (0);
	args[FSNAME_POS_OPEN] = xxfs->dev_name;
	args_copy = deep_copy_array (args, sizeof (args) / sizeof (args[0]));
	if ( args_copy == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		free (xxfs->dev_name);
		xxfs->dev_name = NULL;
		free (xxfs);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	WFS_SET_ERRNO (0);
	wfs_xfs_xfs_db_env_copy = deep_copy_array (wfs_xfs_xfs_db_env,
		sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
	if ( wfs_xfs_xfs_db_env_copy == NULL )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
		free_array_deep_copy (args_copy,
			sizeof (args) / sizeof (args[0]));
		free (xxfs->dev_name);
		free (xxfs);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_MALLOC;
	}

	/* Open the pipe for communications */
	WFS_SET_ERRNO (0);
	res = pipe (pipe_fd);
	if ( (res < 0)
#ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
#endif
		 )
	{
		error = WFS_GET_ERRNO_OR_DEFAULT (1L);
		free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
			sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
		free_array_deep_copy (args_copy,
			sizeof (args) / sizeof (args[0]));
		free (xxfs->dev_name);
		xxfs->dev_name = NULL;
		free (xxfs);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_PIPEERR;
	}
	/* In case of child error the parent process
	   will hang waiting for data from a closed pipe.
	*/
	/* NOTE: we shouldn't do this. The child should wait with printing
	   while we are processing the data. Non-blocking mode should be enabled only
	   when no output is an option.
	fcntl (pipe_fd[PIPE_R], F_SETFL, fcntl (pipe_fd[PIPE_R], F_GETFL) | O_NONBLOCK );
	fcntl (pipe_fd[PIPE_W], F_SETFL, fcntl (pipe_fd[PIPE_W], F_GETFL) | O_NONBLOCK );
	*/

	WFS_SET_ERRNO (0);
#ifdef HAVE_SIGNAL_H
	sigchld_recvd = 0;
#endif
	child_xfsdb.program_name = args_copy[0];
	child_xfsdb.args = args_copy;
	child_xfsdb.child_env = wfs_xfs_xfs_db_env_copy;
	child_xfsdb.stdin_fd = -1;
	child_xfsdb.stdout_fd = pipe_fd[PIPE_W];
	child_xfsdb.stderr_fd = pipe_fd[PIPE_W];
	ret_child = wfs_create_child (&child_xfsdb);
	if ( ret_child != WFS_SUCCESS )
	{
		/* error */
		error = WFS_GET_ERRNO_OR_DEFAULT (1L);
		free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
			sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
		free_array_deep_copy (args_copy,
			sizeof (args) / sizeof (args[0]));
		free (xxfs->dev_name);
		xxfs->dev_name = NULL;
		free (xxfs);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_FORKERR;
	}
	/* parent */
	wfs_wait_for_child (&child_xfsdb);

	while ( ((blocksize_set == 0) || (agblocks_set == 0)
		|| (inprogress_found == 0) || (used_inodes_set == 0)
		|| (free_blocks_set == 0)) && (sig_recvd == 0) )
	{
		/* Sample output:
			magicnum = 0x58465342
			blocksize = 4096
			[...]
			rextsize = 1
			agblocks = 4096
			agcount = 1
		*/
		res = wfs_xfs_read_line (pipe_fd[PIPE_R], buffer,
			&child_xfsdb, sizeof (buffer) );
#ifdef HAVE_ERRNO_H
		/*if ( errno == EAGAIN ) continue;*/
#endif
		if ( (res < 0) || (sig_recvd != 0) /*|| (sigchld_recvd != 0)*/
#ifdef HAVE_ERRNO_H
/*			|| ( errno != 0 )*/
#endif
			)
		{
			/* NOTE: waiting for the child has already been taken care of. */
			close (pipe_fd[PIPE_R]);
			close (pipe_fd[PIPE_W]);
			free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
				sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
			free_array_deep_copy (args_copy,
				sizeof (args) / sizeof (args[0]));
			free (xxfs->dev_name);
			xxfs->dev_name = NULL;
			free (xxfs);
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_OPENFS;
		}

		buffer[sizeof (buffer)-1] = '\0';
#define err_str "xfs_db:"
		if ( strstr (buffer, err_str) != NULL )
		{
			/* probably an error occurred, but this function will
				wait for more data forever, so quit here */
			/* NOTE: waiting for the child has already been taken care of. */
			close (pipe_fd[PIPE_R]);
			close (pipe_fd[PIPE_W]);
			free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
				sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
			free_array_deep_copy (args_copy,
				sizeof (args) / sizeof (args[0]));
			free (xxfs->dev_name);
			xxfs->dev_name = NULL;
			free (xxfs);
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_OPENFS;
		}
#define search1 "blocksize = "
#define search2 "agblocks = "
#define search3 "inprogress = "
#define search4 "icount = "
#define search5 "fdblocks = "
		pos1 = strstr (buffer, search1);
		pos2 = strstr (buffer, search2);
		pos3 = strstr (buffer, search3);
		pos4 = strstr (buffer, search4);
		pos5 = strstr (buffer, search5);
		if ( (pos1 == NULL) && (pos2 == NULL)
			&& (pos3 == NULL) && (pos4 == NULL)
			&& (pos5 == NULL) )
		{
			continue;
		}
		if ( pos1 != NULL )
		{
			xxfs->wfs_xfs_blocksize = 0;
			res = sscanf (pos1, search1 "%u", (unsigned int *)&(xxfs->wfs_xfs_blocksize) );
			if ( res != 1 )
			{
				/* NOTE: waiting for the child has already been taken care of. */
				close (pipe_fd[PIPE_R]);
				close (pipe_fd[PIPE_W]);
				free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
					sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
				free_array_deep_copy (args_copy,
					sizeof (args) / sizeof (args[0]));
				free (xxfs->dev_name);
				xxfs->dev_name = NULL;
				free (xxfs);
				if ( error_ret != NULL )
				{
					*error_ret = error;
				}
				return WFS_OPENFS;
			}
			blocksize_set = 1;
		}
		if ( pos2 != NULL )
		{
			res = sscanf (pos2, search2 "%llu", &(xxfs->wfs_xfs_agblocks) );
			if ( res != 1 )
			{
				/* NOTE: waiting for the child has already been taken care of. */
				close (pipe_fd[PIPE_R]);
				close (pipe_fd[PIPE_W]);
				free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
					sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
				free_array_deep_copy (args_copy,
					sizeof (args) / sizeof (args[0]));
				free (xxfs->dev_name);
				xxfs->dev_name = NULL;
				free (xxfs);
				if ( error_ret != NULL )
				{
					*error_ret = error;
				}
				return WFS_OPENFS;
			}
			agblocks_set = 1;
		}
		if ( pos3 != NULL )
		{
			res = sscanf (pos3, search3 "%llu", &inprogress );
			if ( res != 1 )
			{
				/* NOTE: waiting for the child has already been taken care of. */
				close (pipe_fd[PIPE_R]);
				close (pipe_fd[PIPE_W]);
				free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
					sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
				free_array_deep_copy (args_copy,
					sizeof (args) / sizeof (args[0]));
				free (xxfs->dev_name);
				xxfs->dev_name = NULL;
				free (xxfs);
				if ( error_ret != NULL )
				{
					*error_ret = error;
				}
				return WFS_OPENFS;
			}
			if ( inprogress != 0 )
			{
				/* NOTE: waiting for the child has already been taken care of. */
				close (pipe_fd[PIPE_R]);
				close (pipe_fd[PIPE_W]);
				free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
					sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
				free_array_deep_copy (args_copy,
					sizeof (args) / sizeof (args[0]));
				free (xxfs->dev_name);
				xxfs->dev_name = NULL;
				free (xxfs);
				if ( error_ret != NULL )
				{
					*error_ret = error;
				}
				return WFS_OPENFS;
			}
			inprogress_found = 1;
		}
		if ( pos4 != NULL )
		{
			res = sscanf (pos4, search4 "%llu", &(xxfs->inodes_used) );
			if ( res != 1 )
			{
				/* NOTE: waiting for the child has already been taken care of. */
				close (pipe_fd[PIPE_R]);
				close (pipe_fd[PIPE_W]);
				free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
					sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
				free_array_deep_copy (args_copy,
					sizeof (args) / sizeof (args[0]));
				free (xxfs->dev_name);
				xxfs->dev_name = NULL;
				free (xxfs);
				if ( error_ret != NULL )
				{
					*error_ret = error;
				}
				return WFS_OPENFS;
			}
			used_inodes_set = 1;
		}
		if ( pos5 != NULL )
		{
			res = sscanf (pos5, search5 "%llu", &(xxfs->free_blocks) );
			if ( res != 1 )
			{
				/* NOTE: waiting for the child has already been taken care of. */
				close (pipe_fd[PIPE_R]);
				close (pipe_fd[PIPE_W]);
				free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
					sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
				free_array_deep_copy (args_copy,
					sizeof (args) / sizeof (args[0]));
				free (xxfs->dev_name);
				xxfs->dev_name = NULL;
				free (xxfs);
				if ( error_ret != NULL )
				{
					*error_ret = error;
				}
				return WFS_OPENFS;
			}
			free_blocks_set = 1;
		}
	}	/* while */
	close (pipe_fd[PIPE_R]);
	close (pipe_fd[PIPE_W]);
	/* NOTE: waiting for the child has already been taken care of. */

	if (sig_recvd != 0)
	{
		free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
			sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
		free_array_deep_copy (args_copy,
			sizeof (args) / sizeof (args[0]));
		free (xxfs->dev_name);
		xxfs->dev_name = NULL;
		free (xxfs);
		if ( error_ret != NULL )
		{
			*error_ret = error;
		}
		return WFS_SIGNAL;
	}
	/* just in case, after execvp */
	strncpy (xxfs->dev_name, wfs_fs->fsname, namelen + 1);

	mnt_ret = wfs_get_mnt_point (wfs_fs->fsname, &mnt_error,
		buffer, sizeof (buffer), &is_rw);
	if ( (mnt_ret == WFS_SUCCESS) && (buffer[0] != '\0' /*strlen (buffer) > 0*/) )
	{
		WFS_SET_ERRNO (0);
		buffer[sizeof (buffer)-1] = '\0';
		xxfs->mnt_point = WFS_STRDUP (buffer);
		if ( xxfs->mnt_point == NULL )
		{
			error = WFS_GET_ERRNO_OR_DEFAULT (12L);	/* ENOMEM */
			xxfs->wfs_xfs_agblocks = 0;
			xxfs->wfs_xfs_blocksize = 0;
			free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
				sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
			free_array_deep_copy (args_copy,
				sizeof (args) / sizeof (args[0]));
			free (xxfs->dev_name);
			xxfs->dev_name = NULL;
			free (xxfs);
			if ( error_ret != NULL )
			{
				*error_ret = error;
			}
			return WFS_MALLOC;
		}
	}

	free_array_deep_copy (wfs_xfs_xfs_db_env_copy,
		sizeof (wfs_xfs_xfs_db_env) / sizeof (wfs_xfs_xfs_db_env[0]));
	free_array_deep_copy (args_copy,
		sizeof (args) / sizeof (args[0]));
	if ( error_ret != NULL )
	{
		*error_ret = error;
	}
	if ( sig_recvd != 0 )
	{
		free (xxfs->dev_name);
		xxfs->dev_name = NULL;
		free (xxfs);
		return WFS_SIGNAL;
	}
	wfs_fs->whichfs = WFS_CURR_FS_XFS;
	wfs_fs->fs_backend = xxfs;
	return WFS_SUCCESS;
}

/* ======================================================================== */

/**
 * Closes the XFS filesystem.
 * \param wfs_fs The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_xfs_close_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	wfs_fsid_t wfs_fs;
#endif
{
	struct wfs_xfs * xxfs;
	wfs_errcode_t * error_ret;

	xxfs = (struct wfs_xfs *) wfs_fs.fs_backend;
	error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
	WFS_SET_ERRNO (0);
	if ( xxfs != NULL )
	{
		free (xxfs->mnt_point);
		free (xxfs->dev_name);
		free (xxfs);
	}
#ifdef HAVE_ERRNO_H
	if ( errno != 0 )
	{
		if ( error_ret != NULL )
		{
			*error_ret = errno;
		}
		return WFS_FSCLOSE;
	}
	else
#endif
	{
		return WFS_SUCCESS;
	}
}

/* ======================================================================== */

/**
 * Flushes the XFS filesystem.
 * \param wfs_fs The XFS filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t
wfs_xfs_flush_fs (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs WFS_ATTR ((unused)) )
#else
	wfs_fs )
	const wfs_fsid_t wfs_fs WFS_ATTR ((unused));
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
void wfs_xfs_print_version (WFS_VOID)
{
	printf ( "XFS: <?>\n");
}

/* ======================================================================== */

/**
 * Get the preferred size of the error variable.
 * \return the preferred size of the error variable.
 */
size_t wfs_xfs_get_err_size (WFS_VOID)
{
	return sizeof (wfs_errcode_t);
}

/* ======================================================================== */

/**
 * Initialize the library.
 */
void wfs_xfs_init (WFS_VOID)
{
	/* nothing needed to do here */
}

/* ======================================================================== */

/**
 * De-initialize the library.
 */
void wfs_xfs_deinit (WFS_VOID)
{
	/* nothing needed to do here */
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
wfs_xfs_show_error (
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
