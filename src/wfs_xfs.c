/*
 * A program for secure cleaning of free space on filesystems.
 *	-- XFS file system-specific functions.
 *
 * Copyright (C) 2007-2011 Bogdan Drozdowski, bogdandr (at) op.pl
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

#define _FILE_OFFSET_BITS 64
#define _LARGEFILE64_SOURCE 1
#define _BSD_SOURCE /* fsync() */
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
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  ifdef HAVE_TIME_H
#   include <time.h>
#  endif
# endif
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
# include <unistd.h>	/* access(), close(), open(), sync(), select() (the old way) */
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifdef HAVE_LIMITS_H
# include <limits.h>	/* PIPE_BUF */
#endif

/* redefine the inline sig function from hfsp, each time with a different name */
extern unsigned long int wfs_xfs_sig(char c0, char c1, char c2, char c3);
#define sig(a,b,c,d) wfs_xfs_sig(a,b,c,d)

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

#define MAX_SELECT_FAILS 5
#define WFS_XFS_MAX_SELECT_SECONDS 10

/*#define XFS_HAS_SHARED_BLOCKS 1 */

static char wfs_xfs_xfs_db[] = "xfs_db";
static char wfs_xfs_xfs_db_opt_ro[] = "-i";
static char wfs_xfs_xfs_db_opt_cmd[] = "-c";
static char wfs_xfs_xfs_db_opt_end[] = "--";
static char wfs_xfs_xfs_db_cmd_freespace[] = "freesp -d";
static char wfs_xfs_xfs_db_cmd_quit[] = "quit";
static char wfs_xfs_xfs_db_cmd_blocks[] = "blockget -n";
static char wfs_xfs_xfs_db_cmd_check[] = "ncheck";
static char wfs_xfs_xfs_db_cmd_superblock_reset[] = "sb 0";
static char wfs_xfs_xfs_db_cmd_print[] = "print";
static char wfs_xfs_xfs_check[] = "xfs_check";
static const char wfs_xfs_xfs_check_opt_init_default[] = "  ";
static char wfs_xfs_xfs_check_opt_init[] = "  ";
static char wfs_xfs_xfs_freeze[] = "xfs_freeze";
static char wfs_xfs_xfs_freeze_opt_freeze[] = "-f";
static char wfs_xfs_xfs_freeze_opt_unfreeze[] = "-u";

/* ======================================================================== */

#ifndef WFS_ANSIC
static int WFS_ATTR ((nonnull)) WFS_ATTR ((warn_unused_result)) wfs_xfs_read_line
	PARAMS ((int fd, char * const buf, struct child_id * const child, const size_t bufsize));
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
static int WFS_ATTR ((warn_unused_result))
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_xfs_read_line (
#ifdef WFS_ANSIC
	int fd, char * const buf, struct child_id * const child, const size_t bufsize)
#else
	fd, buf, child, bufsize)
	int fd;
	char * const buf;
	struct child_id * const child;
	const size_t bufsize;
#endif
{
	/* read just 1 line */
	int res = 0;
	int select_fails = 0;
	int bytes_read = -1;
	struct timeval tv;
	fd_set set;
#ifndef HAVE_MEMSET
	int offset;
#endif

	if ( (buf == NULL) || (child == NULL) || (bufsize == 0) || (fd < 0) )
	{
		return -1;
	}

#ifdef HAVE_MEMSET
	memset (buf, 0, bufsize);
#else
	for ( offset = 0; offset < bufsize; offset++ )
	{
		buf[offset] = '\0';
	}
#endif
	do
	{
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
#if (((defined HAVE_SYS_SELECT_H) || (((defined TIME_WITH_SYS_TIME)	\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))		\
	&& (defined HAVE_UNISTD_H)))				\
	&& (defined HAVE_SELECT))
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
#if (((defined HAVE_SYS_SELECT_H) || (((defined TIME_WITH_SYS_TIME)	\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))		\
	&& (defined HAVE_UNISTD_H)))				\
	&& (defined HAVE_SELECT))
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
			if ( select_fails > MAX_SELECT_FAILS )
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
static void flush_pipe_output PARAMS ((const int fd));
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
		write (fd, "\n", 1);
	}
# if (defined HAVE_FSYNC) && (defined HAVE_UNISTD_H)
	fsync (fd);
# endif
}

# ifndef WFS_ANSIC
static void flush_pipe_input PARAMS ((const int fd));
# endif

/**
 * Reads the given pipe until end of data is reached.
 * @param fd The pipe file descriptor to empty.
 */
static void
flush_pipe_input (
# ifdef WFS_ANSIC
	const int fd)
# else
	fd )
	const int fd;
# endif
{
	int r;
	char c;
	/* set non-blocking mode to quit as soon as the pipe is empty */
# ifdef HAVE_FCNTL_H
	r = fcntl (fd, F_SETFL, fcntl (fd, F_GETFL) | O_NONBLOCK );
	if ( r != 0 ) return;
# endif
	do
	{
		r = read (fd, &c, 1);
	} while (r == 1);
	/* set blocking mode again */
# ifdef HAVE_FCNTL_H
	fcntl (fd, F_SETFL, fcntl (fd, F_GETFL) & ~ O_NONBLOCK );
# endif
}
#endif /* WFS_WANT_PART */

#ifdef WFS_WANT_UNRM
/**
 * Starts recursive directory search for deleted inodes
 *	and undelete data on the given XFS filesystem.
 * \param FS The filesystem.
 * \param node Filesystem element at which to start.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result))
wfs_xfs_wipe_unrm (
# ifdef WFS_ANSIC
	const wfs_fsid_t FS WFS_ATTR ((unused)) )
# else
	FS )
	const wfs_fsid_t FS WFS_ATTR ((unused));
# endif
{
	unsigned int prev_percent = 0;
	/*
	 * The XFS has no undelete capability.
	 * Directories' sizes are multiples of block size, so can't wipe
	 *  unused space in these blocks.
	 */
	show_progress (PROGRESS_UNRM, 100, &prev_percent);
	return WFS_SUCCESS;
}
#endif /* WFS_WANT_UNRM */

#if (defined WFS_WANT_WFS) || (defined WFS_WANT_PART)

# ifndef WFS_ANSIC
static size_t WFS_ATTR ((warn_unused_result)) wfs_xfs_get_block_size
	PARAMS ((const wfs_fsid_t FS));
# endif

/**
 * Returns the buffer size needed to work on the
 *	smallest physical unit on a XFS filesystem.
 * \param FS The filesystem.
 * \return Block size on the filesystem.
 */
static size_t WFS_ATTR ((warn_unused_result))
wfs_xfs_get_block_size (
# ifdef WFS_ANSIC
	const wfs_fsid_t FS )
# else
	FS )
	const wfs_fsid_t FS;
# endif
{
	return FS.xxfs.wfs_xfs_blocksize;
}
#endif /* (defined WFS_WANT_WFS) || (defined WFS_WANT_PART) */


#ifdef WFS_WANT_WFS
/**
 * Wipes the free space on the given XFS filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result))
# ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
# endif
wfs_xfs_wipe_fs	(
# ifdef WFS_ANSIC
	const wfs_fsid_t FS, error_type * const error )
# else
	FS, error )
	const wfs_fsid_t FS;
	error_type * const error;
# endif
{
	unsigned long int i;
	int res;
	int pipe_fd[2];
	int fs_fd;
	struct child_id child_freeze, child_unfreeze, child_xfsdb;
	errcode_enum ret_child;
	/* 	 xfs_freeze -f (freeze) | -u (unfreeze) mount-point */
# define FSNAME_POS_FREEZE 2
	char * args_freeze[] = { wfs_xfs_xfs_freeze, wfs_xfs_xfs_freeze_opt_freeze, NULL, NULL };
# define FSNAME_POS_UNFREEZE 2
	char * args_unfreeze[] = { wfs_xfs_xfs_freeze, wfs_xfs_xfs_freeze_opt_unfreeze, NULL, NULL };
	/*	 xfs_db  -c 'freesp -d' dev_name */
# define FSNAME_POS_FREESP 7
	char * args_db[] = { wfs_xfs_xfs_db, wfs_xfs_xfs_db_opt_ro, wfs_xfs_xfs_db_opt_cmd,
		wfs_xfs_xfs_db_cmd_freespace, wfs_xfs_xfs_db_opt_cmd, wfs_xfs_xfs_db_cmd_quit,
		wfs_xfs_xfs_db_opt_end, NULL, NULL };
	char read_buffer[WFS_XFSBUFSIZE];
	unsigned long long int agno, agoff, length;
	unsigned char * buffer;
	unsigned long long int j;
	int selected[NPAT];
	errcode_enum ret_wfs = WFS_SUCCESS;
	unsigned int prev_percent = 0;
	unsigned long long int curr_block = 0;
	size_t mnt_point_len;
	size_t dev_name_len;

	if ( error == NULL )
	{
		show_progress (PROGRESS_WFS, 100, &prev_percent);
		return WFS_BADPARAM;
	}

	/* Copy the file system name info the right places */
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	dev_name_len = strlen (FS.xxfs.dev_name);
	args_db[FSNAME_POS_FREESP] = (char *) malloc ( dev_name_len + 1 );
	if ( args_db[FSNAME_POS_FREESP] == NULL )
	{
# ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
# else
		error->errcode.gerror = 12L;	/* ENOMEM */
# endif
		show_progress (PROGRESS_WFS, 100, &prev_percent);
		return WFS_MALLOC;
	}
	strncpy ( args_db[FSNAME_POS_FREESP], FS.xxfs.dev_name, dev_name_len + 1 );
	/* we need the mount point here, not the FS device */
	if ( FS.xxfs.mnt_point != NULL )
	{
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		mnt_point_len = strlen (FS.xxfs.mnt_point);
		args_freeze[FSNAME_POS_FREEZE] = (char *) malloc ( mnt_point_len + 1 );
		if ( args_freeze[FSNAME_POS_FREEZE] == NULL )
		{
# ifdef HAVE_ERRNO_H
			error->errcode.gerror = errno;
# else
			error->errcode.gerror = 12L;	/* ENOMEM */
# endif
			free (args_db[FSNAME_POS_FREESP]);
			show_progress (PROGRESS_WFS, 100, &prev_percent);
			return WFS_MALLOC;
		}
		strncpy ( args_freeze[FSNAME_POS_FREEZE], FS.xxfs.mnt_point, mnt_point_len + 1);
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		args_unfreeze[FSNAME_POS_UNFREEZE] = (char *) malloc ( mnt_point_len + 1 );
		if ( args_unfreeze[FSNAME_POS_UNFREEZE] == NULL )
		{
# ifdef HAVE_ERRNO_H
			error->errcode.gerror = errno;
# else
			error->errcode.gerror = 12L;	/* ENOMEM */
# endif
			free (args_freeze[FSNAME_POS_FREEZE]);
			free (args_db[FSNAME_POS_FREESP]);
			show_progress (PROGRESS_WFS, 100, &prev_percent);
			return WFS_MALLOC;
		}
		strncpy ( args_unfreeze[FSNAME_POS_UNFREEZE], FS.xxfs.mnt_point, mnt_point_len + 1 );
	}
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	buffer = (unsigned char *) malloc ( wfs_xfs_get_block_size (FS) );
	if ( buffer == NULL )
	{
# ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
# else
		error->errcode.gerror = 12L;	/* ENOMEM */
# endif
		free (args_unfreeze[FSNAME_POS_UNFREEZE]);
		free (args_freeze[FSNAME_POS_FREEZE]);
		free (args_db[FSNAME_POS_FREESP]);
		show_progress (PROGRESS_WFS, 100, &prev_percent);
		return WFS_MALLOC;
	}

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	res = pipe (pipe_fd);
	if ( (res < 0)
# ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
# endif
		 )
	{
# ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
# else
		error->errcode.gerror = 1L;
# endif
		free (buffer);
		free (args_unfreeze[FSNAME_POS_UNFREEZE]);
		free (args_freeze[FSNAME_POS_FREEZE]);
		free (args_db[FSNAME_POS_FREESP]);
		show_progress (PROGRESS_WFS, 100, &prev_percent);
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

	if ( FS.xxfs.mnt_point != NULL )
	{
		/* Freeze the filesystem */
# ifdef HAVE_SIGNAL_H
		sigchld_recvd = 0;
# endif
		child_freeze.program_name = args_freeze[0];
		child_freeze.args = args_freeze;
		child_freeze.stdin_fd = -1;
		child_freeze.stdout_fd = -1;
		child_freeze.stderr_fd = -1;
		ret_child = wfs_create_child (&child_freeze);
		if ( ret_child != WFS_SUCCESS )
		{
			/* error */
# ifdef HAVE_ERRNO_H
			error->errcode.gerror = errno;
# else
			error->errcode.gerror = 1L;
# endif
			close (pipe_fd[PIPE_R]);
			close (pipe_fd[PIPE_W]);
			free (buffer);
			free (args_unfreeze[FSNAME_POS_UNFREEZE]);
			free (args_freeze[FSNAME_POS_FREEZE]);
			free (args_db[FSNAME_POS_FREESP]);
			show_progress (PROGRESS_WFS, 100, &prev_percent);
			return WFS_FORKERR;
		}
		/* parent */
		wfs_wait_for_child (&child_freeze);
	}	/* if ( FS.xxfs.mnt_point != NULL )  */

	/* parent, continued */
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
# ifdef HAVE_SIGNAL_H
	sigchld_recvd = 0;
# endif
	child_xfsdb.program_name = args_db[0];
	child_xfsdb.args = args_db;
	child_xfsdb.stdin_fd = -1;
	child_xfsdb.stdout_fd = pipe_fd[PIPE_W];
	child_xfsdb.stderr_fd = pipe_fd[PIPE_W];
	ret_child = wfs_create_child (&child_xfsdb);
	if ( ret_child != WFS_SUCCESS )
	{
		/* error */
# ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
# else
		error->errcode.gerror = 1L;
# endif
		/* can't return from here - have to un-freeze first */
		ret_wfs = WFS_FORKERR;
	}
	/* parent */
# ifdef HAVE_SLEEP
	sleep (1);
# else
	for (i=0; (i < (1<<30)) && (sig_recvd == 0); i++ );
# endif
	/* open the FS */
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	fs_fd = open64 (FS.xxfs.dev_name, O_WRONLY | O_EXCL
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
		res = wfs_xfs_read_line (pipe_fd[PIPE_R], read_buffer, &child_xfsdb, sizeof (read_buffer) );
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
		/* Disk offset = (agno * FS.xxfs.wfs_xfs_agblocks + agoff ) * \
			FS.xxfs.wfs_xfs_blocksize */
		/* Wiping loop */
		for ( i=0; (i < npasses) && (sig_recvd == 0); i++ )
		{
			/* NOTE: this must be inside */
			if ( lseek64 (fs_fd, (off64_t) (agno * FS.xxfs.wfs_xfs_agblocks + agoff) *
				wfs_xfs_get_block_size (FS), SEEK_SET ) !=
					(off64_t) (agno * FS.xxfs.wfs_xfs_agblocks + agoff) *
					wfs_xfs_get_block_size (FS)
				)
			{
				break;
			}
			fill_buffer ( i, buffer, wfs_xfs_get_block_size (FS), selected, FS );
			for ( j=0; (j < length) && (sig_recvd == 0); j++ )
			{
				if ( write (fs_fd, buffer, wfs_xfs_get_block_size (FS))
					!= (ssize_t) wfs_xfs_get_block_size (FS)
					)
				{
					ret_wfs = WFS_BLKWR;
					break;
				}
				/* Flush after each writing, if more than 1 overwriting
					needs to be done. Allow I/O bufferring (efficiency),
					if just one pass is needed. */
				if ( (npasses > 1) && (sig_recvd == 0) )
				{
					error->errcode.gerror = wfs_xfs_flush_fs (FS);
				}
			}
			if ( j < length ) break;
		}
		if ( (FS.zero_pass != 0) && (sig_recvd == 0) )
		{
			/* NOTE: this must be inside */
			if ( lseek64 (fs_fd, (off64_t) (agno * FS.xxfs.wfs_xfs_agblocks + agoff) *
				wfs_xfs_get_block_size (FS), SEEK_SET ) !=
					(off64_t) (agno * FS.xxfs.wfs_xfs_agblocks + agoff) *
					wfs_xfs_get_block_size (FS)
				)
			{
				break;
			}
			/* last pass with zeros: */
# ifdef HAVE_MEMSET
			memset ( buffer, 0, wfs_xfs_get_block_size (FS) );
# else
			for ( j=0; j < wfs_xfs_get_block_size (FS); j++ )
			{
				buffer[j] = '\0';
			}
# endif
			if ( sig_recvd == 0 )
			{
				for ( j=0; (j < length) && (sig_recvd == 0); j++ )
				{
					if ( write (fs_fd, buffer, wfs_xfs_get_block_size (FS))
						!= (ssize_t) wfs_xfs_get_block_size (FS)
					)
					{
						ret_wfs = WFS_BLKWR;
						break;
					}
					/* Flush after each writing, if more than 1 overwriting
					needs to be done. Allow I/O bufferring (efficiency),
					if just one pass is needed. */
					if ( (npasses > 1) && (sig_recvd == 0) )
					{
						error->errcode.gerror = wfs_xfs_flush_fs (FS);
					}
				}
				if ( j < length ) break;
			}
		}
		curr_block += length;
		if ( FS.xxfs.free_blocks > 0 )
		{
			show_progress (PROGRESS_WFS, (unsigned int) ((curr_block * 100)
				/(FS.xxfs.free_blocks)), &prev_percent);
		}
		if ( i < npasses ) break;
	}
	/* child stopped writing? something went wrong?
	close the FS and kill the child process
	*/

	close (fs_fd);
	wfs_wait_for_child (&child_xfsdb);
	show_progress (PROGRESS_WFS, 100, &prev_percent);

	if ( FS.xxfs.mnt_point != NULL )
	{
		/* un-freeze the filesystem */
# ifdef HAVE_SIGNAL_H
		sigchld_recvd = 0;
# endif
		child_unfreeze.program_name = args_unfreeze[0];
		child_unfreeze.args = args_unfreeze;
		child_unfreeze.stdin_fd = -1;
		child_unfreeze.stdout_fd = -1;
		child_unfreeze.stderr_fd = -1;
		ret_child = wfs_create_child (&child_unfreeze);
		if ( ret_child != WFS_SUCCESS )
		{
			/* error */
# ifdef HAVE_ERRNO_H
			error->errcode.gerror = errno;
# else
			error->errcode.gerror = 1L;
# endif
			ret_wfs = WFS_FORKERR;
		}
		/* parent */
		wfs_wait_for_child (&child_unfreeze);
	} /* if ( FS.xxfs.mnt_point != NULL ) */

	close (pipe_fd[PIPE_R]);
	close (pipe_fd[PIPE_W]);

	free (buffer);
	free (args_unfreeze[FSNAME_POS_UNFREEZE]);
	free (args_freeze[FSNAME_POS_FREEZE]);
	free (args_db[FSNAME_POS_FREESP]);
	if (sig_recvd != 0) return WFS_SIGNAL;
	return ret_wfs;
}
#endif /* WFS_WANT_WFS */

#ifdef WFS_WANT_PART
/**
 * Wipes the free space in partially used blocks on the given XFS filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result))
wfs_xfs_wipe_part (
# ifdef WFS_ANSIC
	const wfs_fsid_t FS
#  ifdef XFS_HAS_SHARED_BLOCKS
	WFS_ATTR ((unused))
#  endif
	, error_type * const error
#  ifdef XFS_HAS_SHARED_BLOCKS
	WFS_ATTR ((unused))
#  endif
	)
# else
	FS, error)
	const wfs_fsid_t FS
#  ifdef XFS_HAS_SHARED_BLOCKS
		WFS_ATTR ((unused))
#  endif
	;
	error_type * const error
#  ifdef XFS_HAS_SHARED_BLOCKS
		WFS_ATTR ((unused))
#  endif
	;
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
	errcode_enum ret_part = WFS_SUCCESS;
# ifndef XFS_HAS_SHARED_BLOCKS

	unsigned long int i;
	int res;
	int pipe_from_ino_db[2];
	int pipe_from_blk_db[2], pipe_to_blk_db[2];
	int fs_fd;
	struct child_id child_ncheck, child_xfsdb;
	errcode_enum ret_child;
	/*	 xfs_db   dev_name */
#  define FSNAME_POS_PART_NCHECK 9
	char * args_db_ncheck[] = { wfs_xfs_xfs_db, wfs_xfs_xfs_db_opt_ro, wfs_xfs_xfs_db_opt_cmd,
		wfs_xfs_xfs_db_cmd_blocks, wfs_xfs_xfs_db_opt_cmd, wfs_xfs_xfs_db_cmd_check,
		wfs_xfs_xfs_db_opt_cmd, wfs_xfs_xfs_db_cmd_quit, wfs_xfs_xfs_db_opt_end, NULL, NULL };
#  define FSNAME_POS_PART_DB 3
	char * args_db[] = { wfs_xfs_xfs_db, wfs_xfs_xfs_db_opt_ro, wfs_xfs_xfs_db_opt_end, NULL, NULL };
	char read_buffer[WFS_XFSBUFSIZE];
	char * pos1 = NULL;
	char * pos2 = NULL;
	unsigned char * buffer;
	int selected[NPAT];
	unsigned long long int inode, inode_size, start_block, number_of_blocks;
	int length_to_wipe;
	unsigned long long int trash;
	int got_mode_line, got_size_line;
	unsigned int mode;
	unsigned int offset;
	char inode_cmd[40];
	unsigned int prev_percent = 0;
	unsigned long long int curr_inode = 0;
	size_t dev_name_len;

	if ( error == NULL )
	{
		show_progress (PROGRESS_PART, 100, &prev_percent);
		return WFS_BADPARAM;
	}

	/* Copy the file system name info the right places */
#  ifdef HAVE_ERRNO_H
	errno = 0;
#  endif
	dev_name_len = strlen (FS.xxfs.dev_name);
	args_db[FSNAME_POS_PART_DB] = (char *) malloc ( dev_name_len + 1 );
	if ( args_db[FSNAME_POS_PART_DB] == NULL )
	{
#  ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#  else
		error->errcode.gerror = 12L;	/* ENOMEM */
#  endif
		show_progress (PROGRESS_PART, 100, &prev_percent);
		return WFS_MALLOC;
	}
	strncpy ( args_db[FSNAME_POS_PART_DB], FS.xxfs.dev_name, dev_name_len + 1 );

#  ifdef HAVE_ERRNO_H
	errno = 0;
#  endif
	args_db_ncheck[FSNAME_POS_PART_NCHECK] = (char *) malloc ( dev_name_len + 1 );
	if ( args_db_ncheck[FSNAME_POS_PART_NCHECK] == NULL )
	{
#  ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#  else
		error->errcode.gerror = 12L;	/* ENOMEM */
#  endif
		free (args_db[FSNAME_POS_PART_DB]);
		show_progress (PROGRESS_PART, 100, &prev_percent);
		return WFS_MALLOC;
	}
	strncpy ( args_db_ncheck[FSNAME_POS_PART_NCHECK], FS.xxfs.dev_name, dev_name_len + 1 );

#  ifdef HAVE_ERRNO_H
	errno = 0;
#  endif
	buffer = (unsigned char *) malloc ( wfs_xfs_get_block_size (FS) );
	if ( buffer == NULL )
	{
#  ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#  else
		error->errcode.gerror = 12L;	/* ENOMEM */
#  endif
		free (args_db_ncheck[FSNAME_POS_PART_NCHECK]);
		free (args_db[FSNAME_POS_PART_DB]);
		show_progress (PROGRESS_PART, 100, &prev_percent);
		return WFS_MALLOC;
	}

#  ifdef HAVE_ERRNO_H
	errno = 0;
#  endif
	res = pipe (pipe_from_ino_db);
	if ( (res < 0)
#  ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
#  endif
		 )
	{
#  ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#  else
		error->errcode.gerror = 1L;
#  endif
		free (buffer);
		free (args_db_ncheck[FSNAME_POS_PART_NCHECK]);
		free (args_db[FSNAME_POS_PART_DB]);
		show_progress (PROGRESS_PART, 100, &prev_percent);
		return WFS_PIPEERR;
	}

#  ifdef HAVE_ERRNO_H
	errno = 0;
#  endif
	res = pipe (pipe_to_blk_db);
	if ( (res < 0)
#  ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
#  endif
		 )
	{
#  ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#  else
		error->errcode.gerror = 1L;
#  endif
		close (pipe_from_ino_db[PIPE_R]);
		close (pipe_from_ino_db[PIPE_W]);
		free (buffer);
		free (args_db_ncheck[FSNAME_POS_PART_NCHECK]);
		free (args_db[FSNAME_POS_PART_DB]);
		show_progress (PROGRESS_PART, 100, &prev_percent);
		return WFS_PIPEERR;
	}

#  ifdef HAVE_ERRNO_H
	errno = 0;
#  endif
	res = pipe (pipe_from_blk_db);
	if ( (res < 0)
#  ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
#  endif
		 )
	{
#  ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#  else
		error->errcode.gerror = 1L;
#  endif
		close (pipe_from_ino_db[PIPE_R]);
		close (pipe_from_ino_db[PIPE_W]);
		close (pipe_to_blk_db[PIPE_R]);
		close (pipe_to_blk_db[PIPE_W]);
		free (buffer);
		free (args_db_ncheck[FSNAME_POS_PART_NCHECK]);
		free (args_db[FSNAME_POS_PART_DB]);
		show_progress (PROGRESS_PART, 100, &prev_percent);
		return WFS_PIPEERR;
	}

	/* open the first xfs_db process - it will read used inode's numbers */
#  ifdef HAVE_ERRNO_H
	errno = 0;
#  endif
#  ifdef HAVE_SIGNAL_H
	sigchld_recvd = 0;
#  endif
	child_ncheck.program_name = args_db_ncheck[0];
	child_ncheck.args = args_db_ncheck;
	child_ncheck.stdin_fd = -1;
	child_ncheck.stdout_fd = pipe_from_ino_db[PIPE_W];
	child_ncheck.stderr_fd = -1;
	ret_child = wfs_create_child (&child_ncheck);
	if ( ret_child != WFS_SUCCESS )
	{
		/* error */
#  ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#  else
		error->errcode.gerror = 1L;
#  endif
		close (pipe_from_ino_db[PIPE_R]);
		close (pipe_from_ino_db[PIPE_W]);
		close (pipe_to_blk_db[PIPE_R]);
		close (pipe_to_blk_db[PIPE_W]);
		close (pipe_from_blk_db[PIPE_R]);
		close (pipe_from_blk_db[PIPE_W]);
		free (buffer);
		free (args_db_ncheck[FSNAME_POS_PART_NCHECK]);
		free (args_db[FSNAME_POS_PART_DB]);
		show_progress (PROGRESS_PART, 100, &prev_percent);
		return WFS_FORKERR;
	}
	/* parent */
	/* open a second xfs_db process - this one will read inodes' block info */
#  ifdef HAVE_ERRNO_H
	errno = 0;
#  endif
#  ifdef HAVE_SIGNAL_H
	sigchld_recvd = 0;
#  endif
	child_xfsdb.program_name = args_db[0];
	child_xfsdb.args = args_db;
	child_xfsdb.stdin_fd = pipe_to_blk_db[PIPE_R];
	child_xfsdb.stdout_fd = pipe_from_blk_db[PIPE_W];
	child_xfsdb.stderr_fd = pipe_from_blk_db[PIPE_W];
	ret_child = wfs_create_child (&child_xfsdb);
	if ( ret_child != WFS_SUCCESS )
	{
		/* error */
#  ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#  else
		error->errcode.gerror = 1L;
#  endif
		close (pipe_from_ino_db[PIPE_R]);
		close (pipe_from_ino_db[PIPE_W]);
		wfs_wait_for_child (&child_ncheck);
		close (pipe_to_blk_db[PIPE_R]);
		close (pipe_to_blk_db[PIPE_W]);
		close (pipe_from_blk_db[PIPE_R]);
		close (pipe_from_blk_db[PIPE_W]);
		free (buffer);
		free (args_db_ncheck[FSNAME_POS_PART_NCHECK]);
		free (args_db[FSNAME_POS_PART_DB]);
		show_progress (PROGRESS_PART, 100, &prev_percent);
		return WFS_FORKERR;
	}
	/* parent */
	/* open the FS */
#  ifdef HAVE_ERRNO_H
	errno = 0;
#  endif
	fs_fd = open64 (FS.xxfs.dev_name, O_WRONLY | O_EXCL
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
			ret_part = WFS_INOREAD;
			break;
		}
		read_buffer[sizeof (read_buffer)-1] = '\0';
		res = sscanf ( read_buffer, " %llu", &inode );
		if ( res != 1 )
		{
			continue;	/* stop ony when child stops writing */
		}
		/* request inode data from the second xfs_db */
#  ifdef HAVE_SNPRINTF
		snprintf (inode_cmd, sizeof (inode_cmd)-1, "inode %llu\nprint\n", inode);
#  else
		sprintf (inode_cmd, "inode %llu\nprint\n", inode);
#  endif
		inode_cmd[sizeof (inode_cmd)-1] = '\0';
		res = write (pipe_to_blk_db[PIPE_W], inode_cmd, strlen (inode_cmd) );
		if ( res <= 0 )
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
		flush_pipe_input (pipe_from_blk_db[PIPE_R]);
		if ( (got_mode_line == 0) || (got_size_line == 0) )
		{
			ret_part = WFS_INOREAD;
			continue;
		}
		/* check inode mode */
		if ( ! S_ISREG (mode) ) continue;

		/* send "bmap -d" */
		res = write (pipe_to_blk_db[PIPE_W], "bmap -d\n", 8);
		if ( res <= 0 ) break;
		flush_pipe_output (pipe_to_blk_db[PIPE_W]);
		do
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
			read_buffer[sizeof (read_buffer)-1] = '\0';
			/* parse line into block numbers. Read line has data:
				data offset 0 startblock 1215 (0/1215) count 7 flag 0
			 */
			/* check for first line element */
			pos1 = strstr (read_buffer, "da");
			if ( pos1 == NULL ) pos1 = strstr (read_buffer, " d");
			if ( pos1 == NULL ) pos1 = strstr (read_buffer, "\rd");
			if ( pos1 == NULL ) pos1 = strstr (read_buffer, "\nd");
			if ( pos1 == NULL )
			{
				/* if missing, start reading again */
				res = 0;
				continue;
			}
			/* check for last line element */
			if ( strstr (read_buffer, "flag") == NULL )
			{
				/* if missing, but first is present, joing this reading
				   with the next one */
				strncpy (read_buffer, pos1, (size_t)(&read_buffer[sizeof (read_buffer)] - pos1));
				res = &read_buffer[sizeof (read_buffer)] - pos1;
				read_buffer[res] = '\0';
				continue;
			}
			res = 0;
			res = sscanf (pos1,
				"data offset %u startblock %llu (%llu/%llu) count %llu flag %u",
				&offset, &start_block, &trash, &trash, &number_of_blocks, &mode );
			/* flush input to get rid of the rest of inode info and 'xfs_db>' trash */
			flush_pipe_input (pipe_from_blk_db[PIPE_R]);
			if ( res != 6 )
			{
				/* line found, but cannot be parsed */
				break;
			}
			if ( offset > wfs_xfs_get_block_size (FS) ) continue;

			/* wipe the last block
			 * The length of the last part of the file in the last block is
			 * (inode_size+offset)%block_size, so we need to wipe
			 * block_size - [(inode_size+offset)%block_size] bytes
			 */
			/* NOTE: 'offset' is probably NOT the offset within a block at all */
			length_to_wipe = (int)wfs_xfs_get_block_size (FS)
				- (int)((inode_size/*+offset*/)%wfs_xfs_get_block_size (FS));
			if ( length_to_wipe <= 0 ) continue;
			for ( i=0; (i < npasses) && (sig_recvd == 0); i++ )
			{
				/* NOTE: this must be inside! */
				if ( lseek64 (fs_fd,
						(off64_t) (start_block * wfs_xfs_get_block_size (FS)
						+ inode_size),
						SEEK_SET )
					!= (off64_t) (start_block * wfs_xfs_get_block_size (FS)
						+ inode_size)
				   )
				{
					break;
				}
				fill_buffer ( i, buffer, wfs_xfs_get_block_size (FS), selected, FS );
				if ( write (fs_fd, buffer, (size_t)length_to_wipe) != length_to_wipe )
				{
					ret_part = WFS_BLKWR;
					break;
				}
				/* Flush after each writing, if more than 1 overwriting needs to be done.
				   Allow I/O bufferring (efficiency), if just one pass is needed. */
				if ( (npasses > 1) && (sig_recvd == 0) )
				{
					error->errcode.gerror = wfs_xfs_flush_fs (FS);
				}
				/* go back to writing position */
			}
			if ( (FS.zero_pass != 0) && (sig_recvd == 0) )
			{
				/* NOTE: this must be inside */
				if ( lseek64 (fs_fd,
						(off64_t) (start_block * wfs_xfs_get_block_size (FS)
						+ inode_size),
						SEEK_SET )
					!= (off64_t) (start_block * wfs_xfs_get_block_size (FS)
						+ inode_size)
				   )
				{
					break;
				}
				/* last pass with zeros: */
#  ifdef HAVE_MEMSET
				memset ( buffer, 0, wfs_xfs_get_block_size (FS) );
#  else
				for ( i=0; i < wfs_xfs_get_block_size (FS); i++ )
				{
					buffer[i] = '\0';
				}
#  endif
				if ( sig_recvd == 0 )
				{
					if ( write (fs_fd, buffer, (size_t)length_to_wipe)
						!= length_to_wipe )
					{
						ret_part = WFS_BLKWR;
						break;
					}
					/* Flush after each writing, if more than 1 overwriting needs
					 to be done.
					Allow I/O bufferring (efficiency), if just one pass is needed. */
					if ( (npasses > 1) && (sig_recvd == 0) )
					{
						error->errcode.gerror = wfs_xfs_flush_fs (FS);
					}
				}
			}
			curr_inode++;
			if ( FS.xxfs.inodes_used > 0 )
			{
				show_progress (PROGRESS_PART, (unsigned int) ((curr_inode * 100)
					/(FS.xxfs.inodes_used)), &prev_percent);
			}
			break;
		} while (sig_recvd == 0);
	} /* while: reading inode-file */
	show_progress (PROGRESS_PART, 100, &prev_percent);
	write (pipe_to_blk_db[PIPE_W], "quit\n", 5);
	close (pipe_to_blk_db[PIPE_R]);
	close (pipe_to_blk_db[PIPE_W]);

	/* child stopped writing? something went wrong?
	   close the FS and kill the child process
	 */
	if ( fs_fd >= 0 ) close (fs_fd);
	wfs_wait_for_child (&child_xfsdb);
	wfs_wait_for_child (&child_ncheck);

	close (pipe_from_ino_db[PIPE_R]);
	close (pipe_from_ino_db[PIPE_W]);
	close (pipe_from_blk_db[PIPE_R]);
	close (pipe_from_blk_db[PIPE_W]);

	free (buffer);
	free (args_db_ncheck[FSNAME_POS_PART_NCHECK]);
	free (args_db[FSNAME_POS_PART_DB]);
	if (sig_recvd != 0) return WFS_SIGNAL;
# endif /* XFS_HAS_SHARED_BLOCKS */
	return ret_part;
}
#endif /* WFS_WANT_PART */

/**
 * Checks if the XFS filesystem has errors.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_xfs_check_err (
#ifdef WFS_ANSIC
	const wfs_fsid_t FS, error_type * const error )
#else
	FS, error )
	const wfs_fsid_t FS;
	error_type * const error;
#endif
{
	/* Requires xfs_db! No output expected.	*/
	int res = 0;
	int pipe_fd[2];
	struct child_id child_xfschk;
	errcode_enum ret_child;
#define FSNAME_POS_CHECK 2
	char * args[] = { wfs_xfs_xfs_check, wfs_xfs_xfs_check_opt_init,
		NULL, NULL }; /* xfs_check [-f] dev/file */
	char buffer[WFS_XFSBUFSIZE];
	size_t dev_name_len;

#ifdef HAVE_STAT_H
	struct stat s;

	if ( stat (FS.xxfs.dev_name, &s) >= 0 )
	{
		if ( S_ISREG (s.st_mode) )
		{
			strcpy (args[1], "-f");
		}
	}
#endif

	/* Re-set the parameter that may have been overwritten: */
	strncpy (wfs_xfs_xfs_check_opt_init, wfs_xfs_xfs_check_opt_init_default,
		sizeof (wfs_xfs_xfs_check_opt_init));
	/* Copy the file system name info the right places */
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	dev_name_len = strlen (FS.xxfs.dev_name);
	args[FSNAME_POS_CHECK] = (char *) malloc ( dev_name_len + 1 );
	if ( args[FSNAME_POS_CHECK] == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		return WFS_MALLOC;
	}
	strncpy ( args[FSNAME_POS_CHECK], FS.xxfs.dev_name, dev_name_len + 1 );
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	res = pipe (pipe_fd);
	if ( (res < 0)
#ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
#endif
		 )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 1L;
#endif
		free (args[FSNAME_POS_CHECK]);
		return WFS_PIPEERR;
	}

	/* This is required. In case of child error the parent process
	   will hang waiting for data from a closed pipe.
	   NOTE: no output is possible, so non-blocking mode is required.
	*/
	fcntl (pipe_fd[PIPE_R], F_SETFL, fcntl (pipe_fd[PIPE_R], F_GETFL) | O_NONBLOCK );
	fcntl (pipe_fd[PIPE_W], F_SETFL, fcntl (pipe_fd[PIPE_W], F_GETFL) | O_NONBLOCK );

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
#ifdef HAVE_SIGNAL_H
	sigchld_recvd = 0;
#endif
	child_xfschk.program_name = args[0];
	child_xfschk.args = args;
	child_xfschk.stdin_fd = -1;
	child_xfschk.stdout_fd = pipe_fd[PIPE_W];
	child_xfschk.stderr_fd = pipe_fd[PIPE_W];
	ret_child = wfs_create_child (&child_xfschk);
	if ( ret_child != WFS_SUCCESS )
	{
		/* error */
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 1L;
#endif
		close (pipe_fd[PIPE_R]);
		close (pipe_fd[PIPE_W]);
		free (args[FSNAME_POS_CHECK]);
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
	free (args[FSNAME_POS_CHECK]);
	if ( res > 0 )
	{
		/* something was read. Filesystem is inconsistent. */
		return WFS_FSHASERROR;
	}

	if (sig_recvd != 0) return WFS_SIGNAL;
	return WFS_SUCCESS;
}

/**
 * Checks if the XFS filesystem is dirty (has unsaved changes).
 * \param FS The filesystem.
 * \return 0 if clean, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_xfs_is_dirty (
#ifdef WFS_ANSIC
	const wfs_fsid_t FS, error_type * const error )
#else
	FS, error )
	const wfs_fsid_t FS;
	error_type * const error;
#endif
{
	/* FIXME Don't know how to get this information *
	return WFS_SUCCESS;*/
	return wfs_xfs_check_err (FS, error);
}

#ifndef WFS_ANSIC
static errcode_enum WFS_ATTR ((warn_unused_result))
	wfs_xfs_get_mnt_point PARAMS ((const char * const dev_name, error_type * const error,
		char * const mnt_point, const size_t mnt_point_len, int * const is_rw ));
#endif

/**
 * Gets the mount point of the given device (if mounted).
 * \param dev_name Device to check.
 * \param error Pointer to error variable.
 * \param mnt_point Array for the mount point.
 * \param is_rw Pointer to a variavle which will tell if the filesystem
 *	is mounted in read+write mode (=1 if yes).
 * \return 0 in case of no errors, other values otherwise.
 */
static errcode_enum WFS_ATTR ((warn_unused_result))
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_xfs_get_mnt_point (
#ifdef WFS_ANSIC
	const char * const dev_name, error_type * const error,
	char * const mnt_point, const size_t mnt_point_len, int * const is_rw )
#else
	dev_name, error, mnt_point, mnt_point_len, is_rw )
	const char * const dev_name;
	error_type * const error;
	char * const mnt_point;
	const size_t mnt_point_len;
	int * const is_rw;
#endif
{
	return wfs_get_mnt_point ( dev_name, error, mnt_point, mnt_point_len, is_rw );
}

/**
 * Checks if the given XFS filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result))
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_xfs_chk_mount (
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
 * Opens a XFS filesystem on the given device.
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
wfs_xfs_open_fs (
#ifdef WFS_ANSIC
	const char * const dev_name, wfs_fsid_t * const FS, CURR_FS * const whichfs,
	const fsdata * const data WFS_ATTR ((unused)), error_type * const error )
#else
	dev_name, FS, whichfs, data, error )
	const char * const dev_name;
	wfs_fsid_t* const FS;
	CURR_FS * const whichfs;
	const fsdata * const data WFS_ATTR ((unused));
	error_type * const error;
#endif
{
	int res = 0;
	errcode_enum mnt_ret;
	int pipe_fd[2];
	struct child_id child_xfsdb;
	errcode_enum ret_child;
	int fs_fd;
	unsigned char xfs_sig[4];
	ssize_t sig_read;
#define FSNAME_POS_OPEN 9
	char * args[] = { wfs_xfs_xfs_db, wfs_xfs_xfs_db_opt_ro, wfs_xfs_xfs_db_opt_cmd,
		wfs_xfs_xfs_db_cmd_superblock_reset, wfs_xfs_xfs_db_opt_cmd,
		wfs_xfs_xfs_db_cmd_print, wfs_xfs_xfs_db_opt_cmd, wfs_xfs_xfs_db_cmd_quit,
		wfs_xfs_xfs_db_opt_end, NULL, NULL }; /* xfs_db -c 'sb 0' -c print dev_name */
	char buffer[WFS_XFSBUFSIZE];
	int blocksize_set = 0, agblocks_set = 0, inprogress_found = 0, used_inodes_set = 0,
		free_blocks_set = 0;

	char *pos1 = NULL, *pos2 = NULL, *pos3 = NULL, *pos4 = NULL, *pos5 = NULL;
	int is_rw;
	unsigned long long int inprogress;
	size_t namelen;
	size_t buffer_len;

	if ((dev_name == NULL) || (FS == NULL) || (whichfs == NULL) || (error == NULL))
	{
		return WFS_BADPARAM;
	}
	*whichfs = CURR_NONE;
	FS->xxfs.mnt_point = NULL;
	namelen = strlen (dev_name);

	/* first check if 0x58465342 signature present, to save resources if different filesystem */
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	fs_fd = open64 (dev_name, O_RDONLY
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
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		return WFS_OPENFS;
	}
	sig_read = read (fs_fd, xfs_sig, 4);
	close (fs_fd);
	if ( sig_read != 4 )
	{
		return WFS_OPENFS;
	}
	if ((xfs_sig[0] != 0x58) || (xfs_sig[1] != 0x46) || (xfs_sig[2] != 0x53) || (xfs_sig[3] != 0x42))
	{
		return WFS_OPENFS;
	}

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	FS->xxfs.dev_name = (char *) malloc ( namelen + 1 );
	if ( FS->xxfs.dev_name == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		return WFS_MALLOC;
	}
	strncpy ( FS->xxfs.dev_name, dev_name, namelen + 1 );
	/* Copy the file system name info the right places */
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	args[FSNAME_POS_OPEN] = (char *) malloc ( namelen + 1 );
	if ( args[FSNAME_POS_OPEN] == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		free (FS->xxfs.dev_name);
		FS->xxfs.dev_name = NULL;
		return WFS_MALLOC;
	}
	strncpy ( args[FSNAME_POS_OPEN], FS->xxfs.dev_name, namelen + 1 );

#if (defined HAVE_UNISTD_H) && (defined HAVE_ACCESS)
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	if ( access (dev_name, W_OK) != 0 )
	{
# ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
# else
		error->errcode.gerror = 1L;
# endif
		free (args[FSNAME_POS_OPEN]);
		free (FS->xxfs.dev_name);
		FS->xxfs.dev_name = NULL;
		return WFS_OPENFS;
	}
#endif
	/* Open the pipe for communications */
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	res = pipe (pipe_fd);
	if ( (res < 0)
#ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
#endif
		 )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 1L;
#endif
		free (args[FSNAME_POS_OPEN]);
		free (FS->xxfs.dev_name);
		FS->xxfs.dev_name = NULL;
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

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
#ifdef HAVE_SIGNAL_H
	sigchld_recvd = 0;
#endif
	child_xfsdb.program_name = args[0];
	child_xfsdb.args = args;
	child_xfsdb.stdin_fd = -1;
	child_xfsdb.stdout_fd = pipe_fd[PIPE_W];
	child_xfsdb.stderr_fd = pipe_fd[PIPE_W];
	ret_child = wfs_create_child (&child_xfsdb);
	if ( ret_child != WFS_SUCCESS )
	{
		/* error */
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 1L;
#endif
		free (args[FSNAME_POS_OPEN]);
		free (FS->xxfs.dev_name);
		FS->xxfs.dev_name = NULL;
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
			free (args[FSNAME_POS_OPEN]);
			free (FS->xxfs.dev_name);
			FS->xxfs.dev_name = NULL;
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
			free (args[FSNAME_POS_OPEN]);
			free (FS->xxfs.dev_name);
			FS->xxfs.dev_name = NULL;
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
		if ( (pos1 == NULL) && (pos2 == NULL) && (pos3 == NULL) && (pos4 == NULL)
				&& (pos5 == NULL) )
		{
			continue;
		}
		if ( pos1 != NULL )
		{
			res = sscanf (pos1, search1 "%u", &(FS->xxfs.wfs_xfs_blocksize) );
			if ( res != 1 )
			{
				/* NOTE: waiting for the child has already been taken care of. */
				close (pipe_fd[PIPE_R]);
				close (pipe_fd[PIPE_W]);
				free (args[FSNAME_POS_OPEN]);
				free (FS->xxfs.dev_name);
				FS->xxfs.dev_name = NULL;
				return WFS_OPENFS;
			}
			blocksize_set = 1;
		}
		if ( pos2 != NULL )
		{
			res = sscanf (pos2, search2 "%llu", &(FS->xxfs.wfs_xfs_agblocks) );
			if ( res != 1 )
			{
				/* NOTE: waiting for the child has already been taken care of. */
				close (pipe_fd[PIPE_R]);
				close (pipe_fd[PIPE_W]);
				free (args[FSNAME_POS_OPEN]);
				free (FS->xxfs.dev_name);
				FS->xxfs.dev_name = NULL;
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
				free (args[FSNAME_POS_OPEN]);
				free (FS->xxfs.dev_name);
				FS->xxfs.dev_name = NULL;
				return WFS_OPENFS;
			}
			if ( inprogress != 0 )
			{
				/* NOTE: waiting for the child has already been taken care of. */
				close (pipe_fd[PIPE_R]);
				close (pipe_fd[PIPE_W]);
				free (args[FSNAME_POS_OPEN]);
				free (FS->xxfs.dev_name);
				FS->xxfs.dev_name = NULL;
				return WFS_OPENFS;
			}
			inprogress_found = 1;
		}
		if ( pos4 != NULL )
		{
			res = sscanf (pos4, search4 "%llu", &(FS->xxfs.inodes_used) );
			if ( res != 1 )
			{
				/* NOTE: waiting for the child has already been taken care of. */
				close (pipe_fd[PIPE_R]);
				close (pipe_fd[PIPE_W]);
				free (args[FSNAME_POS_OPEN]);
				free (FS->xxfs.dev_name);
				FS->xxfs.dev_name = NULL;
				return WFS_OPENFS;
			}
			used_inodes_set = 1;
		}
		if ( pos5 != NULL )
		{
			res = sscanf (pos5, search5 "%llu", &(FS->xxfs.free_blocks) );
			if ( res != 1 )
			{
				/* NOTE: waiting for the child has already been taken care of. */
				close (pipe_fd[PIPE_R]);
				close (pipe_fd[PIPE_W]);
				free (args[FSNAME_POS_OPEN]);
				free (FS->xxfs.dev_name);
				FS->xxfs.dev_name = NULL;
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
		free (args[FSNAME_POS_OPEN]);
		free (FS->xxfs.dev_name);
		FS->xxfs.dev_name = NULL;
		return WFS_SIGNAL;
	}
	/* just in case, after execvp */
	strncpy ( FS->xxfs.dev_name, dev_name, namelen + 1 );

	mnt_ret = wfs_xfs_get_mnt_point (dev_name, error, buffer, sizeof (buffer), &is_rw);
	if ( (mnt_ret == WFS_SUCCESS) && (buffer[0] != '\0' /*strlen (buffer) > 0*/) )
	{
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		buffer[sizeof (buffer)-1] = '\0';
		buffer_len = strlen (buffer);
		FS->xxfs.mnt_point = (char *) malloc ( buffer_len + 1 );
		if ( FS->xxfs.mnt_point == NULL )
		{
#ifdef HAVE_ERRNO_H
			error->errcode.gerror = errno;
#else
			error->errcode.gerror = 12L;	/* ENOMEM */
#endif
			FS->xxfs.wfs_xfs_agblocks = 0;
			FS->xxfs.wfs_xfs_blocksize = 0;
			free (args[FSNAME_POS_OPEN]);
			free (FS->xxfs.dev_name);
			FS->xxfs.dev_name = NULL;
			return WFS_MALLOC;
		}
		strncpy ( FS->xxfs.mnt_point, buffer, buffer_len + 1 );
	}

	free (args[FSNAME_POS_OPEN]);
	if (sig_recvd != 0)
	{
		free (FS->xxfs.dev_name);
		FS->xxfs.dev_name = NULL;
		return WFS_SIGNAL;
	}
	*whichfs = CURR_XFS;
	return WFS_SUCCESS;
}

/**
 * Closes the XFS filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum
wfs_xfs_close_fs (
#ifdef WFS_ANSIC
	wfs_fsid_t FS, error_type * const error
# ifndef HAVE_ERRNO_H
	WFS_ATTR ((unused))
# endif
	)
#else
	FS, error
	)
	wfs_fsid_t FS;
	error_type * const error
# ifndef HAVE_ERRNO_H
		WFS_ATTR ((unused))
# endif
	;
#endif
{
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	free (FS.xxfs.mnt_point);
	free (FS.xxfs.dev_name);
#ifdef HAVE_ERRNO_H
	if ( errno != 0 )
	{
		if ( error != NULL )
		{
			error->errcode.gerror = errno;
		}
		return WFS_FSCLOSE;
	}
	else
#endif
		return WFS_SUCCESS;
}

/**
 * Flushes the XFS filesystem.
 * \param FS The XFS filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum
wfs_xfs_flush_fs (
#ifdef WFS_ANSIC
	const wfs_fsid_t FS WFS_ATTR ((unused)) )
#else
	FS )
	const wfs_fsid_t FS WFS_ATTR ((unused));
#endif
{
	/* Better than nothing */
#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_SYNC)
	sync ();
#endif
	return WFS_SUCCESS;
}
