/*
 * A program for secure cleaning of free space on filesystems.
 *	-- XFS file system-specific functions, header file.
 *
 * Copyright (C) 2007-2008 Bogdan Drozdowski, bogdandr (at) op.pl
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
# include <unistd.h>	/* access(), close(), dup2(), fork(), sync(), STDIN_FILENO,
			   STDOUT_FILENO, STDERR_FILENO, select () (the old way) */
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#else
# ifdef HAVE_WAIT_H
#  include <wait.h>
# endif
#endif
#ifndef WEXITSTATUS
# define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
# define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

#ifdef HAVE_SCHED_H
# include <sched.h>
#endif

#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif

#include "wipefreespace.h"
#include "wfs_xfs.h"
#include "wfs_signal.h"
#include "wfs_util.h"

#define PIPE_R 0
#define PIPE_W 1
#define XFSBUFSIZE 240

#ifndef STDIN_FILENO
# define STDIN_FILENO	0
#endif

#ifndef STDOUT_FILENO
# define STDOUT_FILENO	1
#endif

#ifndef STDERR_FILENO
# define STDERR_FILENO	2
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

/*#define XFS_HAS_SHARED_BLOCKS 1 */

/**
 * Flushes the given pipe so that hopefully the data sent will be
 *  received at the other end.
 * @param fd The pipe file descriptor to flush.
 */
static void
flush_pipe_output (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const int fd)
#else
	fd )
	const int fd;
#endif
{
	int i;
	for (i=0; i < PIPE_BUF; i++)
	{
		write (fd, "\n", 1);
	}
#ifdef HAVE_FSYNC
	fsync (fd);
#endif
}

/**
 * Reads the given pipe until end of data is reached.
 * @param fd The pipe file descriptor to empty.
 */
static void
flush_pipe_input (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const int fd)
#else
	fd )
	const int fd;
#endif
{
	int r;
	char c;
	/* set non-blocking mode to quit as soon as the pipe is empty */
	r = fcntl (fd, F_SETFL, fcntl (fd, F_GETFL) | O_NONBLOCK );
	if ( r != 0 ) return;
	do
	{
		r = read (fd, &c, 1);
	} while (r == 1);
	/* set blocking mode again */
	fcntl (fd, F_SETFL, fcntl (fd, F_GETFL) & ~ O_NONBLOCK );
}

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
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const wfs_fsid_t FS WFS_ATTR ((unused)) )
#else
	FS WFS_ATTR ((unused)) )
	const wfs_fsid_t FS;
#endif
{
	/*
	 * The XFS has no undelete capability.
	 * Directories' sizes are multiples of block size, so can't wipe
	 *  unused space in these blocks.
	 */
	return WFS_SUCCESS;
}

/**
 * Returns the buffer size needed to work on the
 *	smallest physical unit on a XFS filesystem.
 * \param FS The filesystem.
 * \return Block size on the filesystem.
 */
static size_t WFS_ATTR ((warn_unused_result))
wfs_xfs_get_block_size (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const wfs_fsid_t FS )
#else
	FS )
	const wfs_fsid_t FS;
#endif
{
	return FS.xxfs.wfs_xfs_blocksize;
}


/**
 * Wipes the free space on the given XFS filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_xfs_wipe_fs	(
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const wfs_fsid_t FS, error_type * const error )
#else
	FS, error )
	const wfs_fsid_t FS;
	error_type * const error;
#endif
{
	unsigned long int i;
	int res;
	int pipe_fd[2];
	int fs_fd;
	pid_t p_f, p_uf, p_db;
	/* 	 xfs_freeze -f (freeze) | -u (unfreeze) mount-point */
	char * args_freeze[] = { "xfs_freeze", "-f", NULL, NULL };
	char * args_unfreeze[] = { "xfs_freeze", "-u", NULL, NULL };
	/*	 xfs_db  -c 'freesp -d' dev_name */
	char *  args_db[] = { "xfs_db", "-i", "-c", "freesp -d", "--",
		NULL, NULL };
	char read_buffer[XFSBUFSIZE];
	unsigned long long agno, agoff, length;
	unsigned char * buffer;
	unsigned long long j;
	int selected[NPAT];
	errcode_enum ret_wfs = WFS_SUCCESS;
	int bytes_read;
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
	struct timeval tv;
	fd_set set;
#endif

	if ( error == NULL ) return WFS_BADPARAM;

	/* Copy the file system name info the right places */
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	args_db[5] = (char *) malloc ( strlen (FS.xxfs.dev_name) + 1 );
	if ( args_db[5] == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		return WFS_MALLOC;
	}
	strncpy ( args_db[5], FS.xxfs.dev_name, strlen (FS.xxfs.dev_name) + 1 );
	/* we need the mount point here, not the FS device */
	if ( FS.xxfs.mnt_point != NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		args_freeze[2] = (char *) malloc ( strlen (FS.xxfs.mnt_point) + 1 );
		if ( args_freeze[2] == NULL )
		{
#ifdef HAVE_ERRNO_H
			error->errcode.gerror = errno;
#else
			error->errcode.gerror = 12L;	/* ENOMEM */
#endif
			free (args_db[5]);
			return WFS_MALLOC;
		}
		strncpy ( args_freeze[2], FS.xxfs.mnt_point, strlen (FS.xxfs.mnt_point) + 1 );
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		args_unfreeze[2] = (char *) malloc ( strlen (FS.xxfs.mnt_point) + 1 );
		if ( args_unfreeze[2] == NULL )
		{
#ifdef HAVE_ERRNO_H
			error->errcode.gerror = errno;
#else
			error->errcode.gerror = 12L;	/* ENOMEM */
#endif
			free (args_freeze[2]);
			free (args_db[5]);
			return WFS_MALLOC;
		}
		strncpy ( args_unfreeze[2], FS.xxfs.mnt_point, strlen (FS.xxfs.mnt_point) + 1 );
	}
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	buffer = (unsigned char *) malloc ( wfs_xfs_get_block_size (FS) );
	if ( buffer == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		free (args_unfreeze[2]);
		free (args_freeze[2]);
		free (args_db[5]);
		return WFS_MALLOC;
	}

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
		free (buffer);
		free (args_unfreeze[2]);
		free (args_freeze[2]);
		free (args_db[5]);
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
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
# ifdef HAVE_SIGNAL_H
		sigchld_recvd = 0;
# endif
		p_f = fork ();
		if ( (p_f < 0)
# ifdef HAVE_ERRNO_H
/*			|| (errno != 0)*/
# endif
		 )
		{
			/* error */
#ifdef HAVE_ERRNO_H
			error->errcode.gerror = errno;
#else
			error->errcode.gerror = 1L;
#endif
			close (pipe_fd[PIPE_R]);
			close (pipe_fd[PIPE_W]);
			free (buffer);
			free (args_unfreeze[2]);
			free (args_freeze[2]);
			free (args_db[5]);
			return WFS_FORKERR;
		}
		else if ( p_f == 0 )
		{
			/* child */
			close (STDOUT_FILENO);
			close (STDERR_FILENO);
			execvp ( "xfs_freeze", args_freeze );
			/* if we got here, exec() failed and there's nothing to do. */
			close (pipe_fd[PIPE_R]);
			close (pipe_fd[PIPE_W]);

			/* NOTE: needed or the parent will wait forever */
			exit (EXIT_FAILURE);
			/* Commit suicide or wait for getting killed *
#if (defined HAVE_GETPID) && (defined HAVE_KILL)
			kill (getpid (), SIGKILL);
#endif
			while (1==1)
			{
#ifdef HAVE_SCHED_YIELD
				sched_yield ();
#elif (defined HAVE_SLEEP)
				sleep (5);
#endif
			}
			*return WFS_EXECERR;*/
		}
		else
		{
			/* parent */
#ifdef HAVE_WAITPID
			waitpid (p_f, NULL, 0);
#else
# if defined HAVE_WAIT
			wait (NULL);
# else
#  if (defined HAVE_SIGNAL_H)
			while (sigchld_recvd == 0)
			{
#   ifdef HAVE_SCHED_YIELD
				sched_yield ();
#   elif (defined HAVE_SLEEP)
				sleep (1);
#   endif
			}
			sigchld_recvd = 0;
#  else
#   ifdef HAVE_SLEEP
			sleep (5);
#   else
			for ( i=0; i < (1<<30); i++ );
#   endif
			kill (p_f, SIGKILL);
#  endif	/* HAVE_SIGNAL_H */
# endif
#endif
		}
	}	/* if ( FS.xxfs.mnt_point != NULL )  */

	/* parent, continued */
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
# ifdef HAVE_SIGNAL_H
	sigchld_recvd = 0;
# endif
	p_db = fork ();
	if ( (p_db < 0)
# ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
# endif
		 )
	{
		/* error */
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 1L;
#endif
		/* can't return from here - have to un-freeze first */
		ret_wfs = WFS_FORKERR;
	}
	else if ( p_db == 0 )
	{
		/* child */
		close (pipe_fd[PIPE_R]);

		close (STDOUT_FILENO);
		close (STDERR_FILENO);
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		res = dup2 (pipe_fd[PIPE_W], STDOUT_FILENO);
		if ( (res == STDOUT_FILENO)
#ifdef HAVE_ERRNO_H
/*			&& (errno == 0)*/
#endif
		 )
		{
			res = dup2 (pipe_fd[PIPE_W], STDERR_FILENO);
			if ( (res == STDERR_FILENO)
#ifdef HAVE_ERRNO_H
/*				&& (errno == 0)*/
#endif
			 )
			{
				execvp ( "xfs_db", args_db );
			}
		}
		/* if we got here, exec() failed and there's nothing to do. */
		close (pipe_fd[PIPE_R]);
		close (pipe_fd[PIPE_W]);

		/* NOTE: needed or the parent will wait forever */
		exit (EXIT_FAILURE);
		/* Commit suicide or wait for getting killed *
#if (defined HAVE_GETPID) && (defined HAVE_KILL)
		kill (getpid (), SIGKILL);
#endif
		while (1==1)
		{
#ifdef HAVE_SCHED_YIELD
			sched_yield ();
#elif (defined HAVE_SLEEP)
			sleep (5);
#endif
		}
		*return WFS_EXECERR;*/
	}
	else
	{
		/* parent */
		close (pipe_fd[PIPE_W]);
#ifdef HAVE_SLEEP
		sleep (1);
#else
		for (i=0; (i < (1<<30)) && (sig_recvd == 0); i++ );
#endif
		/* open the FS */
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		fs_fd = open64 (FS.xxfs.dev_name, O_WRONLY | O_EXCL);
		if ( (fs_fd < 0)
#ifdef HAVE_ERRNO_H
/*			|| (errno != 0)*/
#endif
		   )
		{
			/* can't return from here - have to un-freeze first */
			ret_wfs = WFS_OPENFS;
		}
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
		FD_ZERO ( &set );
		FD_SET ( pipe_fd[PIPE_R], &set );
#endif
		while ( (sig_recvd == 0) /*&& (ret_wfs == WFS_SUCCESS)*/ )
		{
			/* read just 1 line */
			res = 0;
			do
			{
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
				tv.tv_sec = 10;
				tv.tv_usec = 0;
#endif
# ifdef HAVE_ERRNO_H
				errno = 0;
# endif
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
				if ( select ( pipe_fd[PIPE_R]+1, &set, NULL, NULL, &tv ) > 0 )
				{
#endif
					bytes_read = read (pipe_fd[PIPE_R], &(read_buffer[res]), 1);
					res++;
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
				}
				else
				{
					bytes_read = 1;	/* just a marker */
					if ( sigchld_recvd != 0 )
					{
						res = -1;
						break;
					}
				}
#endif
			}
			while (     (read_buffer[res-1] != '\n')
				 && (read_buffer[res-1] != '\r')
				 && (res < XFSBUFSIZE)
				 && (bytes_read == 1)
				 && (sig_recvd == 0)
				  );
#ifdef HAVE_ERRNO_H
			/*if ( errno == EAGAIN ) continue;*/
#endif
			if ( (res < 0) || (sig_recvd != 0)
#ifdef HAVE_ERRNO_H
/*				|| ( errno != 0 )*/
#endif
			   )
			{
				/* can't return from here - have to un-freeze first */
				ret_wfs = WFS_INOREAD;
				break;
			}
			read_buffer[XFSBUFSIZE-1] = '\0';

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
				kill (p_db, SIGKILL);
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
			if ( i < npasses ) break;
		}
		/* child stopped writing? somehing went wrong?
		   close the FS and kill the child process
		 */

		close (fs_fd);
#ifdef HAVE_WAITPID
		kill (p_db, SIGINT);
		waitpid (p_db, NULL, 0);
#else
# if defined HAVE_WAIT
		wait (NULL);
# else
#  if (defined HAVE_SIGNAL_H)
		while (sigchld_recvd == 0)
		{
#   ifdef HAVE_SCHED_YIELD
			sched_yield ();
#   elif (defined HAVE_SLEEP)
			sleep (1);
#   endif
		}
		sigchld_recvd = 0;
#  else
#   ifdef HAVE_SLEEP
		sleep (5);
#   else
		for ( i=0; i < (1<<30); i++ );
#   endif
		kill (p_db, SIGKILL);
#  endif	/* HAVE_SIGNAL_H */
# endif
#endif
	} /* parent if fork() for xfs_db succeded */

	if ( FS.xxfs.mnt_point != NULL )
	{
		/* un-freeze the filesystem */
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
# ifdef HAVE_SIGNAL_H
		sigchld_recvd = 0;
# endif
		p_uf = fork ();
		if ( (p_uf < 0)
# ifdef HAVE_ERRNO_H
/*			|| (errno != 0)*/
# endif
		 )
		{
			/* error */
			ret_wfs = WFS_FORKERR;
		}
		else if ( p_uf == 0 )
		{
			/* child */
			close (STDOUT_FILENO);
			close (STDERR_FILENO);
			execvp ( "xfs_freeze", args_unfreeze );
			/* if we got here, exec() failed and there's nothing to do. */
			close (pipe_fd[PIPE_R]);
			close (pipe_fd[PIPE_W]);

			/* NOTE: needed or the parent will wait forever */
			exit (EXIT_FAILURE);
			/* Commit suicide or wait for getting killed *
#if (defined HAVE_GETPID) && (defined HAVE_KILL)
			kill (getpid (), SIGKILL);
#endif
			while (1==1)
			{
#ifdef HAVE_SCHED_YIELD
				sched_yield ();
#elif (defined HAVE_SLEEP)
				sleep (5);
#endif
			}
			*return WFS_EXECERR;*/
		}
		else
		{
		/* parent */
#ifdef HAVE_WAITPID
			waitpid (p_uf, NULL, 0);
#else
# if defined HAVE_WAIT
			wait (NULL);
# else
#  if (defined HAVE_SIGNAL_H)
			while (sigchld_recvd == 0)
			{
#   ifdef HAVE_SCHED_YIELD
				sched_yield ();
#   elif (defined HAVE_SLEEP)
				sleep (1);
#   endif
			}
			sigchld_recvd = 0;
#  else
#   ifdef HAVE_SLEEP
			sleep (5);
#   else
			for ( i=0; i < (1<<30); i++ );
#   endif
			kill (p_uf, SIGKILL);
#  endif	/* HAVE_SIGNAL_H */
# endif
#endif
		}
	} /* if ( FS.xxfs.mnt_point != NULL ) */

	close (pipe_fd[PIPE_R]);
	close (pipe_fd[PIPE_W]);

	free (buffer);
	free (args_unfreeze[2]);
	free (args_freeze[2]);
	free (args_db[5]);
	if (sig_recvd != 0) return WFS_SIGNAL;
	return ret_wfs;
}


/**
 * Wipes the free space in partially used blocks on the given XFS filesystem.
 * \param FS The filesystem.
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result))
wfs_xfs_wipe_part (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const wfs_fsid_t FS
#ifdef XFS_HAS_SHARED_BLOCKS
	WFS_ATTR ((unused))
#endif
	, error_type * const error
#ifdef XFS_HAS_SHARED_BLOCKS
	WFS_ATTR ((unused))
#endif
	 )
#else
	FS
#ifdef XFS_HAS_SHARED_BLOCKS
	WFS_ATTR ((unused))
#endif
	, error
#ifdef XFS_HAS_SHARED_BLOCKS
	WFS_ATTR ((unused))
#endif
	)
	const wfs_fsid_t FS;
	error_type * const error;
#endif
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
#ifndef XFS_HAS_SHARED_BLOCKS

	unsigned long int i;
	int res;
	int pipe_from_ino_db[2];
	int pipe_from_blk_db[2], pipe_to_blk_db[2];
	int fs_fd;
	pid_t p_db_inodes, p_db_blocks;
	/*	 xfs_db   dev_name */
	char * args_db_ncheck[] = { "xfs_db", "-i", "-c", "blockget -n",
		"-c", "ncheck", "--", NULL, NULL };
	char * args_db[] = { "xfs_db", "-i", "--", NULL, NULL };
	char read_buffer[XFSBUFSIZE];
	char * pos1 = NULL;
	char * pos2 = NULL;
	unsigned char * buffer;
	int selected[NPAT];
	unsigned long long inode, inode_size, start_block, number_of_blocks;
	int length_to_wipe;
	unsigned long long trash;
	int got_mode_line, got_size_line;
	unsigned int mode;
	unsigned int offset;
	char inode_cmd[40];
	int bytes_read;
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
	fd_set set;
	struct timeval tv;
#endif

	if ( error == NULL ) return WFS_BADPARAM;

	/* Copy the file system name info the right places */
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	args_db[3] = (char *) malloc ( strlen (FS.xxfs.dev_name) + 1 );
	if ( args_db[3] == NULL )
	{
# ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
# else
		error->errcode.gerror = 12L;	/* ENOMEM */
# endif
		return WFS_MALLOC;
	}
	strncpy ( args_db[3], FS.xxfs.dev_name, strlen (FS.xxfs.dev_name) + 1 );

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	args_db_ncheck[7] = (char *) malloc ( strlen (FS.xxfs.dev_name) + 1 );
	if ( args_db_ncheck[7] == NULL )
	{
# ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
# else
		error->errcode.gerror = 12L;	/* ENOMEM */
# endif
		free (args_db[3]);
		return WFS_MALLOC;
	}
	strncpy ( args_db_ncheck[7], FS.xxfs.dev_name, strlen (FS.xxfs.dev_name) + 1 );

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
		free (args_db_ncheck[7]);
		free (args_db[3]);
		return WFS_MALLOC;
	}

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	res = pipe (pipe_from_ino_db);
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
		free (args_db_ncheck[7]);
		free (args_db[3]);
		return WFS_PIPEERR;
	}

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	res = pipe (pipe_to_blk_db);
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
		close (pipe_from_ino_db[PIPE_R]);
		close (pipe_from_ino_db[PIPE_W]);
		free (buffer);
		free (args_db_ncheck[7]);
		free (args_db[3]);
		return WFS_PIPEERR;
	}

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	res = pipe (pipe_from_blk_db);
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
		close (pipe_from_ino_db[PIPE_R]);
		close (pipe_from_ino_db[PIPE_W]);
		close (pipe_to_blk_db[PIPE_R]);
		close (pipe_to_blk_db[PIPE_W]);
		free (buffer);
		free (args_db_ncheck[7]);
		free (args_db[3]);
		return WFS_PIPEERR;
	}

	/* open the first xfs_db process - it will read used inode's numbers */
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
# ifdef HAVE_SIGNAL_H
	sigchld_recvd = 0;
# endif
	p_db_inodes = fork ();
	if ( (p_db_inodes < 0)
# ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
# endif
		 )
	{
		/* error */
# ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
# else
		error->errcode.gerror = 1L;
# endif
		close (pipe_from_ino_db[PIPE_R]);
		close (pipe_from_ino_db[PIPE_W]);
		close (pipe_to_blk_db[PIPE_R]);
		close (pipe_to_blk_db[PIPE_W]);
		close (pipe_from_blk_db[PIPE_R]);
		close (pipe_from_blk_db[PIPE_W]);
		free (buffer);
		free (args_db_ncheck[7]);
		free (args_db[3]);
		return WFS_FORKERR;
	}
	else if ( p_db_inodes == 0 )
	{
		/* child */
		close (pipe_from_ino_db[PIPE_R]);

		close (STDOUT_FILENO);
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		res = dup2 (pipe_from_ino_db[PIPE_W], STDOUT_FILENO);
		if ( (res == STDOUT_FILENO)
#ifdef HAVE_ERRNO_H
/*			&& (errno == 0)*/
#endif
		 )
		{
			/*dup2 (pipe_from_ino_db[PIPE_W], STDERR_FILENO);*/
			execvp ( "xfs_db", args_db_ncheck );
		}
		/* if we got here, exec() failed and there's nothing to do. */
		close (pipe_from_ino_db[PIPE_W]);

		/* NOTE: needed or the parent will wait forever */
		exit (EXIT_FAILURE);
		/* Commit suicide or wait for getting killed *
# if (defined HAVE_GETPID) && (defined HAVE_KILL)
		kill (getpid (), SIGKILL);
# endif
		while (1==1)
		{
# ifdef HAVE_SCHED_YIELD
			sched_yield ();
# elif (defined HAVE_SLEEP)
			sleep (5);
# endif
		}
		*return WFS_EXECERR;*/
	}
	/* parent */
	close (pipe_from_ino_db[PIPE_W]);

	/* open a second xfs_db process - this one will read inodes' block info */
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
# ifdef HAVE_SIGNAL_H
	sigchld_recvd = 0;
# endif
	p_db_blocks = fork ();
	if ( (p_db_blocks < 0)
# ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
# endif
		 )
	{
		/* error */
		close (pipe_from_ino_db[PIPE_R]);
		close (pipe_from_ino_db[PIPE_W]);
# ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
# else
		error->errcode.gerror = 1L;
# endif
		/* kill the first xfs_db process */
# ifdef HAVE_WAITPID
		kill (p_db_inodes, SIGINT);
		waitpid (p_db_inodes, NULL, 0);
# else
#  if defined HAVE_WAIT
		wait (NULL);
#  else
#   if (defined HAVE_SIGNAL_H)
		while (sigchld_recvd == 0)
		{
#    ifdef HAVE_SCHED_YIELD
			sched_yield ();
#    elif (defined HAVE_SLEEP)
			sleep (1);
#    endif
		}
		sigchld_recvd = 0;
#   else
#    ifdef HAVE_SLEEP
		sleep (5);
#    else
		for ( i=0; i < (1<<30); i++ );
#    endif
		kill (p_db_inodes, SIGKILL);
#   endif	/* HAVE_SIGNAL_H */
#  endif
# endif
		close (pipe_to_blk_db[PIPE_R]);
		close (pipe_to_blk_db[PIPE_W]);
		close (pipe_from_blk_db[PIPE_R]);
		close (pipe_from_blk_db[PIPE_W]);
		free (buffer);
		free (args_db_ncheck[7]);
		free (args_db[3]);
		return WFS_FORKERR;
	}
	else if ( p_db_blocks == 0 )
	{
		/* child */
		close (pipe_to_blk_db[PIPE_W]);
		close (pipe_from_blk_db[PIPE_R]);

		close (STDIN_FILENO);
		close (STDOUT_FILENO);
		close (STDERR_FILENO);
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		res = dup2 (pipe_to_blk_db[PIPE_R], STDIN_FILENO);
		if ( (res == STDIN_FILENO)
#ifdef HAVE_ERRNO_H
/*			&& (errno == 0)*/
#endif
		 )
		{
			res = dup2 (pipe_from_blk_db[PIPE_W], STDOUT_FILENO);
			if ( (res == STDOUT_FILENO)
#ifdef HAVE_ERRNO_H
/*				&& (errno == 0)*/
#endif
			 )
			{
				res = dup2 (pipe_from_blk_db[PIPE_W], STDERR_FILENO);
				if ( (res == STDERR_FILENO)
#ifdef HAVE_ERRNO_H
/*					&& (errno == 0)*/
#endif
				 )
				{
					execvp ( "xfs_db", args_db );
				}
			}
		}
		/* if we got here, exec() failed and there's nothing to do. */
		close (pipe_to_blk_db[PIPE_R]);
		close (pipe_to_blk_db[PIPE_W]);
		close (pipe_from_blk_db[PIPE_R]);
		close (pipe_from_blk_db[PIPE_W]);
		/* NOTE: needed or the parent will wait forever */
		exit (EXIT_FAILURE);
		/* Commit suicide or wait for getting killed *
# if (defined HAVE_GETPID) && (defined HAVE_KILL)
		kill (getpid (), SIGKILL);
# endif
		while (1==1)
		{
# ifdef HAVE_SCHED_YIELD
			sched_yield ();
# elif (defined HAVE_SLEEP)
			sleep (5);
# endif
		}
		*return WFS_EXECERR;*/
	}
	/* parent */
	close (pipe_to_blk_db[PIPE_R]);
	close (pipe_from_blk_db[PIPE_W]);

	/* open the FS */
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	fs_fd = open64 (FS.xxfs.dev_name, O_WRONLY | O_EXCL);
	if ( (fs_fd < 0)
# ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
# endif
	   )
	{
		ret_part = WFS_OPENFS;
	}
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
	FD_ZERO ( &set );
	FD_SET ( pipe_from_ino_db[PIPE_R], &set );
#endif
	while ( (sig_recvd == 0) && (ret_part == WFS_SUCCESS) )
	{
		/* read just 1 line with inode-file pair */
		res = 0;
		do
		{
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
			tv.tv_sec = 10;
			tv.tv_usec = 0;
#endif
# ifdef HAVE_ERRNO_H
			errno = 0;
# endif
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
			if ( select ( pipe_from_ino_db[PIPE_R]+1, &set, NULL, NULL, &tv ) > 0 )
			{
#endif
				bytes_read = read (pipe_from_ino_db[PIPE_R], &(read_buffer[res]), 1);
				res++;
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
			}
			else
			{
				bytes_read = 1;	/* just a marker */
				if ( sigchld_recvd != 0 )
				{
					res = -1;
					break;
				}
			}
#endif
		}
		while (     (read_buffer[res-1] != '\n')
			 && (read_buffer[res-1] != '\r')
			 && (res < XFSBUFSIZE)
			 && (bytes_read == 1)
			 && (sig_recvd == 0)
			  );
# ifdef HAVE_ERRNO_H
		/*if ( errno == EAGAIN ) continue;*/
# endif
		if ( (res < 0) || (sig_recvd != 0)
# ifdef HAVE_ERRNO_H
/*			|| ( errno != 0 )*/
# endif
		   )
		{
			ret_part = WFS_INOREAD;
			break;
		}
		read_buffer[XFSBUFSIZE-1] = '\0';
		res = sscanf ( read_buffer, " %llu", &inode );
		if ( res != 1 )
		{
			break;
		}
		/* request inode data from the second xfs_db */
#ifdef HAVE_SNPRINTF
		snprintf (inode_cmd, sizeof (inode_cmd), "inode %llu\nprint\n", inode);
#else
		sprintf (inode_cmd, "inode %llu\nprint\n", inode);
#endif
		res = write (pipe_to_blk_db[PIPE_W], inode_cmd, strlen (inode_cmd) );
		if ( res <= 0 )
		{
			break;
		}
		flush_pipe_output (pipe_to_blk_db[PIPE_W]);
		/* read the inode info. Look for "core.mode = " and "core.size = " */
		got_mode_line = 0;
		got_size_line = 0;
		mode = 0;
		inode_size = 0;
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
		FD_ZERO ( &set );
		FD_SET ( pipe_from_blk_db[PIPE_R], &set );
#endif
		while (((got_mode_line == 0) || (got_size_line == 0)) && (sig_recvd == 0))
		{
			/* read just 1 line */
			res = 0;
			do
			{
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
				tv.tv_sec = 10;
				tv.tv_usec = 0;
#endif
# ifdef HAVE_ERRNO_H
				errno = 0;
# endif
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
				if ( select ( pipe_from_ino_db[PIPE_R]+1, &set, NULL, NULL, &tv ) > 0 )
				{
#endif
					bytes_read = read (pipe_from_blk_db[PIPE_R],
						&(read_buffer[res]), 1);
					res++;
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
				}
				else
				{
					bytes_read = 1;	/* just a marker */
					if ( sigchld_recvd != 0 )
					{
						res = -1;
						break;
					}
				}
#endif
			}
			while (    (read_buffer[res-1] != '\n')
			 	&& (read_buffer[res-1] != '\r')
			 	&& (res < XFSBUFSIZE)
			 	&& (bytes_read == 1)
			 	&& (sig_recvd == 0)
			  	);
# ifdef HAVE_ERRNO_H
			/*if ( errno == EAGAIN ) continue;*/
# endif
			if ( (res < 0) || (sig_recvd != 0)
# ifdef HAVE_ERRNO_H
/*				|| ( errno != 0 )*/
# endif
			   )
			{
				break;
			}
# define modeline "core.mode = "
# define sizeline "core.size = "
			read_buffer[XFSBUFSIZE-1] = '\0';
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
		res = write (pipe_to_blk_db[PIPE_W], "bmap -d\n", 8 );
		if ( res <= 0 ) break;
		flush_pipe_output (pipe_to_blk_db[PIPE_W]);
		/* read just 1 line */
		res = 0;
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
		FD_ZERO ( &set );
		FD_SET ( pipe_from_blk_db[PIPE_R], &set );
#endif
		do
		{
			do
			{
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
				tv.tv_sec = 10;
				tv.tv_usec = 0;
#endif
# ifdef HAVE_ERRNO_H
				errno = 0;
# endif
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
				if ( select ( pipe_from_ino_db[PIPE_R]+1, &set, NULL, NULL, &tv ) > 0 )
				{
#endif
					bytes_read = read (pipe_from_blk_db[PIPE_R],
						&(read_buffer[res]), 1);
					res++;
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
				}
				else
				{
					bytes_read = 1;	/* just a marker */
					if ( sigchld_recvd != 0 )
					{
						res = -1;
						break;
					}
				}
#endif
			}
			while (    (read_buffer[res-1] != '\n')
			 	&& (read_buffer[res-1] != '\r')
		 		&& (res < XFSBUFSIZE)
		 		&& (bytes_read == 1)
		 		&& (sig_recvd == 0)
		  		);
# ifdef HAVE_ERRNO_H
			/*if ( errno == EAGAIN ) continue;*/
# endif
			if ( (res < 0) || (sig_recvd != 0)
# ifdef HAVE_ERRNO_H
/*				|| ( errno != 0 )*/
# endif
			   )
			{
				break;
			}
			read_buffer[XFSBUFSIZE-1] = '\0';
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
				strncpy (read_buffer, pos1, (size_t)(&read_buffer[XFSBUFSIZE] - pos1 ));
				res = &read_buffer[XFSBUFSIZE] - pos1;
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
			/* NOTE: 'offset' is probably NOT the offset within a block */
			length_to_wipe = wfs_xfs_get_block_size (FS)
				- (int)((inode_size/*+offset*/)%wfs_xfs_get_block_size (FS));
			if ( length_to_wipe <= 0 ) continue;
			for ( i=0; (i < npasses) && (sig_recvd == 0); i++ )
			{
				/* NOTE: this must be instde! */
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
			break;
		} while (sig_recvd == 0);
	} /* while: reading inode-file */
	write (pipe_to_blk_db[PIPE_W], "quit\n", 5);
	close (pipe_to_blk_db[PIPE_R]);
	close (pipe_to_blk_db[PIPE_W]);

	/* child stopped writing? somehing went wrong?
	   close the FS and kill the child process
	 */
	if ( fs_fd >= 0 ) close (fs_fd);
# ifdef HAVE_WAITPID
	kill (p_db_inodes, SIGINT);
	waitpid (p_db_inodes, NULL, 0);
# else
#  if defined HAVE_WAIT
	wait (NULL);
#  else
#   if (defined HAVE_SIGNAL_H)
	while (sigchld_recvd == 0)
	{
#    ifdef HAVE_SCHED_YIELD
		sched_yield ();
#    elif (defined HAVE_SLEEP)
		sleep (1);
#    endif
	}
	sigchld_recvd = 0;
#   else
#    ifdef HAVE_SLEEP
	sleep (5);
#    else
	for ( i=0; i < (1<<30); i++ );
#    endif
	kill (p_db_inodes, SIGKILL);
#   endif	/* HAVE_SIGNAL_H */
#  endif
# endif

# ifdef HAVE_WAITPID
	kill (p_db_blocks, SIGINT);
	waitpid (p_db_blocks, NULL, 0);
# else
#  if defined HAVE_WAIT
	wait (NULL);
#  else
#   if (defined HAVE_SIGNAL_H)
	while (sigchld_recvd == 0)
	{
#    ifdef HAVE_SCHED_YIELD
		sched_yield ();
#    elif (defined HAVE_SLEEP)
		sleep (1);
#    endif
	}
	sigchld_recvd = 0;
#   else
#    ifdef HAVE_SLEEP
	sleep (5);
#    else
	for ( i=0; i < (1<<30); i++ );
#   endif
	kill (p_db_blocks, SIGKILL);
#   endif	/* HAVE_SIGNAL_H */
#  endif
# endif
	close (pipe_from_ino_db[PIPE_R]);
	close (pipe_from_ino_db[PIPE_W]);
	close (pipe_from_blk_db[PIPE_R]);
	close (pipe_from_blk_db[PIPE_W]);

	free (buffer);
	free (args_db_ncheck[7]);
	free (args_db[3]);
	if (sig_recvd != 0) return WFS_SIGNAL;
#endif /* XFS_HAS_SHARED_BLOCKS */
	return ret_part;
}


/**
 * Checks if the XFS filesystem has errors.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
int WFS_ATTR ((warn_unused_result))
wfs_xfs_check_err (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
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
	pid_t p;
	char * args[] = { "xfs_check", "  ", NULL, NULL }; /* xfs_check [-f] dev/file */
	char buffer[XFSBUFSIZE];
	int bytes_read;
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
	fd_set set;
	struct timeval tv;
#endif


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

	/* Copy the file system name info the right places */
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	args[2] = (char *) malloc ( strlen (FS.xxfs.dev_name) + 1 );
	if ( args[2] == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		return WFS_MALLOC;
	}
	strncpy ( args[2], FS.xxfs.dev_name, strlen (FS.xxfs.dev_name) + 1 );
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
		free (args[2]);
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
# ifdef HAVE_SIGNAL_H
	sigchld_recvd = 0;
# endif
	p = fork ();
	if ( (p < 0)
#ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
#endif
	)
	{
		/* error */
		close (pipe_fd[PIPE_R]);
		close (pipe_fd[PIPE_W]);
		free (args[2]);
		return WFS_FORKERR;
	}
	else if ( p == 0 )
	{
		/* child */
		close (pipe_fd[PIPE_R]);

		close (STDOUT_FILENO);
		close (STDERR_FILENO);
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		res = dup2 (pipe_fd[PIPE_W], STDOUT_FILENO);
		if ( (res == STDOUT_FILENO)
#ifdef HAVE_ERRNO_H
/*			&& (errno == 0)*/
#endif
		 )
		{
			res = dup2 (pipe_fd[PIPE_W], STDERR_FILENO);
			if ( (res == STDERR_FILENO)
#ifdef HAVE_ERRNO_H
/*				&& (errno == 0)*/
#endif
			 )
			{
				execvp ( "xfs_check", args );
			}
		}
		/* if we got here, exec() failed and there's nothing to do. */
		close (pipe_fd[PIPE_R]);
		close (pipe_fd[PIPE_W]);

		/* NOTE: needed or the parent will wait forever */
		exit (EXIT_FAILURE);
		/* Commit suicide or wait for getting killed *
#if (defined HAVE_GETPID) && (defined HAVE_KILL)
		kill (getpid (), SIGKILL);
#endif
		while (1==1)
		{
#ifdef HAVE_SCHED_YIELD
			sched_yield ();
#elif (defined HAVE_SLEEP)
			sleep (5);
#endif
		}
		*return WFS_EXECERR;*/
	}
	else
	{
		close (pipe_fd[PIPE_W]);
		/* NOTE: do NOT wait for the child here. It may be stuck writing to
		   the pipe and WFS will hang
		  */
		/* any output means error. */
		res = 0;
		/* read just 1 line */
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
		FD_ZERO ( &set );
		FD_SET ( pipe_fd[PIPE_R], &set );
#endif
		do
		{
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
			tv.tv_sec = 10;
			tv.tv_usec = 0;
#endif
# ifdef HAVE_ERRNO_H
			errno = 0;
# endif
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
			if ( select ( pipe_fd[PIPE_R]+1, &set, NULL, NULL, &tv ) > 0 )
			{
#endif
				bytes_read = read (pipe_fd[PIPE_R], &(buffer[res]), 1);
				res++;
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
			}
			else
			{
				bytes_read = 1;	/* just a marker */
				if ( sigchld_recvd != 0 )
				{
					res = -1;
					break;
				}
			}
#endif
		}
		while (    (buffer[res-1] != '\n')
			&& (buffer[res-1] != '\r')
			&& (res < XFSBUFSIZE)
			&& (bytes_read == 1)
			&& (sig_recvd == 0)
			);

		if ( res > 1 )
		{
			/* something was read. Filesystem is inconsistent. */
			close (pipe_fd[PIPE_R]);
			close (pipe_fd[PIPE_W]);
			free (args[2]);
			return WFS_FSHASERROR;
		}
	}
	close (pipe_fd[PIPE_R]);
	close (pipe_fd[PIPE_W]);

#ifdef HAVE_WAITPID
	kill (p, SIGINT);
	waitpid (p, NULL, 0);
#else
# if defined HAVE_WAIT
	wait (NULL);
# else
#  if (defined HAVE_SIGNAL_H)
	while (sigchld_recvd == 0)
	{
#   ifdef HAVE_SCHED_YIELD
		sched_yield ();
#   elif (defined HAVE_SLEEP)
		sleep (1);
#   endif
	}
	sigchld_recvd = 0;
#  else
#   ifdef HAVE_SLEEP
	sleep (5);
#   else
	for ( i=0; i < (1<<30); i++ );
#   endif
	kill (p, SIGKILL);
#  endif	/* HAVE_SIGNAL_H */
# endif
#endif

	free (args[2]);
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
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
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

/**
 * Gets the mount point of the given device (if mounted).
 * \param dev_name Device to check.
 * \param error Pointer to error variable.
 * \param mnt_point Array for the mount point.
 * \param is_rw Pointer to a variavle which will tell if the filesystem
 *	is mounted in read+write mode (=1 if yes).
 * \return 0 in case of no errors, other values otherwise.
 */
static errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_xfs_get_mnt_point (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char * const dev_name, error_type * const error,
	char * const mnt_point, int * const is_rw )
#else
	dev_name, error, mnt_point, is_rw )
	const char * const dev_name;
	error_type * const error;
	char * const mnt_point;
	int * const is_rw;
#endif
{
	return wfs_get_mnt_point ( dev_name, error, mnt_point, is_rw );
}

/**
 * Checks if the given XFS filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_xfs_chk_mount (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
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
errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_xfs_open_fs (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char * const dev_name, wfs_fsid_t * const FS, CURR_FS * const whichfs,
	const fsdata * const data WFS_ATTR ((unused)), error_type * const error )
#else
	dev_name, FS, whichfs, data WFS_ATTR ((unused)), error )
	const char * const dev_name;
	wfs_fsid_t* const FS;
	CURR_FS * const whichfs;
	const fsdata * const data;
	error_type * const error;
#endif
{
	int res = 0;
	errcode_enum mnt_ret;
	int pipe_fd[2];
	pid_t p;
	char * args[] = { "xfs_db", "-i", "-c", "sb 0", "-c", "print", "--",
		NULL, NULL }; /* xfs_db -c 'sb 0' -c print dev_name */
	char buffer[XFSBUFSIZE];
	int blocksize_set = 0, agblocks_set = 0, inprogress_found = 0;

	char *pos1 = NULL, *pos2 = NULL, *pos3 = NULL;
	int is_rw;
	unsigned long long int inprogress;
	int bytes_read;
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
	struct timeval tv;
	fd_set set;
#endif


	if ((dev_name == NULL) || (FS == NULL) || (whichfs == NULL) || (error == NULL))
	{
		return WFS_BADPARAM;
	}
	*whichfs = CURR_NONE;
	FS->xxfs.mnt_point = NULL;

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	FS->xxfs.dev_name = (char *) malloc ( strlen (dev_name) + 1 );
	if ( FS->xxfs.dev_name == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		return WFS_MALLOC;
	}
	strncpy ( FS->xxfs.dev_name, dev_name, strlen (dev_name) + 1 );
	/* Copy the file system name info the right places */
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	args[7] = (char *) malloc ( strlen (FS->xxfs.dev_name) + 1 );
	if ( args[7] == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		free (FS->xxfs.dev_name);
		return WFS_MALLOC;
	}
	strncpy ( args[7], FS->xxfs.dev_name, strlen (FS->xxfs.dev_name) + 1 );

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
		free (args[7]);
		free (FS->xxfs.dev_name);
		return WFS_OPENFS;
	}
#endif
	/* Fill wfs_xfs_blocksize and wfs_xfs_agblocks */
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	res = pipe (pipe_fd);
	if ( (res < 0)
#ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
#endif
		 )
	{
# ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
# else
		error->errcode.gerror = 1L;
# endif
		free (args[7]);
		free (FS->xxfs.dev_name);
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

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
# ifdef HAVE_SIGNAL_H
	sigchld_recvd = 0;
# endif
	p = fork ();
	if ( (p < 0)
#ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
#endif
	 )
	{
		/* error */
# ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
# else
		error->errcode.gerror = 1L;
# endif
		free (args[7]);
		free (FS->xxfs.dev_name);
		return WFS_FORKERR;
	}
	else if ( p == 0 )
	{
		/* child */
		close (pipe_fd[PIPE_R]);

		close (STDOUT_FILENO);
		close (STDERR_FILENO);
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		res = dup2 (pipe_fd[PIPE_W], STDOUT_FILENO);
		if ( (res == STDOUT_FILENO)
#ifdef HAVE_ERRNO_H
/*			&& (errno == 0)*/
#endif
		 )
		{
			res = dup2 (pipe_fd[PIPE_W], STDERR_FILENO);
			if ( (res == STDERR_FILENO)
#ifdef HAVE_ERRNO_H
/*				&& (errno == 0)*/
#endif
			 )
			{
				execvp ( "xfs_db", args );
			}
		}
		/* if we got here, exec() failed and there's nothing to do. */
		close (pipe_fd[PIPE_R]);
		close (pipe_fd[PIPE_W]);

		/* NOTE: needed or the parent will wait forever */
		exit (EXIT_FAILURE);
		/* Commit suicide or wait for getting killed *
#if (defined HAVE_GETPID) && (defined HAVE_KILL)
		kill (getpid (), SIGKILL);
#endif
		while (1==1)
		{
#ifdef HAVE_SCHED_YIELD
			sched_yield ();
#elif (defined HAVE_SLEEP)
			sleep (5);
#endif
		}
		*return WFS_EXECERR;*/
	}
	else
	{
		/* parent */
		close (pipe_fd[PIPE_W]);
#ifdef HAVE_WAITPID
		waitpid (p, NULL, 0);
#else
# if defined HAVE_WAIT
		wait (NULL);
# else
#  if (defined HAVE_SIGNAL_H)
		while (sigchld_recvd == 0)
		{
#   ifdef HAVE_SCHED_YIELD
			sched_yield ();
#   elif (defined HAVE_SLEEP)
			sleep (1);
#   endif
		}
		sigchld_recvd = 0;
#  else
#   ifdef HAVE_SLEEP
		sleep (5);
#   else
		for ( i=0; i < (1<<30); i++ );
#   endif
		kill (p, SIGKILL);
#  endif	/* HAVE_SIGNAL_H */
# endif
#endif
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
		FD_ZERO ( &set );
		FD_SET ( pipe_fd[PIPE_R], &set );
#endif
		while ( ((blocksize_set == 0) || (agblocks_set == 0)
			|| (inprogress_found == 0)) && (sig_recvd == 0) )
		{
			/* Sample output:
				magicnum = 0x58465342
				blocksize = 4096
				[...]
				rextsize = 1
				agblocks = 4096
				agcount = 1
			*/
#ifdef HAVE_ERRNO_H
			errno = 0;
#endif
			/* read just 1 line */
			res = 0;
			do
			{
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
				tv.tv_sec = 10;
				tv.tv_usec = 0;
#endif
#ifdef HAVE_ERRNO_H
				errno = 0;
#endif
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
				if ( select ( pipe_fd[PIPE_R]+1, &set, NULL, NULL, &tv ) > 0 )
				{
#endif
					bytes_read = read (pipe_fd[PIPE_R], &(buffer[res]), 1);
					res++;
#if ((defined HAVE_SYS_SELECT_H) || (defined TIME_WITH_SYS_TIME)\
	|| (defined HAVE_SYS_TIME_H) || (defined HAVE_TIME_H))	\
	&& (defined HAVE_SELECT)
				}
				else
				{
					bytes_read = 1;	/* just a marker */
					if ( sigchld_recvd != 0 )
					{
						res = -1;
						break;
					}
				}
#endif
			}
			while (    (buffer[res-1] != '\n')
				&& (buffer[res-1] != '\r')
				&& (res < XFSBUFSIZE)
				&& (bytes_read == 1)
				&& (sig_recvd == 0)
				);
#ifdef HAVE_ERRNO_H
			/*if ( errno == EAGAIN ) continue;*/
#endif
			if ( (res < 0) || (sig_recvd != 0)
#ifdef HAVE_ERRNO_H
/*				|| ( errno != 0 )*/
#endif
			   )
			{
				/* NOTE: waiting for the child has already been taken care of. */
				close (pipe_fd[PIPE_R]);
				close (pipe_fd[PIPE_W]);
				free (args[7]);
				free (FS->xxfs.dev_name);
				return WFS_OPENFS;
			}
			buffer[XFSBUFSIZE-1] = '\0';
#define err_str "xfs_db:"
			if ( strstr (buffer, err_str) != NULL )
			{
				/* probably an error occurred, but this function will
				   wait for more data forever, so quit here */
				/* NOTE: waiting for the child has already been taken care of. */
				close (pipe_fd[PIPE_R]);
				close (pipe_fd[PIPE_W]);
				free (args[7]);
				free (FS->xxfs.dev_name);
				return WFS_OPENFS;
			}
#define search1 "blocksize = "
#define search2 "agblocks = "
#define search3 "inprogress = "
			pos1 = strstr (buffer, search1);
			pos2 = strstr (buffer, search2);
			pos3 = strstr (buffer, search3);
			if ( (pos1 == NULL) && (pos2 == NULL) && (pos3 == NULL) )
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
					free (args[7]);
					free (FS->xxfs.dev_name);
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
					free (args[7]);
					free (FS->xxfs.dev_name);
					return WFS_OPENFS;
				}
				agblocks_set = 1;
			}
			if ( pos3 != NULL )
			{
				res = sscanf (pos3, search3 "%llu", &inprogress );
				if ( res != 1 )
				{
					close (pipe_fd[PIPE_R]);
					close (pipe_fd[PIPE_W]);
					free (args[7]);
					free (FS->xxfs.dev_name);
					return WFS_OPENFS;
				}
				if ( inprogress != 0 )
				{
					close (pipe_fd[PIPE_R]);
					close (pipe_fd[PIPE_W]);
					free (args[7]);
					free (FS->xxfs.dev_name);
					return WFS_OPENFS;
				}
				inprogress_found = 1;
			}
		}	/* while */
		close (pipe_fd[PIPE_R]);
		close (pipe_fd[PIPE_W]);
		/* NOTE: waiting for the child has already been taken care of. */
	}	/* else - parent */

	if (sig_recvd != 0)
	{
		free (args[7]);
		free (FS->xxfs.dev_name);
		return WFS_SIGNAL;
	}
	/* just in case, after execvp */
	strncpy ( FS->xxfs.dev_name, dev_name, strlen (dev_name) + 1 );

	mnt_ret = wfs_xfs_get_mnt_point (dev_name, error, buffer, &is_rw);
	if ( (mnt_ret == WFS_SUCCESS) && (strlen (buffer) > 0) )
	{
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		FS->xxfs.mnt_point = (char *) malloc ( strlen (buffer) + 1 );
		if ( FS->xxfs.mnt_point == NULL )
		{
#ifdef HAVE_ERRNO_H
			error->errcode.gerror = errno;
#else
			error->errcode.gerror = 12L;	/* ENOMEM */
#endif
			FS->xxfs.wfs_xfs_agblocks = 0;
			FS->xxfs.wfs_xfs_blocksize = 0;
			free (args[7]);
			free (FS->xxfs.dev_name);
			return WFS_MALLOC;
		}
		strncpy ( FS->xxfs.mnt_point, buffer, strlen (buffer) + 1 );
	}

	if (sig_recvd != 0)
	{
		free (args[7]);
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
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	wfs_fsid_t FS, error_type * const error
# ifndef HAVE_ERRNO_H
	WFS_ATTR ((unused))
# endif
	)
#else
	FS, error
# ifndef HAVE_ERRNO_H
	WFS_ATTR ((unused))
# endif
	)
	wfs_fsid_t FS;
	error_type * const error;
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
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const wfs_fsid_t FS WFS_ATTR ((unused)) )
#else
	FS WFS_ATTR ((unused)) )
	const wfs_fsid_t FS;
#endif
{
	/* Better than nothing */
#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H) && (defined HAVE_SYNC)
	sync ();
#endif
	return WFS_SUCCESS;
}
