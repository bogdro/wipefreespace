/*
 * A program for secure cleaning of free space on filesystems.
 *	-- XFS file system-specific functions, header file.
 *
 * Copyright (C) 2007 Bogdan Drozdowski, bogdandr (at) op.pl
 * License: GNU General Public License, v3+
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

/*
#define _FILE_OFFSET_BITS 64
#define _LARGEFILE64_SOURCE 1

#if (defined HAVE_XFS_LIBXFS_H) && (defined HAVE_LIBXFS)
# include <xfs/libxfs.h>
# include <xfs/path.h>
#elif (defined HAVE_LIBXFS_H) && (defined HAVE_LIBXFS)
# include <libxfs.h>
# include <path.h>
#else
# error Something wrong. XFS requested, but libxfs.h or XFS library missing.
#endif

#ifdef HAVE_SYS_STAT_H
# define __USE_FILE_OFFSET64 1
# include <sys/stat.h>
#endif
*/

#define _FILE_OFFSET_BITS 64
#define __USE_FILE_OFFSET64 1
#define _LARGEFILE64_SOURCE 1

#ifdef HAVE_GETMNTENT_R
	/* getmntent_r() */
# define _GNU_SOURCE	1
#endif

#include <stdio.h>	/* sscanf(), FILE */

#ifdef HAVE_MNTENT_H
# include <mntent.h>
#endif

#ifdef HAVE_PATHS_H
# include <paths.h>
#endif

#ifndef _PATH_DEVNULL
# define	_PATH_DEVNULL	"/dev/null"
#endif

#ifndef _PATH_MOUNTED
# ifdef MNT_MNTTAB
#  define	_PATH_MOUNTED	MNT_MNTTAB
# else
#  define	_PATH_MOUNTED	"/etc/mtab"
# endif
#endif

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

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#else
# include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
# if (!STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>	/* strncpy() */
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* access(), close(), dup2(), fork() */
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifdef HAVE_SCHED_H
# include <sched.h>
#endif

#include "wipefreespace.h"
#include "wfs_xfs.h"
#include "wfs_signal.h"

#define PIPE_R 0
#define PIPE_W 1
#define XFSBUFSIZE 240

errcode_enum WFS_ATTR ((warn_unused_result))
wfs_xfs_wipe_unrm ( const wfs_fsid_t FS WFS_ATTR ((unused)) )
{
	/* The XFS has no undelete capability. */
	return WFS_SUCCESS;
}

errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_xfs_wipe_fs	( const wfs_fsid_t FS, error_type * const error )
{
	unsigned long int i;
	int res;
	int pipe_fd[2];
	int fs_fd;
	int empty_fd;
	FILE *pipe_r;
	pid_t p_f, p_uf, p_db;
	/* 	 xfs_freeze -f (freeze) | -u (unfreeze) mount-point */
	char * args_freeze[] = { "xfs_freeze", "-f", NULL, NULL };
	char * args_unfreeze[] = { "xfs_freeze", "-u", NULL, NULL };
	/*	 xfs_db  -c 'freesp -d' dev_name */
	char *  args_db[] = { "xfs_db", "-i", "-c", "freesp -d",
		NULL, NULL };
	char read_buffer[XFSBUFSIZE];
	unsigned long long agno, agoff, length;
	char * pos1 = NULL;
	unsigned char * buffer;
	unsigned long long j;
	int selected[NPAT];
	errcode_enum ret_wfs = WFS_SUCCESS;

	if ( error == NULL ) return WFS_BADPARAM;

	/* Copy the file system name info the right places */
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	args_db[4] = (char *) malloc ( strlen (FS.xxfs.dev_name) + 1 );
	if ( args_db[4] == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		return WFS_MALLOC;
	}
	strncpy ( args_db[4], FS.xxfs.dev_name, strlen (FS.xxfs.dev_name) + 1 );
	/* we need the mount point here, not the FS device */
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	if ( FS.xxfs.mnt_point != NULL )
	{
		args_freeze[2] = (char *) malloc ( strlen (FS.xxfs.mnt_point) + 1 );
		if ( args_freeze[2] == NULL )
		{
#ifdef HAVE_ERRNO_H
			error->errcode.gerror = errno;
#else
			error->errcode.gerror = 12L;	/* ENOMEM */
#endif
			free (args_db[4]);
			return WFS_MALLOC;
		}
		strncpy ( args_freeze[2], FS.xxfs.mnt_point, strlen (FS.xxfs.mnt_point) + 1 );
		args_unfreeze[2] = args_freeze[2];
	}
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	buffer = (unsigned char *) malloc ( FS.xxfs.wfs_xfs_blocksize );
	if ( buffer == NULL )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 12L;	/* ENOMEM */
#endif
		if ( FS.xxfs.mnt_point != NULL ) free (args_freeze[2]);
		free (args_db[4]);
		return WFS_MALLOC;
	}

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	res = pipe (pipe_fd);
	if ( res < 0 )
	{
#ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
#else
		error->errcode.gerror = 1L;
#endif
		free (buffer);
		free (args_freeze[2]);
		free (args_db[4]);
		return WFS_PIPEERR;
	}
	/* This is required. In case of child error the parent process
	   will hang waiting for data from a closed pipe.
	*/
	fcntl (pipe_fd[PIPE_R], F_SETFL, fcntl (pipe_fd[PIPE_R], F_GETFL) | O_NONBLOCK );
	fcntl (pipe_fd[PIPE_W], F_SETFL, fcntl (pipe_fd[PIPE_W], F_GETFL) | O_NONBLOCK );

	if ( FS.xxfs.mnt_point != NULL )
	{
		/* Freeze the filesystem */
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		p_f = fork ();
		if ( p_f < 0 )
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
			free (args_freeze[2]);
			free (args_db[4]);
			return WFS_FORKERR;
		}
		else if ( p_f == 0 )
		{
			/* child */
			/* redirect output to a closed fd */
# ifdef HAVE_ERRNO_H
			errno = 0;
# endif
			empty_fd = open ( _PATH_DEVNULL, O_WRONLY );
			if ( (empty_fd < 0)
#ifdef HAVE_ERRNO_H
				|| (errno != 0)
#endif
			   )
			{
				close (STDOUT_FILENO);
				close (STDERR_FILENO);
			}
			else
			{
				dup2 (empty_fd, STDOUT_FILENO);
				dup2 (empty_fd, STDERR_FILENO);
				close (empty_fd);
			}
			execvp ( "xfs_freeze", args_freeze );
			/* if we got here, exec() failed and there's nothing to do. */
			close (pipe_fd[PIPE_R]);
			close (pipe_fd[PIPE_W]);
			/* Commit suicide or wait for getting killed */
#if (defined HAVE_GETPID) && (defined HAVE_KILL)
			kill (getpid (), SIGKILL);
#endif
			while (1==1)
			{
#ifdef HAVE_SCHED_YIELD
				sched_yield ();
#endif
			}
			/*return WFS_EXECERR;*/
		}
		else
		{
			/* parent */
#ifdef HAVE_WAITPID
			waitpid (p_f, NULL, 0);
#elif defined HAVE_WAIT
			wait (NULL);
#else
# ifdef HAVE_SLEEP
			sleep (5);
# else
			for (i=0; (i < (1<<31)-1) && (sig_recvd == 0); i++ );
# endif
			kill (p_f, SIGKILL);
#endif
		}
	}	/* if ( FS.xxfs.mnt_point != NULL )  */

	/* parent, continued */
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	p_db = fork ();
	if ( p_db < 0 )
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
		dup2 (pipe_fd[PIPE_W], STDOUT_FILENO);
		dup2 (pipe_fd[PIPE_W], STDERR_FILENO);
		execvp ( "xfs_db", args_db );
		/* if we got here, exec() failed and there's nothing to do. */
		close (pipe_fd[PIPE_R]);
		close (pipe_fd[PIPE_W]);
		/* Commit suicide or wait for getting killed */
#if (defined HAVE_GETPID) && (defined HAVE_KILL)
		kill (getpid (), SIGKILL);
#endif
		while (1==1)
		{
#ifdef HAVE_SCHED_YIELD
			sched_yield ();
#endif
		}
		/*return WFS_EXECERR;*/
	}
	else
	{
		/* parent */
#ifdef HAVE_SLEEP
		sleep (1);
#else
		for (i=0; (i < (1<<30)) && (sig_recvd == 0); i++ );
#endif
		pipe_r = fdopen (pipe_fd[PIPE_R], "r");
		/* open the FS */
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		fs_fd = open64 (FS.xxfs.dev_name, O_WRONLY | O_EXCL);
		if ( (fs_fd < 0)
#ifdef HAVE_ERRNO_H
			|| (errno != 0)
#endif
		   )
		{
			/* can't return from here - have to un-freeze first */
			ret_wfs = WFS_OPENFS;
		}
		while ( (sig_recvd == 0) && (ret_wfs == WFS_SUCCESS) )
		{
			if ( pipe_r == NULL )
			{
				/*read (pipe_fd[PIPE_R], buffer, XFSBUFSIZE-1);*/
				/* read just 1 line */
				res = 0;
				do
				{
					i = read (pipe_fd[PIPE_R], &(read_buffer[res]), 1);
					res++;
				}
				while (     (read_buffer[res-1] != '\n')
					 && (read_buffer[res-1] != '\r')
					 && (res < XFSBUFSIZE)
					 && (i == 1)
					 && (sig_recvd == 0)
					  );
				read_buffer[res++] = '\0';
			}
			else
			{
				pos1 = fgets (read_buffer, XFSBUFSIZE, pipe_r);
			}
#ifdef HAVE_ERRNO_H
			/*if ( errno == EAGAIN ) continue;*/
#endif
			if ( ( ( (pipe_r == NULL) && (res < 0) )
				|| ( (pipe_r != NULL) && (pos1 == NULL) ) )
				|| (sig_recvd != 0)
#ifdef HAVE_ERRNO_H
				|| ( errno != 0 )
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
					FS.xxfs.wfs_xfs_blocksize, SEEK_SET ) !=
						(off64_t) (agno * FS.xxfs.wfs_xfs_agblocks + agoff) *
						FS.xxfs.wfs_xfs_blocksize
				   )
				{
					break;
				}
				fill_buffer ( i, buffer, FS.xxfs.wfs_xfs_blocksize, selected );
				for ( j=0; (j < length) && (sig_recvd == 0); j++ )
				{
					if ( write (fs_fd, buffer, FS.xxfs.wfs_xfs_blocksize)
						!= (ssize_t) FS.xxfs.wfs_xfs_blocksize
					   )
					{
						break;
					}
					/* Flush after each writing, if more than 1 overwriting needs to be done.
					   Allow I/O bufferring (efficiency), if just one pass is needed. */
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
		waitpid (p_db, NULL, 0);
#elif defined HAVE_WAIT
		wait (NULL);
#else
# ifdef HAVE_SLEEP
		sleep (5);
# else
		for (i=0; (i < (1<<31)-1) && (sig_recvd == 0); i++ );
# endif
		kill (p_db, SIGKILL);
#endif
	} /* parent if fork() for xfs_db succeded */

	if ( FS.xxfs.mnt_point != NULL )
	{
		/* un-freeze the filesystem */
		p_uf = fork ();
		if ( p_uf < 0 )
		{
			/* error */
			ret_wfs = WFS_FORKERR;
		}
		else if ( p_uf == 0 )
		{
			/* child */
			/* redirect output to a closed fd */
# ifdef HAVE_ERRNO_H
			errno = 0;
# endif
			empty_fd = open ( _PATH_DEVNULL, O_WRONLY );
			if ( (empty_fd < 0)
#ifdef HAVE_ERRNO_H
				|| (errno != 0)
#endif
			   )
			{
				close (STDOUT_FILENO);
				close (STDERR_FILENO);
			}
			else
			{
				/* the way daemon() used to do it */
				dup2 (empty_fd, STDOUT_FILENO);
				dup2 (empty_fd, STDERR_FILENO);
				close (empty_fd);
			}
			execvp ( "xfs_freeze", args_unfreeze );
			/* if we got here, exec() failed and there's nothing to do. */
			close (pipe_fd[PIPE_R]);
			close (pipe_fd[PIPE_W]);
			/* Commit suicide or wait for getting killed */
#if (defined HAVE_GETPID) && (defined HAVE_KILL)
			kill (getpid (), SIGKILL);
#endif
			while (1==1)
			{
#ifdef HAVE_SCHED_YIELD
				sched_yield ();
#endif
			}
			/*return WFS_EXECERR;*/
		}
		else
		{
		/* parent */
#ifdef HAVE_WAITPID
			waitpid (p_uf, NULL, 0);
#elif defined HAVE_WAIT
			wait (NULL);
#else
# ifdef HAVE_SLEEP
			sleep (5);
# else
			for (i=0; (i < (1<<31)-1) && (sig_recvd == 0); i++ );
# endif
			kill (p_uf, SIGKILL);
#endif
		}
	} /* if ( FS.xxfs.mnt_point != NULL ) */

	close (pipe_fd[PIPE_R]);
	close (pipe_fd[PIPE_W]);

	free (buffer);
	free (args_freeze[2]);
	free (args_db[4]);
	if (sig_recvd != 0) return WFS_SIGNAL;
	return ret_wfs;
}

errcode_enum WFS_ATTR ((warn_unused_result))
wfs_xfs_wipe_part ( const wfs_fsid_t FS WFS_ATTR ((unused)) )
{
	/* FIXME Don't know how to get all the required information
	   (used i-node numbers)
	 xfs_db -c "sb 0" -c "print" ----->
	             icount      number of allocated inodes.
                     ifree       number of allocated inodes that are not in use.
	 xfs_check -i <ino-number>
	 */
	return WFS_SUCCESS;
}

int WFS_ATTR ((warn_unused_result))
wfs_xfs_check_err ( const wfs_fsid_t FS )
{
	/* Requires xfs_db! No output expected.	*/
	int res = 0;
	unsigned long int i;
	int pipe_fd[2];
	FILE *pipe_r;
	pid_t p;
	char *  args[] = { "xfs_check", "   ", NULL, NULL }; /* xfs_check [-f] dev/file */
	char buffer[XFSBUFSIZE];
	char *pos;

#ifdef HAVE_STAT_H
	struct stat s;

	if ( stat (FS.xxfs.dev_name, &s) >= 0 )
	{
		if ( S_ISREG(s.st_mode) )
		{
			strcpy (args[1], "-f");
		}
	}
#endif

	args[2] = FS.xxfs.dev_name;
	if ( pipe (pipe_fd) < 0 )
	{
		return WFS_PIPEERR;
	}
	/* This is required. In case of child error the parent process
	   will hang waiting for data from a closed pipe.
	*/
	fcntl (pipe_fd[PIPE_R], F_SETFL, fcntl (pipe_fd[PIPE_R], F_GETFL) | O_NONBLOCK );
	fcntl (pipe_fd[PIPE_W], F_SETFL, fcntl (pipe_fd[PIPE_W], F_GETFL) | O_NONBLOCK );

	p = fork ();
	if ( p < 0 )
	{
		/* error */
		close (pipe_fd[PIPE_R]);
		close (pipe_fd[PIPE_W]);
		return WFS_FORKERR;
	}
	else if ( p == 0 )
	{
		/* child */
		dup2 (pipe_fd[PIPE_W], STDOUT_FILENO);
		dup2 (pipe_fd[PIPE_W], STDERR_FILENO);
		/*execve ( "/bin/echo", args, NULL );*/
		/*execlp ( "echo", "echo", "XXX", NULL );*/
		execvp ( "xfs_check", args );
		/* if we got here, exec() failed and there's nothing to do. */
		close (pipe_fd[PIPE_R]);
		close (pipe_fd[PIPE_W]);
		/* Commit suicide or wait for getting killed */
#if (defined HAVE_GETPID) && (defined HAVE_KILL)
		kill (getpid (), SIGKILL);
#endif
		while (1==1)
		{
#ifdef HAVE_SCHED_YIELD
			sched_yield ();
#endif
		}
		/*return WFS_EXECERR;*/
	}
	else
	{
#ifdef HAVE_WAITPID
		waitpid (p, NULL, 0);
#elif defined HAVE_WAIT
		wait (NULL);
#else
# ifdef HAVE_SLEEP
		sleep (5);
# else
		for (i=0; (i < (1<<31)-1) && (sig_recvd == 0); i++ );
# endif
		kill (p, SIGKILL);
#endif
		pipe_r = fdopen (pipe_fd[PIPE_R], "r");
		/* any output means error. */
		if ( pipe_r == NULL )
		{
			/*res = read (pipe_fd[PIPE_R], buffer, XFSBUFSIZE-1);*/
			/* read just 1 line */
			res = 0;
			do
			{
				i = read (pipe_fd[PIPE_R], &(buffer[res]), 1);
				res++;
			}
			while (    (buffer[res-1] != '\n')
				&& (buffer[res-1] != '\r')
				&& (res < XFSBUFSIZE)
				&& (i == 1)
				&& (sig_recvd == 0)
				);
		}
		else
		{
			pos = fgets (buffer, XFSBUFSIZE, pipe_r);
		}

		if ( ( (pipe_r == NULL) && (res >= 0) )
			|| ( (pipe_r != NULL) && (pos != NULL) )
		   )
		{
			/* something was read. Filesystem is inconsistent. */
			close (pipe_fd[PIPE_R]);
			close (pipe_fd[PIPE_W]);
			return WFS_FSHASERROR;
		}
	}
	close (pipe_fd[PIPE_R]);
	close (pipe_fd[PIPE_W]);

	return WFS_SUCCESS;
}

int WFS_ATTR ((warn_unused_result))
wfs_xfs_is_dirty ( const wfs_fsid_t FS )
{
	/* FIXME Don't know how to get this information *
	return WFS_SUCCESS;*/
	return wfs_xfs_check_err (FS);
}

int WFS_ATTR ((warn_unused_result))
wfs_xfs_get_block_size ( const wfs_fsid_t FS )
{
	return FS.xxfs.wfs_xfs_blocksize;
}

static errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_xfs_get_mnt_point ( const char * const dev_name, error_type * const error,
	char * const mnt_point, int * const is_rw )
{
#ifdef HAVE_MNTENT_H
	FILE *mnt_f;
	struct mntent *mnt, mnt_copy;
# ifdef HAVE_GETMNTENT_R
#  define MNTBUFLEN 4096
	char buffer[MNTBUFLEN];
# endif
#endif
/*
	if ( (dev_name == NULL) || (error == NULL) || (mnt_point == NULL) || (is_rw == NULL) )
		return WFS_BADPARAM;
*/
	*is_rw = 1;
	strcpy (mnt_point, "");

#ifdef HAVE_MNTENT_H
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	mnt_f = setmntent (_PATH_MOUNTED, "r");
	if (mnt_f == NULL)
	{
# ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
# endif
		return WFS_MNTCHK;
	}
	do
	{
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
# ifndef HAVE_GETMNTENT_R
		mnt = getmntent (mnt_f);
		memcpy ( &mnt_copy, mnt, sizeof (struct mntent) );
# else
		mnt = getmntent_r (mnt_f, &mnt_copy, buffer, MNTBUFLEN);
# endif
		if ( mnt == NULL ) break;
		if ( strcmp (dev_name, mnt->mnt_fsname) == 0 ) break;

	} while ( 1==1 );

	endmntent (mnt_f);
	if ( (mnt == NULL)
# ifdef HAVE_ERRNO_H
		&& (errno == 0)
# endif
	   )
	{
		*is_rw = 0;
		return WFS_SUCCESS;	/* seems not to be mounted */
	}
# ifdef HAVE_HASMNTOPT
	if (hasmntopt (mnt, "rw") != NULL)
	{
		error->errcode.gerror = 1L;
		*is_rw = 1;
		strcpy (mnt_point, mnt->mnt_dir);
		return WFS_MNTRW;
	}
# else
	error->errcode.gerror = 1L;
	*is_rw = 1;
	strcpy (mnt_point, mnt->mnt_dir);
	return WFS_MNTRW;	/* can't check for r/w, so don't do anything */
# endif
	*is_rw = 0;
	strcpy (mnt_point, mnt->mnt_dir);
	return WFS_SUCCESS;
#else	/* ! HAVE_MNTENT_H */
	error->errcode.gerror = 1L;
	return WFS_MNTCHK;	/* can't check, so don't do anything */
#endif	/* HAVE_MNTENT_H */
}

errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_xfs_chk_mount ( const char * const dev_name, error_type * const error )
{
	errcode_enum res;
	int is_rw;
	char buffer[MNTBUFLEN];

	res = wfs_xfs_get_mnt_point (dev_name, error, buffer, &is_rw);
	if ( res != WFS_SUCCESS )
	{
		return res;
	}
	/*
	else if ( is_rw != 0 )
	{
		* impossible to get here right now *
		return WFS_MNTRW;
	}
	*/
	else
	{
		return WFS_SUCCESS;
	}
}

errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
wfs_xfs_open_fs ( const char * const dev_name, wfs_fsid_t* const FS, CURR_FS * const whichfs,
		  const fsdata * const data WFS_ATTR ((unused)), error_type * const error )
{
	int res = 0;
	errcode_enum mnt_ret;
	unsigned long int i;
	int pipe_fd[2];
	FILE *pipe_r;
	pid_t p;
	char *  args[] = { "xfs_db", "-i", "-c", "sb 0", "-c", "print",
		NULL, NULL }; /* xfs_db -c 'sb 0' -c print dev_name */
	char buffer[XFSBUFSIZE];
	int blocksize_set = 0, agblocks_set = 0;
#define search1 "blocksize = "
#define search2 "agblocks = "
	char *pos1 = NULL, *pos2 = NULL;
	int is_rw;

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
	args[6] = FS->xxfs.dev_name;

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
		free (FS->xxfs.dev_name);
		return WFS_OPENFS;
	}
#endif
	/* Fill wfs_xfs_blocksize and wfs_xfs_agblocks */
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	if ( pipe (pipe_fd) < 0 )
	{
# ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
# else
		error->errcode.gerror = 1L;
# endif
		free (FS->xxfs.dev_name);
		return WFS_PIPEERR;
	}
	/* This is required. In case of child error the parent process
	   will hang waiting for data from a closed pipe.
	*/
	fcntl (pipe_fd[PIPE_R], F_SETFL, fcntl (pipe_fd[PIPE_R], F_GETFL) | O_NONBLOCK );
	fcntl (pipe_fd[PIPE_W], F_SETFL, fcntl (pipe_fd[PIPE_W], F_GETFL) | O_NONBLOCK );

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	p = fork ();
	if ( p < 0 )
	{
		/* error */
# ifdef HAVE_ERRNO_H
		error->errcode.gerror = errno;
# else
		error->errcode.gerror = 1L;
# endif
		free (FS->xxfs.dev_name);
		return WFS_FORKERR;
	}
	else if ( p == 0 )
	{
		/* child */
		dup2 (pipe_fd[PIPE_W], STDOUT_FILENO);
		dup2 (pipe_fd[PIPE_W], STDERR_FILENO);
		/*execve ( "/bin/echo", args, NULL );*/
		/*execlp ( "echo", "echo", "XXX", NULL );*/
		execvp ( "xfs_db", args );
		/* if we got here, exec() failed and there's nothing to do. */
		close (pipe_fd[PIPE_R]);
		close (pipe_fd[PIPE_W]);
		/* Commit suicide or wait for getting killed */
#if (defined HAVE_GETPID) && (defined HAVE_KILL)
		kill (getpid (), SIGKILL);
#endif
		while (1==1)
		{
#ifdef HAVE_SCHED_YIELD
			sched_yield ();
#endif
		}
		/*return WFS_EXECERR;*/
	}
	else
	{
		/* parent */
#ifdef HAVE_WAITPID
		waitpid (p, NULL, 0);
#elif defined HAVE_WAIT
		wait (NULL);
#else
# ifdef HAVE_SLEEP
		sleep (5);
# else
		for (i=0; (i < (1<<31)-1) && (sig_recvd == 0); i++ );
# endif
		kill (p, SIGKILL);
#endif
		pipe_r = fdopen (pipe_fd[PIPE_R], "r");
		while ( ((blocksize_set == 0) || (agblocks_set == 0)) && (sig_recvd == 0) )
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
			if ( pipe_r == NULL )
			{
				/*res = read (pipe_fd[PIPE_R], buffer, XFSBUFSIZE-1);*/
				/* read just 1 line */
				res = 0;
				do
				{
					i = read (pipe_fd[PIPE_R], &(buffer[res]), 1);
					res++;
				}
				while (    (buffer[res-1] != '\n')
					&& (buffer[res-1] != '\r')
					&& (res < XFSBUFSIZE)
					&& (i == 1)
					&& (sig_recvd == 0)
					);
			}
			else
			{
				pos1 = fgets (buffer, XFSBUFSIZE, pipe_r);
			}
#ifdef HAVE_ERRNO_H
			/*if ( errno == EAGAIN ) continue;*/
#endif
			if ( ( ( (pipe_r == NULL) && (res < 0) )
				|| ( (pipe_r != NULL) && (pos1 == NULL) ) )
				|| (sig_recvd != 0)
#ifdef HAVE_ERRNO_H
				|| ( errno != 0 )
#endif
			   )
			{
#ifdef HAVE_WAITPID
				waitpid (p, NULL, 0);
#elif defined HAVE_WAIT
				wait (NULL);
#else
# ifdef HAVE_SLEEP
				sleep (5);
# else
				for (i=0; (i < (1<<31)-1) && (sig_recvd == 0); i++ );
# endif
				kill (p, SIGKILL);
#endif
				close (pipe_fd[PIPE_R]);
				close (pipe_fd[PIPE_W]);
				free (FS->xxfs.dev_name);
				return WFS_OPENFS;
			}
			buffer[XFSBUFSIZE-1] = '\0';
			pos1 = strstr (buffer, search1);
			pos2 = strstr (buffer, search2);
			if ( (pos1 == NULL) && (pos2 == NULL) )
			{
				continue;
			}
			if ( pos1 != NULL )
			{
				res = sscanf (pos1, search1 "%lu", &(FS->xxfs.wfs_xfs_blocksize) );
				if ( res != 1 )
				{
#ifdef HAVE_WAITPID
					waitpid (p, NULL, 0);
#elif defined HAVE_WAIT
					wait (NULL);
#else
# ifdef HAVE_SLEEP
					sleep (5);
# else
					for (i=0; (i < (1<<31)-1) && (sig_recvd == 0); i++ );
# endif
					kill (p, SIGKILL);
#endif
					close (pipe_fd[PIPE_R]);
					close (pipe_fd[PIPE_W]);
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
#ifdef HAVE_WAITPID
					waitpid (p, NULL, 0);
#elif defined HAVE_WAIT
					wait (NULL);
#else
# ifdef HAVE_SLEEP
					sleep (5);
# else
					for (i=0; (i < (1<<31)-1) && (sig_recvd == 0); i++ );
# endif
					kill (p, SIGKILL);
#endif
					close (pipe_fd[PIPE_R]);
					close (pipe_fd[PIPE_W]);
					free (FS->xxfs.dev_name);
					return WFS_OPENFS;
				}
				agblocks_set = 1;
			}
		}	/* while */
		close (pipe_fd[PIPE_R]);
		close (pipe_fd[PIPE_W]);
#ifdef HAVE_WAITPID
		waitpid (p, NULL, 0);
#elif defined HAVE_WAIT
		wait (NULL);
#else
# ifdef HAVE_SLEEP
		sleep (5);
# else
		for (i=0; (i < (1<<31)-1) && (sig_recvd == 0); i++ );
# endif
		kill (p, SIGKILL);
#endif
	}	/* else - parent */

	if (sig_recvd != 0) return WFS_SIGNAL;
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
			free (FS->xxfs.dev_name);
			return WFS_MALLOC;
		}
		strncpy ( FS->xxfs.mnt_point, buffer, strlen (buffer) + 1 );
	}

	if (sig_recvd != 0) return WFS_SIGNAL;
	*whichfs = CURR_XFS;
	return WFS_SUCCESS;
}

errcode_enum
wfs_xfs_close_fs ( wfs_fsid_t FS, error_type * const error
#ifndef HAVE_ERRNO_H
	WFS_ATTR ((unused))
#endif
)
{
#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	free (FS.xxfs.mnt_point);
	free (FS.xxfs.dev_name);
#ifdef HAVE_ERRNO_H
	if ( errno != 0 )
	{
		error->errcode.gerror = errno;
		return WFS_FSCLOSE;
	}
	else
#endif
		return WFS_SUCCESS;
}

errcode_enum
wfs_xfs_flush_fs ( const wfs_fsid_t FS WFS_ATTR ((unused)) )
{
	/* Better than nothing */
#if (!defined __STRICT_ANSI__)
	sync ();
#endif
	return WFS_SUCCESS;
}
