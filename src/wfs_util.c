/*
 * A program for secure cleaning of free space on filesystems.
 *	-- utility functions.
 *
 * Copyright (C) 2007-2010 Bogdan Drozdowski, bogdandr (at) op.pl
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

#ifdef HAVE_GETMNTENT_R
	/* getmntent_r() */
# define _GNU_SOURCE	1
#endif

#include <stdio.h>	/* FILE */

#ifdef HAVE_STRING_H
# if ((!defined STDC_HEADERS) || (!STDC_HEADERS)) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>	/* strncpy() */
#endif

#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>	/* required for sys/mount.h on some systems */
#endif

#ifdef HAVE_MNTENT_H
# include <mntent.h>
#endif

#ifdef HAVE_SYS_STATFS_H
# include <sys/statfs.h>
#endif

#ifdef HAVE_SYS_MOUNT_H
# include <sys/mount.h>
#endif

#ifdef HAVE_SYS_VFS_H
# include <sys/vfs.h>
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

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* access(), close(), dup2(), fork(), sync(), STDIN_FILENO,
			   STDOUT_FILENO, STDERR_FILENO */
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif
#ifndef ECHILD
# define ECHILD 10
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* exit() */
#endif

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#else
# ifdef HAVE_WAIT_H
#  include <wait.h>
# endif
#endif
#ifndef WEXITSTATUS
# define WEXITSTATUS(stat_val) ((unsigned int)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
# define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif
#ifndef WIFSIGNALED
# define WIFSIGNALED(status) (((signed char) (((status) & 0x7f) + 1) >> 1) > 0)
#endif

#ifdef HAVE_SCHED_H
# include <sched.h>
#endif

#include "wipefreespace.h"
#include "wfs_util.h"

#ifndef EXIT_FAILURE
# define EXIT_FAILURE (1)
#endif

#ifndef MNTOPT_RW
# define MNTOPT_RW	"rw"
#endif

#ifndef STDIN_FILENO
# define STDIN_FILENO	0
#endif

#ifndef STDOUT_FILENO
# define STDOUT_FILENO	1
#endif

#ifndef STDERR_FILENO
# define STDERR_FILENO	2
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
errcode_enum WFS_ATTR ((warn_unused_result))
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_get_mnt_point (
#ifdef WFS_ANSIC
	const char * const dev_name
# if !(((defined HAVE_MNTENT_H) && ((defined HAVE_GETMNTENT) || (defined HAVE_GETMNTENT_R))) \
	|| ((defined HAVE_SYS_MOUNT_H) && (defined HAVE_GETMNTINFO)))
		WFS_ATTR ((unused))
# endif
	, error_type * const error,
	char * const mnt_point, const size_t mnt_point_len
# if !(((defined HAVE_MNTENT_H) && ((defined HAVE_GETMNTENT) || (defined HAVE_GETMNTENT_R))) \
	|| ((defined HAVE_SYS_MOUNT_H) && (defined HAVE_GETMNTINFO)))
		WFS_ATTR ((unused))
# endif
	, int * const is_rw )
#else
	dev_name
# if !(((defined HAVE_MNTENT_H) && ((defined HAVE_GETMNTENT) || (defined HAVE_GETMNTENT_R))) \
	|| ((defined HAVE_SYS_MOUNT_H) && (defined HAVE_GETMNTINFO)))
		WFS_ATTR ((unused))
# endif
	, error, mnt_point, mnt_point_len
# if !(((defined HAVE_MNTENT_H) && ((defined HAVE_GETMNTENT) || (defined HAVE_GETMNTENT_R))) \
	|| ((defined HAVE_SYS_MOUNT_H) && (defined HAVE_GETMNTINFO)))
		WFS_ATTR ((unused))
# endif
	, is_rw )
	const char * const dev_name;
	error_type * const error;
	char * const mnt_point;
	const size_t mnt_point_len;
	int * const is_rw;
#endif
{
#if (defined HAVE_MNTENT_H) && ((defined HAVE_GETMNTENT) || (defined HAVE_GETMNTENT_R))
	FILE *mnt_f;
	struct mntent *mnt, mnt_copy;
# ifdef HAVE_GETMNTENT_R
	char buffer[WFS_MNTBUFLEN];
# endif
#else	/* ! HAVE_MNTENT_H */
# if (defined HAVE_SYS_MOUNT_H) && (defined HAVE_GETMNTINFO)
	struct statfs * filesystems = NULL;
	int count;
	int i;
# endif
#endif
/*
	if ( (dev_name == NULL) || (error == NULL) || (mnt_point == NULL) || (is_rw == NULL) )
		return WFS_BADPARAM;
*/
	*is_rw = 1;
	mnt_point[0] = '\0';

#if (defined HAVE_MNTENT_H) && ((defined HAVE_GETMNTENT) || (defined HAVE_GETMNTENT_R))
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
		mnt = getmntent_r (mnt_f, &mnt_copy, buffer, WFS_MNTBUFLEN);
# endif
		if ( mnt == NULL ) break;
		if ( strcmp (dev_name, mnt->mnt_fsname) == 0 ) break;

	} while ( 1==1 );

	endmntent (mnt_f);
	if ( (mnt == NULL)
# ifdef HAVE_ERRNO_H
/*		&& (errno == 0)*/
# endif
	   )
	{
		*is_rw = 0;
		return WFS_SUCCESS;	/* seems not to be mounted */
	}
# ifdef HAVE_HASMNTOPT
	if (hasmntopt (mnt, MNTOPT_RW) != NULL)
	{
		error->errcode.gerror = 1L;
		*is_rw = 1;
		strncpy (mnt_point, mnt->mnt_dir, mnt_point_len);
		mnt_point[mnt_point_len] = '\0';
		return WFS_MNTRW;
	}
# else
	error->errcode.gerror = 1L;
	*is_rw = 1;
	strncpy (mnt_point, mnt->mnt_dir, mnt_point_len);
	mnt_point[mnt_point_len] = '\0';
	return WFS_MNTRW;	/* can't check for r/w, so don't do anything */
# endif
	*is_rw = 0;
	strncpy (mnt_point, mnt->mnt_dir, mnt_point_len);
	mnt_point[mnt_point_len] = '\0';
	return WFS_SUCCESS;
#else	/* ! HAVE_MNTENT_H */
# if (defined HAVE_SYS_MOUNT_H) && (defined HAVE_GETMNTINFO)
	count = getmntinfo (&filesystems, 0);
	if ( (count <= 0) || (filesystems == NULL) )
	{
		error->errcode.gerror = 1L;
		return WFS_MNTCHK;	/* can't check, so don't do anything */
	}
	else
	{
		/* BSD systems have a 'u_int32_t f_flags' in "struct statfs". This
		   field is a copy of the mount flags. */
		for ( i = 0; i < count; i++ )
		{
			if ( (strcmp (dev_name, filesystems[i].f_mntfromname) == 0)
				&& ((filesystems[i].f_flags & MNT_RDONLY) != MNT_RDONLY) )
			{
				error->errcode.gerror = 1L;
				*is_rw = 1;
				strncpy (mnt_point, filesystems[i].f_mntonname, mnt_point_len);
				mnt_point[mnt_point_len] = '\0';
				return WFS_MNTRW;
			}
		}
		*is_rw = 0;
		return WFS_SUCCESS;
	}
# else /* ! HAVE_MNTENT_H && ! HAVE_GETMNTINFO */
	error->errcode.gerror = 1L;
	return WFS_MNTCHK;	/* can't check, so don't do anything */
# endif
#endif	/* HAVE_MNTENT_H */
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
wfs_check_mounted (
#ifdef WFS_ANSIC
	const char * const dev_name, error_type * const error )
#else
	dev_name, error )
	const char * const dev_name;
	error_type * const error;
#endif
{
	errcode_enum res;
	int is_rw;
	char buffer[WFS_MNTBUFLEN];

	if ( error == NULL )
	{
		return WFS_BADPARAM;
	}

	res = wfs_get_mnt_point (dev_name, error, buffer, sizeof (buffer), &is_rw);
	buffer[WFS_MNTBUFLEN-1] = '\0';
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

/*
 * The child function called after successful creating a child process.
 */
static void *
child_function (
#ifdef WFS_ANSIC
	void * p
# if ! ((defined HAVE_EXECVP) && (defined HAVE_CLOSE) && (defined HAVE_DUP2))
		WFS_ATTR ((unused))
# endif
	)
#else
	p)
	void * p
# if ! ((defined HAVE_EXECVP) && (defined HAVE_CLOSE) && (defined HAVE_DUP2))
		WFS_ATTR ((unused))
# endif
	;
#endif
{
#if (defined HAVE_EXECVP) && (defined HAVE_CLOSE) && (defined HAVE_DUP2)
	const struct child_id * const id = (struct child_id *) p;
	int res;
	if ( p != NULL )
	{
		close (STDIN_FILENO);
		close (STDOUT_FILENO);
		close (STDERR_FILENO);
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		if ( id->stdin_fd != -1 )
		{
			res = dup2 (id->stdin_fd, STDIN_FILENO);
			if ( (res != STDIN_FILENO)
# ifdef HAVE_ERRNO_H
/*				|| (errno != 0)*/
# endif
				)
			{
				/* error redirecting stdin */
				if ( id->type == CHILD_FORK ) exit (EXIT_FAILURE);
			}
		}
		if ( id->stdout_fd != -1 )
		{
			res = dup2 (id->stdout_fd, STDOUT_FILENO);
			if ( (res != STDOUT_FILENO)
# ifdef HAVE_ERRNO_H
/*				|| (errno != 0)*/
# endif
				)
			{
				/* error redirecting stdout */
				if ( id->type == CHILD_FORK ) exit (EXIT_FAILURE);
			}
		}
		if ( id->stderr_fd != -1 )
		{
			res = dup2 (id->stderr_fd, STDERR_FILENO);
			if ( (res != STDERR_FILENO)
# ifdef HAVE_ERRNO_H
/*				|| (errno != 0)*/
# endif
				)
			{
				/* error redirecting stderr */
				if ( id->type == CHILD_FORK ) exit (EXIT_FAILURE);
			}
		}
		execvp ( id->program_name, id->args );
	}
#endif /* HAVE_EXECVP */
	/* if we got here, exec() failed or is unavailable and there's nothing to do. */
	/* NOTE: exit() is needed or the parent will wait forever */
	exit (EXIT_FAILURE);
	/* Die or wait for getting killed *
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

/**
 * Launches a child process that runs the given program with the given arguments,
 * redirecting its input, output and error output to the given file descriptors.
 * \param id A structure describing the child process to create and containing its data after creation.
 * \return WFS_SUCCESS on success, other values otherwise.
 */
errcode_enum WFS_ATTR ((warn_unused_result))
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_create_child (
#ifdef WFS_ANSIC
	struct child_id * const id)
#else
	id )
	struct child_id * const id;
#endif
{
	if ( id == NULL ) return WFS_BADPARAM;

#ifdef HAVE_FORK
	id->chld_id.chld_pid = fork ();
	if ( id->chld_id.chld_pid < 0 ) return WFS_FORKERR;
	else if ( id->chld_id.chld_pid == 0 )
	{
		child_function (id);
		/* Not all compilers may detect that child_function() will never return, so
		   return here just in case. */
		return WFS_SUCCESS;
	}
	else
	{
		/* parent */
		id->type = CHILD_FORK;
		return WFS_SUCCESS;
	}
#else
	/* PThreads shouldn't be used, because an exit() in a thread causes the whole
	   program to be closed. Besides, there is no portable way to check if a thread
	   is still working / has finished (another thread can't be used, because exec*()
	   kills all threads). */
	return WFS_EXECERR;
#endif
}

/**
 * Waits for the specified child process to finish working.
 * \param id A structure describing the child process to wait for.
 */
void
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_wait_for_child (
#ifdef WFS_ANSIC
	const struct child_id * const id)
#else
	id )
	const struct child_id * const id;
#endif
{
	if ( id == NULL ) return;
	if ( id->type == CHILD_FORK )
	{
#ifdef HAVE_WAITPID
		waitpid (id->chld_id.chld_pid, NULL, 0);
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
		kill (id->chld_id.chld_pid, SIGKILL);
#  endif	/* HAVE_SIGNAL_H */
# endif
#endif
	}
}

/**
 * Tells if the specified child process finished working.
 * \param id A structure describing the child process to check.
 * \return 0 if the child is still active.
 */
int
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_has_child_exited (
#ifdef WFS_ANSIC
	const struct child_id * const id)
#else
	id )
	const struct child_id * const id;
#endif
{
#ifdef HAVE_WAITPID
	int status;
	int ret;
#endif
	if ( id == NULL ) return 1;
	if ( id->type == CHILD_FORK )
	{
#ifdef HAVE_WAITPID
		ret = waitpid (id->chld_id.chld_pid, &status, WNOHANG);
		if ( ret > 0 )
		{
# ifdef WIFEXITED
			if ( WIFEXITED (status) ) return 1;
# endif
# ifdef WIFSIGNALED
			if ( WIFSIGNALED (status) ) return 1;
# endif
		}
		else if ( ret < 0 )
		{
# ifdef HAVE_ERRNO_H
			/* No child processes? Then the child must have exited already. */
			if ( errno == ECHILD ) return 1;
# endif
		}
		return 0;
#else
		return 1;
#endif
	}
	return 0;
}
