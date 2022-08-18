/*
 * A program for secure cleaning of free space on filesystems.
 *	-- utility functions.
 *
 * Copyright (C) 2007-2013 Bogdan Drozdowski, bogdandr (at) op.pl
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

#if (defined HAVE_PUTENV) || (defined HAVE_SETENV)
# define _XOPEN_SOURCE 600
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
# include <unistd.h>	/* close(), dup2(), fork(), sync(), STDIN_FILENO,
			   STDOUT_FILENO, STDERR_FILENO */
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif
#ifndef ECHILD
# define ECHILD 10
#endif

/*
#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif
*/

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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>	/* for open() */
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>	/* for open() */
#endif

#if (defined HAVE_FCNTL_H) && (defined HAVE_SYS_IOCTL_H)
# include <fcntl.h>     /* O_RDWR, open() for ioctl() */
# include <sys/ioctl.h>
#else
# undef HAVE_IOCTL
#endif

#ifdef HAVE_LINUX_HDREG_H
# include <linux/hdreg.h>
#else
# ifdef HAVE_HDREG_H
#  include <hdreg.h>
# else
#  define HDIO_DRIVE_CMD	0x031f
#  define HDIO_GET_WCACHE	0x030e
#  define HDIO_SET_WCACHE	0x032b
# endif
#endif

#ifdef HAVE_LIBINTL_H
# include <libintl.h>	/* translation stuff */
#endif

#ifdef HAVE_LOCALE_H
# include <locale.h>
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

/* ======================================================================== */

/**
 * Gets the mount point of the given device (if mounted).
 * \param dev_name Device to check.
 * \param error Pointer to error variable.
 * \param mnt_point Array for the mount point.
 * \param is_rw Pointer to a variavle which will tell if the filesystem
 *	is mounted in read+write mode (=1 if yes).
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
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
	, wfs_errcode_t * const error,
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
	wfs_errcode_t * const error;
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
	if ( mnt_f == NULL )
	{
# ifdef HAVE_ERRNO_H
		if ( error != NULL )
		{
			*error = (wfs_errcode_t)errno;
		}
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
		memcpy (&mnt_copy, mnt, sizeof (struct mntent));
# else
		mnt = getmntent_r (mnt_f, &mnt_copy, buffer, WFS_MNTBUFLEN);
# endif
		if ( mnt == NULL )
		{
			break;
		}
		if ( strcmp (dev_name, mnt->mnt_fsname) == 0 )
		{
			break;
		}

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
		if ( error != NULL )
		{
			*error = (wfs_errcode_t)1L;
		}
		*is_rw = 1;
		strncpy (mnt_point, mnt->mnt_dir, mnt_point_len);
		mnt_point[mnt_point_len] = '\0';
		return WFS_MNTRW;
	}
# else
	if ( error != NULL )
	{
		*error = (wfs_errcode_t)1L;
	}
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
		if ( error != NULL )
		{
			*error = (wfs_errcode_t)1L;
		}
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
				if ( error != NULL )
				{
					*error = (wfs_errcode_t)1L;
				}
				*is_rw = 1;
				strncpy (mnt_point, filesystems[i].f_mntonname, mnt_point_len);
				mnt_point[mnt_point_len] = '\0';
				return WFS_MNTRW;
			}
		}
		*is_rw = 0;
		return WFS_SUCCESS;
	}
# else /* ! HAVE_SYS_MOUNT_H && ! HAVE_GETMNTINFO */
	if ( error != NULL )
	{
		*error = (wfs_errcode_t)1L;
	}
	return WFS_MNTCHK;	/* can't check, so don't do anything */
# endif
#endif	/* HAVE_MNTENT_H */
}


/* ======================================================================== */

/**
 * Checks if the given filesystem is mounted in read-write mode.
 * \param devname Device name, like /dev/hdXY
 * \param error Pointer to error variable.
 * \return 0 in case of no errors, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_check_mounted (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
#endif
{
	wfs_errcode_t res;
	int is_rw;
	char buffer[WFS_MNTBUFLEN];

	res = wfs_get_mnt_point (wfs_fs.fsname, wfs_fs.fs_error, buffer,
		sizeof (buffer), &is_rw);
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

/* ======================================================================== */

#ifndef WFS_ANSIC
static void * child_function WFS_PARAMS ((void * p));
#endif

/*
 * The child function called after successful creating a child process.
 */
static void *
child_function (
#ifdef WFS_ANSIC
	void * p
	)
#else
	p)
	void * p;
#endif
{
#if (!defined HAVE_EXECVPE) && ((defined HAVE_PUTENV) || (defined HAVE_SETENV))
	int envi;
# if (!defined HAVE_PUTENV) && (defined HAVE_SETENV)
	int equindex;
	char * equpos;
# endif
#endif
	const child_id_t * const id = (child_id_t *) p;
	int res;
#ifdef HAVE_EXECVPE
	char * null_env[] = { NULL };
#endif

	if ( id != NULL )
	{
#if (defined HAVE_CLOSE)
		close (STDIN_FILENO);
		close (STDOUT_FILENO);
		close (STDERR_FILENO);
#endif

#if (defined HAVE_DUP2)
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
				if ( id->type == CHILD_FORK )
				{
					exit (EXIT_FAILURE);
				}
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
				if ( id->type == CHILD_FORK )
				{
					exit (EXIT_FAILURE);
				}
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
				if ( id->type == CHILD_FORK )
				{
					exit (EXIT_FAILURE);
				}
			}
		}
#endif /* HAVE_DUP2 */

#ifdef HAVE_EXECVPE
		if ( id->child_env != NULL )
		{
			execvpe (id->program_name, id->args, id->child_env);
		}
		else
		{
			execvpe (id->program_name, id->args, null_env);
		}
#else /* ! HAVE_EXECVPE */
		/* Debian 5 seems to be missing execvpe(), so we must rewrite
		the environment by hand and run the program with execvp() */
# ifdef HAVE_EXECVP
		if ( id->child_env != NULL )
		{
#  ifdef HAVE_PUTENV
			envi = 0;
			while (id->child_env[envi] != NULL)
			{
				putenv (id->child_env[envi]);
				envi++;
			}
#  else /* ! HAVE_PUTENV */
#   ifdef HAVE_SETENV
			envi = 0;
			while (id->child_env[envi] != NULL)
			{
				equpos = strchr (id->child_env[envi], '=');
				if ( equpos == NULL )
				{
					setenv (id->child_env[envi], "", 1);
				}
				else
				{
					equindex = equpos - id->child_env[envi];
					id->child_env[envi][equindex] = '\0';
					setenv (id->child_env[envi],
						&(id->child_env[envi][equindex+1]), 1);
				}
				envi++;
			}
#   endif /* HAVE_SETENV */
#  endif /* HAVE_PUTENV */
		}
		execvp (id->program_name, id->args);
# endif /* HAVE_EXECVP */
#endif /* HAVE_EXECVPE */
	}
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

/* ======================================================================== */

/**
 * Launches a child process that runs the given program with the given arguments,
 * redirecting its input, output and error output to the given file descriptors.
 * \param id A structure describing the child process to create and containing its data after creation.
 * \return WFS_SUCCESS on success, other values otherwise.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_create_child (
#ifdef WFS_ANSIC
	child_id_t * const id)
#else
	id )
	child_id_t * const id;
#endif
{
	if ( id == NULL )
	{
		return WFS_BADPARAM;
	}

#ifdef HAVE_FORK
	id->chld_id.chld_pid = fork ();
	if ( id->chld_id.chld_pid < 0 )
	{
		return WFS_FORKERR;
	}
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

/* ======================================================================== */

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
	const child_id_t * const id)
#else
	id )
	const child_id_t * const id;
#endif
{
	if ( id == NULL )
	{
		return;
	}
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

/* ======================================================================== */

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
	const child_id_t * const id)
#else
	id )
	const child_id_t * const id;
#endif
{
#ifdef HAVE_WAITPID
	int status;
	int ret;
#endif
	if ( id == NULL )
	{
		return 1;
	}
	if ( id->type == CHILD_FORK )
	{
#ifdef HAVE_WAITPID
		ret = waitpid (id->chld_id.chld_pid, &status, WNOHANG);
		if ( ret > 0 )
		{
# ifdef WIFEXITED
			if ( WIFEXITED (status) )
			{
				return 1;
			}
# endif
# ifdef WIFSIGNALED
			if ( WIFSIGNALED (status) )
			{
				return 1;
			}
# endif
		}
		else if ( ret < 0 )
		{
# ifdef HAVE_ERRNO_H
			/* No child processes? Then the child must have exited already. */
			if ( errno == ECHILD )
			{
				return 1;
			}
# endif
		}
		return 0;
#else
		return 1;
#endif
	}
	return 0;
}

/* ======================================================================== */

#ifdef malloc

# define rpl_malloc 1
# if malloc == 1	/* replacement function requested */
#  undef rpl_malloc
#  undef malloc

/* Replacement malloc() function */
void *
rpl_malloc (
#  ifdef WFS_ANSIC
	size_t n)
#  else
	n)
	size_t n;
#  endif
{
	if (n == 0)
	{
		n = 1;
	}
	return malloc (n);
}
# endif
# undef rpl_malloc
#endif /* malloc */

/* ======================================================================== */

/**
 * Converts the filesystem type (enum) to filesystem name.
 * \param fs The filesystem to convert.
 * \return The filesystem name
 */
const char *
convert_fs_to_name (
#ifdef WFS_ANSIC
	const wfs_curr_fs_t fs)
#else
	fs)
	const wfs_curr_fs_t fs;
#endif
{
	if ( fs == WFS_CURR_FS_NONE )
	{
		return "<none>";
	}
	else if ( fs == WFS_CURR_FS_EXT234FS )
	{
		return "ext2/3/4";
	}
	else if ( fs == WFS_CURR_FS_NTFS )
	{
		return "NTFS";
	}
	else if ( fs == WFS_CURR_FS_XFS )
	{
		return "XFS";
	}
	else if ( fs == WFS_CURR_FS_REISERFS )
	{
		return "ReiserFSv3";
	}
	else if ( fs == WFS_CURR_FS_REISER4 )
	{
		return "Reiser4";
	}
	else if ( fs == WFS_CURR_FS_FATFS )
	{
		return "FAT12/16/32";
	}
	else if ( fs == WFS_CURR_FS_MINIXFS )
	{
		return "MinixFSv1/2";
	}
	else if ( fs == WFS_CURR_FS_JFS )
	{
		return "JFS";
	}
	else if ( fs == WFS_CURR_FS_HFSP )
	{
		return "HFS+";
	}
	else if ( fs == WFS_CURR_FS_OCFS )
	{
		return "OCFS";
	}
	return "<unknown>";
}

/* ======================================================================== */

/**
 * Re-enables drive cache when the wiping function is about to finish.
 * \param dev_name The name of the device.
 * \param total_fs The total number of filesystems in the ioctls array.
 * \param ioctls The array of filesystems.
 */
wfs_errcode_t
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
enable_drive_cache (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs
#ifndef HAVE_IOCTL
		WFS_ATTR ((unused))
#endif
	, const int total_fs
#ifndef HAVE_IOCTL
		WFS_ATTR ((unused))
#endif
	, fs_ioctl_t ioctls[]
#ifndef HAVE_IOCTL
		WFS_ATTR ((unused))
#endif
	)
#else
	wfs_fs
#ifndef HAVE_IOCTL
		WFS_ATTR ((unused))
#endif
	, total_fs
#ifndef HAVE_IOCTL
		WFS_ATTR ((unused))
#endif
	, ioctls
#ifndef HAVE_IOCTL
		WFS_ATTR ((unused))
#endif
	)
	wfs_fsid_t wfs_fs;
	const int total_fs;
	fs_ioctl_t ioctls[];
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;	/* Value returned */
#ifdef HAVE_IOCTL
	int j;
	int curr_ioctl = -1;
	int ioctl_fd;
	unsigned char hd_cmd[4];
	wfs_errcode_t * error_ret = NULL;

	if ( (ioctls != NULL) && (wfs_fs.fsname != NULL) )
	{
		for ( j = 0; j < total_fs; j++ )
		{
			/* ioctls[j].fs_name can't be NULL, it's an array */
			if ( strncmp (ioctls[j].fs_name, wfs_fs.fsname,
				sizeof (ioctls[j].fs_name) - 1) == 0 )
			{
				curr_ioctl = j;
				break;
			}
		}
		if ( (curr_ioctl >= 0) && (curr_ioctl < total_fs) )
		{
			if ( (ioctls[curr_ioctl].how_many == 0)
				&& (ioctls[curr_ioctl].was_enabled != 0) )
			{
				error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
				ioctl_fd = open (ioctls[curr_ioctl].fs_name,
						 O_RDWR | O_EXCL);
				if ( ioctl_fd >= 0 )
				{
					/* enable cache: */
					hd_cmd[0] = 0xef;	/* ATA_OP_SETFEATURES */
					hd_cmd[1] = 0;
					hd_cmd[2] = 0x02;
					hd_cmd[3] = 0;
					j = ioctl (ioctl_fd, HDIO_DRIVE_CMD, hd_cmd);
					if ( j != 0 )
					{
# ifdef HAVE_ERRNO_H
						if ( error_ret != NULL )
						{
							*error_ret = (wfs_errcode_t)errno;
						}
# endif
						ret = WFS_IOCTL;
					}
					else
					{
						ioctls[curr_ioctl].how_many--;
					}
					close (ioctl_fd);
				}
				else
				{
# ifdef HAVE_ERRNO_H
					if ( error_ret != NULL )
					{
						*error_ret = (wfs_errcode_t)errno;
					}
# endif
					ret = WFS_OPENFS;
				}
			}
		}
		else
		{
			ret = WFS_BADPARAM;
		}
	}
	else
	{
		ret = WFS_BADPARAM;
	}
#endif
	return ret;
}

/* ======================================================================== */

/**
 * Disables drive cache when the wiping function is about to finish.
 * \param dev_name The name of the device.
 * \param total_fs The total number of filesystems in the ioctls array.
 * \param ioctls The array of filesystems.
 */
wfs_errcode_t
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
disable_drive_cache (
#ifdef WFS_ANSIC
	wfs_fsid_t wfs_fs
#ifndef HAVE_IOCTL
		WFS_ATTR ((unused))
#endif
	, const int total_fs
#ifndef HAVE_IOCTL
		WFS_ATTR ((unused))
#endif
	, fs_ioctl_t ioctls[]
#ifndef HAVE_IOCTL
		WFS_ATTR ((unused))
#endif
	)
#else
	wfs_fs
#ifndef HAVE_IOCTL
		WFS_ATTR ((unused))
#endif
	, total_fs
#ifndef HAVE_IOCTL
		WFS_ATTR ((unused))
#endif
	, ioctls
#ifndef HAVE_IOCTL
		WFS_ATTR ((unused))
#endif
	)
	wfs_fsid_t wfs_fs;
	const int total_fs;
	fs_ioctl_t ioctls[];
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;	/* Value returned */
#ifdef HAVE_IOCTL
	int j;
	int curr_ioctl = -1;
	int ioctl_fd;
	unsigned char hd_cmd[4];
	wfs_errcode_t * error_ret = NULL;

	if ( (ioctls != NULL) && (wfs_fs.fsname != NULL) )
	{
		for ( j = 0; j < total_fs; j++ )
		{
			if ( strncmp (ioctls[j].fs_name, wfs_fs.fsname,
				sizeof (ioctls[j].fs_name) - 1) == 0 )
			{
				curr_ioctl = j;
				break;
			}
		}
		if ( (curr_ioctl >= 0) && (curr_ioctl < total_fs) )
		{
			error_ret = (wfs_errcode_t *) wfs_fs.fs_error;
			ioctl_fd = open (ioctls[curr_ioctl].fs_name,
				O_RDWR | O_EXCL);
			if ( ioctl_fd >= 0 )
			{
				ioctls[curr_ioctl].was_enabled = 0;
				/* check if caching was enabled */
				ioctl (ioctl_fd, HDIO_GET_WCACHE,
					&ioctls[curr_ioctl].was_enabled);
				/* flush the drive's caches: */
				hd_cmd[0] = 0xe7;	/* ATA_OP_FLUSHCACHE */
				hd_cmd[1] = 0;
				hd_cmd[2] = 0;
				hd_cmd[3] = 0;
				ioctl (ioctl_fd, HDIO_DRIVE_CMD, hd_cmd);
				hd_cmd[0] = 0xea;	/* ATA_OP_FLUSHCACHE_EXT */
				hd_cmd[1] = 0;
				hd_cmd[2] = 0;
				hd_cmd[3] = 0;
				ioctl (ioctl_fd, HDIO_DRIVE_CMD, hd_cmd);
				/* disable cache: */
				hd_cmd[0] = 0xef;	/* ATA_OP_SETFEATURES */
				hd_cmd[1] = 0;
				hd_cmd[2] = 0x82;
				hd_cmd[3] = 0;
				j = ioctl (ioctl_fd, HDIO_DRIVE_CMD, hd_cmd);
				if ( j != 0 )
				{
# ifdef HAVE_ERRNO_H
					if ( error_ret != NULL )
					{
						*error_ret = (wfs_errcode_t)errno;
					}
# endif
					ret = WFS_IOCTL;
				}
				else
				{
					ioctls[curr_ioctl].how_many++;
				}
				close (ioctl_fd);
			}
			else
			{
# ifdef HAVE_ERRNO_H
				if ( error_ret != NULL )
				{
					*error_ret = (wfs_errcode_t)errno;
				}
# endif
				ret = WFS_OPENFS;
			}
		}
		else
		{
			ret = WFS_BADPARAM;
		}
	}
	else
	{
		ret = WFS_BADPARAM;
	}
#endif
	return ret;
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
wfs_show_fs_error_gen (
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
	wfs_errcode_t err = 0;
	const char * progname;

	if ( (wfs_is_stderr_open() == 0) || (msg == NULL) )
	{
		return;
	}
	if ( wfs_fs.fs_error != NULL )
	{
		err = *(wfs_errcode_t *)(wfs_fs.fs_error);
	}

	progname = wfs_get_program_name();
	fprintf (stderr, "%s:%s: %s " WFS_ERR_MSG_FORMAT "\n",
		(progname != NULL)? progname : "",
		(wfs_fs.fsname != NULL)? wfs_fs.fsname : "",
		_(wfs_err_msg),
		_(wfs_err_msg),
		err,
		_(msg),
		(extra != NULL)? extra : "",
		(wfs_fs.fsname != NULL)? wfs_fs.fsname : "");
	fflush (stderr);
}

