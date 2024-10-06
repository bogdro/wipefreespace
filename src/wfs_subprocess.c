/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- subprocess functions.
 *
 * Copyright (C) 2024 Bogdan Drozdowski, bogdro (at) users.sourceforge.net
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
#include "wfs_subprocess.h"

#ifndef EXIT_FAILURE
# define EXIT_FAILURE (1)
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

#if (defined TEST_COMPILE) && (defined WFS_ANSIC)
# undef WFS_ANSIC
#endif

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
#ifdef HAVE_DUP2
	int res;
#endif
#ifdef HAVE_EXECVPE
	char * null_env[] = { NULL };
#endif

	if ( id != NULL )
	{
#if (defined HAVE_DUP2)
		WFS_SET_ERRNO (0);
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
# if (defined HAVE_CLOSE)
		else
		{
			close (STDIN_FILENO);
		}
# endif
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
# if (defined HAVE_CLOSE)
		else
		{
			close (STDOUT_FILENO);
		}
# endif
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
# if (defined HAVE_CLOSE)
		else
		{
			close (STDERR_FILENO);
		}
# endif
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

#ifdef HAVE_WORKING_FORK /* HAVE_FORK */
	id->chld_id.chld_pid = fork ();
	if ( id->chld_id.chld_pid < 0 )
	{
		return WFS_FORKERR;
	}
	else if ( id->chld_id.chld_pid == 0 )
	{
		id->type = CHILD_FORK;
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
