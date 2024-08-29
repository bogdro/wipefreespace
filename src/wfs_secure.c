/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- security-related procedures.
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

#define _LARGEFILE64_SOURCE 1

#include <stdio.h>	/* stdout & stderr */

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>	/* fstat() to check stdout & stderr */
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* clearenv() */
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* get(e)uid(), environ */
#endif

#include "wipefreespace.h"

#ifdef HAVE_SYS_CAPABILITY_H
# include <sys/capability.h>	/* not before ext2fs.h or wipefreespace.h */
#endif

#include "wfs_secure.h"

#if (defined HAVE_SYS_STAT_H) && ((defined HAVE_STAT) || (defined HAVE_STAT64))
# define WFS_HAVE_STAT 1
#else
# undef WFS_HAVE_STAT
#endif

#ifdef TEST_COMPILE
# undef WFS_ANSIC
#endif

/* ======================================================================== */

/**
 * Clears the (POSIX) capabilities of the program.
 * \return 0 on success, other values otherwise.
 */
int GCC_WARN_UNUSED_RESULT
wfs_clear_cap (WFS_VOID)
{
#if (defined HAVE_SYS_CAPABILITY_H) && (defined HAVE_LIBCAP)
	int res;
	cap_t my_capab;
#endif
	wfs_errcode_t ret = WFS_SUCCESS;

#if (defined HAVE_SYS_CAPABILITY_H) && (defined HAVE_LIBCAP)

	WFS_SET_ERRNO (0);
	/* NOTE: Valgring says this calls capget(..., NULL), but
	there's nothing we can do about it. */
	my_capab = cap_init ();
	if ( (my_capab != NULL)
# ifdef HAVE_ERRNO_H
/*		&& (errno == 0)*/
# endif
	   )
	{
		WFS_SET_ERRNO (0);
		res = cap_set_proc (my_capab);
		if ( (res != 0)
# ifdef HAVE_ERRNO_H
/*			|| (errno != 0)*/
# endif
		   )
		{
			ret = WFS_GET_ERRNO_OR_DEFAULT (1L);
		}
		/* don't care about any cap_free() errors right now */
		cap_free (my_capab);
	}
	else
	{	/* cap_init() failed. Get current capabilities and clear them. */

		WFS_SET_ERRNO (0);
		my_capab = cap_get_proc ();
		if ( (my_capab != NULL)
# ifdef HAVE_ERRNO_H
/*			&& (errno == 0)*/
# endif
		   )
		{
			WFS_SET_ERRNO (0);
			res = cap_clear (my_capab);

			if ( (res != 0)
# ifdef HAVE_ERRNO_H
/*				|| (errno != 0)*/
# endif
			   )
			{
				ret = WFS_GET_ERRNO_OR_DEFAULT (1L);
			}
			else
			{	/* cap_clear() success */
				WFS_SET_ERRNO (0);
				res = cap_set_proc (my_capab);
				if ( (res != 0)
# ifdef HAVE_ERRNO_H
/*					|| (errno != 0)*/
# endif
				   )
				{
					ret = WFS_GET_ERRNO_OR_DEFAULT (1L);
				}
			}
			/* don't care about any cap_free() errors right now */
			cap_free (my_capab);
		}
		else
		{
			/* cap_get_proc() failed. */
			ret = WFS_GET_ERRNO_OR_DEFAULT (1L);
		}
	}
#endif /* #if (defined HAVE_SYS_CAPABILITY_H) && (defined HAVE_LIBCAP) */

	return ret;
}

/* ======================================================================== */

/**
 * Checks if stdout & stderr are open.
 * \param stdout_open Pointer to an int which will get the value 0 if
 *	the standard output is not open.
 * \param stderr_open Pointer to an int which will get the value 0 if
 *	the standard error output is not open.
 */
void
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_check_stds (
#ifdef WFS_ANSIC
	int * const stdout_open, int * const stderr_open)
#else
	stdout_open, stderr_open)
	int * const stdout_open;
	int * const stderr_open;
#endif
{
#ifdef WFS_HAVE_STAT
	int res;
# ifdef HAVE_FSTAT64
	struct stat64 stat_buf;
# else
	struct stat stat_buf;
# endif
# ifdef HAVE_UNISTD_H
	int stdout_fd = STDOUT_FILENO;
	int stderr_fd = STDERR_FILENO;
# else
	int stdout_fd = 1;
	int stderr_fd = 2;
# endif
#endif

	if ( stdout_open != NULL )
	{
		*stdout_open = 1;

#ifdef WFS_HAVE_STAT

		WFS_SET_ERRNO (0);
# ifdef HAVE_FSTAT64
		res = fstat64 (stdout_fd, &stat_buf);
# elif HAVE_FSTAT
		res = fstat (stdout_fd, &stat_buf);
# else
		res = 0; /* open by default */
# endif
		if ( (res < 0)
# ifdef HAVE_ERRNO_H
/*			|| (errno != 0)*/
# endif
		   )
		{
			*stdout_open = 0;
		}
#endif	/* WFS_HAVE_STAT */
	}

	if ( stderr_open != NULL )
	{
		*stderr_open = 1;

#ifdef WFS_HAVE_STAT
		WFS_SET_ERRNO (0);
# ifdef HAVE_FSTAT64
		res = fstat64 (stderr_fd, &stat_buf);
# elif HAVE_FSTAT
		res = fstat (stderr_fd, &stat_buf);
# else
		res = 0; /* open by default */
# endif
		if ( (res < 0)
# ifdef HAVE_ERRNO_H
/*			|| (errno != 0)*/
# endif
		   )
		{
			*stderr_open = 0;
		}
#endif	/* WFS_HAVE_STAT */
	}

	if ( (stdout == NULL) && (stdout_open != NULL) )
	{
		*stdout_open = 0;
	}
	if ( (stderr == NULL) && (stderr_open != NULL) )
	{
		*stderr_open = 0;
	}
}

/* ======================================================================== */

/**
 * Checks if the program is being run setuid(root).
 * \return WFS_SUCCESS if not.
 */
wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_check_suid (WFS_VOID)
{
	wfs_errcode_t ret = WFS_SUCCESS;

#if (defined HAVE_UNISTD_H) && (defined HAVE_GETEUID) && (defined HAVE_GETUID)
	if ( (geteuid () != getuid () ) && (geteuid () == 0) )
	{
		ret = WFS_SUID;
	}
#endif
	return ret;
}


/* ======================================================================== */

/**
 * Clears the environment.
 */
void
wfs_clear_env (WFS_VOID)
{
#if (defined HAVE_CLEARENV)
	clearenv ();
#else
# if (defined HAVE_UNISTD_H) && (defined HAVE_DECL_ENVIRON) && (HAVE_DECL_ENVIRON)
	environ = NULL;
# endif
# if (defined HAVE_UNISTD_H) && (defined HAVE_DECL___ENVIRON) && (HAVE_DECL___ENVIRON)
	__environ = NULL;
# endif
#endif
}
