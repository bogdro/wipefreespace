/*
 * A program for secure cleaning of free space on filesystems.
 *	-- security-related procedures.
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
#include "wipefreespace.h"

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

#ifdef HAVE_SYS_CAPABILITY_H
# include <sys/capability.h>	/* not before ext2fs.h or wipefreespace.h */
#endif

#include "secure.h"

/**
 * Clears the (POSIX) capabilities of the program.
 * \return 0 on success, other values otherwise.
 */
int WFS_ATTR ((nonnull)) WFS_ATTR ((warn_unused_result))
wfs_clear_cap (error_type * const error)
{
#ifdef HAVE_SYS_CAPABILITY_H
	int res;
	cap_t my_capab;
#endif

	error->errcode.gerror = WFS_SUCCESS;

#ifdef HAVE_SYS_CAPABILITY_H

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	my_capab = cap_init ();
	if ( (my_capab != NULL)
# ifdef HAVE_ERRNO_H
		&& (errno == 0)
# endif
	   )
	{
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		res = cap_set_proc (my_capab);
		if ( (res != 0)
# ifdef HAVE_ERRNO_H
			|| (errno != 0)
# endif
		   )
		{
# ifdef HAVE_ERRNO_H
			error->errcode.gerror = errno;
# else
			error->errcode.gerror = 1L;
# endif
		}
	}
	else
	{	/* cap_init() failed. Get current capabilities and clear them. */

# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		my_capab = cap_get_proc ();
		if ( (my_capab != NULL)
# ifdef HAVE_ERRNO_H
			&& (errno == 0)
# endif
		   )
		{
# ifdef HAVE_ERRNO_H
			errno = 0;
# endif
			res = cap_clear (my_capab);

			if ( (res != 0)
# ifdef HAVE_ERRNO_H
				|| (errno != 0)
# endif
			   )
			{
# ifdef HAVE_ERRNO_H
				error->errcode.gerror = errno;
# else
				error->errcode.gerror = 1L;
# endif
			}
			else
			{	/* cap_clear() success */
# ifdef HAVE_ERRNO_H
				errno = 0;
# endif
				res = cap_set_proc (my_capab);
				if ( (res != 0)
# ifdef HAVE_ERRNO_H
					|| (errno != 0)
# endif
				   )
				{
# ifdef HAVE_ERRNO_H
					error->errcode.gerror = errno;
# else
					error->errcode.gerror = 1L;
# endif
				}
			}
		}
		else
		{	/* cap_get_proc() failed. */
# ifdef HAVE_ERRNO_H
			error->errcode.gerror = errno;
# else
			error->errcode.gerror = 1L;
# endif
		}
	}
#endif /* HAVE_SYS_CAPABILITY_H */

	return error->errcode.gerror;
}

/**
 * Checks if stdout & stderr are open.
 * \param stdout_open Pointer to an int, which will get the value 0 if standard output is not open.
 * \param stderr_open Pointer to an int, which will get the value 0 if standard error output is not open.
 */
void WFS_ATTR ((nonnull))
wfs_check_stds (int *stdout_open, int *stderr_open)
{
#ifdef HAVE_SYS_STAT_H
	int res;
	struct stat stat_buf;
#endif

	if ( stdout_open != NULL )
	{
		*stdout_open = 1;

#ifdef HAVE_SYS_STAT_H

# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
# ifdef HAVE_UNISTD_H
		res = fstat (STDOUT_FILENO, &stat_buf);
# else
		res = fstat (1, &stat_buf);
# endif
		if ( (res < 0)
# ifdef HAVE_ERRNO_H
			|| (errno != 0)
# endif
		   )
		{
			*stdout_open = 0;
		}
	}

	if ( stderr_open != NULL )
	{
		*stderr_open = 1;

# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
# ifdef HAVE_UNISTD_H
		res = fstat (STDERR_FILENO, &stat_buf);
# else
		res = fstat (2, &stat_buf);
# endif
		if ( (res < 0)
# ifdef HAVE_ERRNO_H
			|| (errno != 0)
# endif
		   )
		{
			*stderr_open = 0;
		}
	}
#endif	/* HAVE_SYS_STAT_H */

	if ( (stdout == NULL) && (stdout_open != NULL) ) *stdout_open = 0;
	if ( (stderr == NULL) && (stderr_open != NULL) ) *stderr_open = 0;
}

/**
 * Checks if the program is being run setuid(root).
 * \return 0 if not.
 */
int WFS_ATTR ((warn_unused_result))
wfs_check_suid (void)
{
	int ret = WFS_SUCCESS;

#if (defined HAVE_UNISTD_H) && (defined HAVE_GETEUID) && (defined HAVE_GETUID)
	if ( (geteuid () != getuid () ) && (geteuid () == 0) )
	{

		ret = WFS_SUID;
	}
#endif
	return ret;
}


/**
 * Clears the environment.
 */
void
wfs_clear_env (void)
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
