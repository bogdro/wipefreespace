/*
 * A program for secure cleaning of free space on filesystems.
 *	-- signal-related functions.
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
 *
 */

#include "wfs_cfg.h"

#include <stdio.h>	/* s(n)printf() */

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_STRING_H
# if ((!defined STDC_HEADERS) || (!STDC_HEADERS)) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_LIBINTL_H
# include <libintl.h>	/* translation stuff */
#endif

#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif

#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif

/* redefine the inline sig function from hfsp, each time with a different name */
#define sig(a,b,c,d) wfs_signal_sig(a,b,c,d)
#include "wipefreespace.h"
#include "wfs_signal.h"

/* ======================================================================== */

/* These have to be public and always defined: */
volatile sig_atomic_t sig_recvd = 0;		/* non-zero after signal received */
volatile sig_atomic_t sigchld_recvd = 0;	/* non-zero after SIGCHLD signal received */

#ifdef HAVE_SIGNAL_H
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
static struct sigaction sa/* = { .sa_handler = &term_signal_received }*/;
# endif
/* Handled signals which will cause the program to exit cleanly. */
static const int signals[] =
{
	SIGINT
# ifdef SIGQUIT
	, SIGQUIT
# endif
# ifdef SIGILL
	, SIGILL
# endif
# ifdef SIGABRT
	, SIGABRT
# endif
# ifdef SIGFPE
	, SIGFPE
# endif
# ifdef SIGSEGV
	, SIGSEGV
# endif
# ifdef SIGPIPE
	, SIGPIPE
# endif
# ifdef SIGALRM
	, SIGALRM
# endif
# ifdef SIGTERM
	, SIGTERM
# endif
# ifdef SIGUSR1
	, SIGUSR1
# endif
# ifdef SIGUSR2
	, SIGUSR2
# endif
# ifdef SIGTTIN
	, SIGTTIN
# endif
# ifdef SIGTTOU
	, SIGTTOU
# endif
# ifdef SIGBUS
	, SIGBUS
# endif
# ifdef SIGPROF
	, SIGPROF
# endif
# ifdef SIGSYS
	, SIGSYS
# endif
# ifdef SIGTRAP
	, SIGTRAP
# endif
# ifdef SIGXCPU
	, SIGXCPU
# endif
# ifdef SIGXFSZ
	, SIGXFSZ
# endif
# ifdef SIGVTALRM
	, SIGVTALRM
# endif
# ifdef SIGCHLD
	, SIGCHLD
# endif
# ifdef SIGPOLL
	, SIGPOLL
# endif
# ifdef SIGPWR
	, SIGPWR
# endif
# ifdef SIGUNUSED
	, SIGUNUSED
# endif
# ifdef SIGEMT
	, SIGEMT
# endif
# ifdef SIGLOST
	, SIGLOST
# endif
# ifdef SIGIO
	, SIGIO
# endif
};

# ifndef RETSIGTYPE
#  define RETSIGTYPE void
# endif
/**
 * Signal handler - Sets a flag which will stop further program operations, when a
 * signal which would normally terminate the program is received.
 * \param signum Signal number.
 */
static RETSIGTYPE
term_signal_received (
#ifdef WFS_ANSIC
	const int signum)
# else
	signum)
	const int signum;
# endif
{
	sig_recvd = signum;
# define void 1
# define int 2
# if RETSIGTYPE != void
	return 0;
# endif
# undef int
# undef void
}

static RETSIGTYPE
child_signal_received (
#ifdef WFS_ANSIC
	const int signum)
# else
	signum)
	const int signum;
# endif
{
	sigchld_recvd = signum;
# define void 1
# define int 2
# if RETSIGTYPE != void
	return 0;
# endif
# undef int
# undef void
}

#endif /* HAVE_SIGNAL_H */

/* =============================================================== */

void wfs_set_sigh (
#ifdef WFS_ANSIC
	error_type * const error, const int opt_verbose)
#else
	error, opt_verbose)
	error_type * const error;
	const int opt_verbose;
#endif
{
#ifdef HAVE_SIGNAL_H
# define 	TMPSIZE	12
	char tmp[TMPSIZE];		/* Place for a signal number in case of error. */
	int res;			/* s(n)printf result */
	size_t s;			/* sizeof(signals) */
# if (defined __STRICT_ANSI__) && (defined HAVE_SIGNAL_H)
	typedef void (*sighandler_t) (int);
	sighandler_t shndlr;
# endif
	wfs_fsid_t wf_gen;

	wf_gen.fsname = "";
	/*
	 * Setting signal handlers. We need to catch signals in order to close (and flush)
	 * an opened file system, to prevent unconsistencies.
	 */

# if (!defined HAVE_SIGACTION) || (defined __STRICT_ANSI__)
	/* ANSI C */
	for ( s=0; s < sizeof (signals) / sizeof (signals[0]); s++ )
	{
#  ifdef HAVE_ERRNO_H
		errno = 0;
#  endif
		shndlr = signal ( signals[s], &term_signal_received );
		if ( (shndlr == SIG_ERR)
#  ifdef HAVE_ERRNO_H
/*			|| (errno != 0)*/
#  endif
		   )
		{
#  ifdef HAVE_ERRNO_H
			error->errcode.gerror = errno;
#  else
			error->errcode.gerror = 1L;
#  endif
			res = sprintf (tmp, "%.*d", TMPSIZE-1, signals[s] );
			tmp[TMPSIZE-1] = '\0';
			if ( error->errcode.gerror == 0 ) error->errcode.gerror = 1L;
			if ( opt_verbose > 0 )
			{
				show_error ( *error, err_msg_signal, (res>0)? tmp : _(sig_unk), wf_gen );
			}
		}
	}
#  ifdef HAVE_ERRNO_H
	errno = 0;
#  endif
	shndlr = signal ( SIGCHLD, &child_signal_received );
	if ( (shndlr == SIG_ERR)
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
		res = sprintf (tmp, "%.*d", TMPSIZE-1, SIGCHLD );
		tmp[TMPSIZE-1] = '\0';
		if ( error->errcode.gerror == 0 ) error->errcode.gerror = 1L;
		if ( opt_verbose > 0 )
		{
			show_error ( *error, err_msg_signal, (res>0)? tmp : _(sig_unk), wf_gen );
		}
	}

# else
	/* more than ANSI C */
#  ifdef HAVE_MEMSET
	memset (&sa, 0, sizeof (struct sigaction));
#  else
	for ( i=0; i < sizeof (struct sigaction); i++ )
	{
		((char *)&sa)[i] = '\0';
	}
#  endif
	sa.sa_handler = &term_signal_received;
	for ( s=0; s < sizeof (signals) / sizeof (signals[0]); s++ )
	{
#  ifdef HAVE_ERRNO_H
		errno = 0;
#  endif
		res = sigaction ( signals[s], &sa, NULL);
		if ( (res != 0)
#  ifdef HAVE_ERRNO_H
/*			|| (errno != 0)*/
#  endif
		   )
		{
#  ifdef HAVE_ERRNO_H
			error->errcode.gerror = errno;
#  else
			error->errcode.gerror = 1L;
#  endif

#  ifdef HAVE_SNPRINTF
			res = snprintf (tmp, TMPSIZE-1, "%.*d", TMPSIZE-1, signals[s] );
#  else
			res = sprintf (tmp, "%.*d", TMPSIZE-1, signals[s] );
#  endif
			tmp[TMPSIZE-1] = '\0';
			if ( error->errcode.gerror == 0 ) error->errcode.gerror = 1L;
			if ( opt_verbose > 0 )
			{
				show_error ( *error, err_msg_signal, (res>0)? tmp : _(sig_unk), wf_gen );
			}
		}
	}
#  ifdef HAVE_ERRNO_H
	errno = 0;
#  endif
	sa.sa_handler = &child_signal_received;
	res = sigaction ( SIGCHLD, &sa, NULL);
	if ( (res != 0)
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

#  ifdef HAVE_SNPRINTF
		res = snprintf (tmp, TMPSIZE-1, "%.*d", TMPSIZE-1, SIGCHLD );
#  else
		res = sprintf (tmp, "%.*d", TMPSIZE-1, SIGCHLD );
#  endif
		tmp[TMPSIZE-1] = '\0';
		if ( error->errcode.gerror == 0 ) error->errcode.gerror = 1L;
		if ( opt_verbose > 0 )
		{
			show_error ( *error, err_msg_signal, (res>0)? tmp : _(sig_unk), wf_gen );
		}
	}
# endif		/* ! ANSI C */

#endif /* HAVE_SIGNAL_H */
}
