/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *
 * Copyright (C) 2007-2026 Bogdan Drozdowski, bogdro (at) users.sourceforge.net
 * License: GNU General Public License, v2+
 *
 * Syntax example: wipefreespace /dev/hdd1
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
 *
 * Thanks to:
 * - Theodore Ts'o, for the great ext2fs library and e2fsprogs
 * - The linux-ntfs team
 * - Colin Plumb, for the great 'shred' program, parts of which are used here.
 *	The 'shred' utility is:
 *	   Copyright (C) 1999-2006 Free Software Foundation, Inc.
 *	   Copyright (C) 1997, 1998, 1999 Colin Plumb.
 * - Mark Lord for the great 'hdparm' utility.
 * - knightray@gmail.com for The Tiny FAT wfs_fs library (on LGPL).
 *
 */

#include "wfs_cfg.h"
#ifdef STAT_MACROS_BROKEN
# if STAT_MACROS_BROKEN
#  error Stat macros broken. Change your C library.
/* make a syntax error, because not all compilers treat #error as an error */
Stat macros broken. Change your C library.
# endif
#endif

#include <stdio.h>

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* random(), srandom(), rand(), srand() */
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_STRING_H
# if ((!defined STDC_HEADERS) || (!STDC_HEADERS)) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#if (defined HAVE_GETOPT_H) && (defined HAVE_GETOPT_LONG)
# define _GNU_SOURCE	1	/* getopt_long() */
# include <getopt.h>
#endif

/*
#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif
*/

/* time() for randomization purposes */
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#ifdef HAVE_TIME_H
# include <time.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* sync() */
#endif

#ifdef HAVE_LIBINTL_H
# include <libintl.h>	/* translation stuff */
#endif

#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif

#ifdef HAVE_LIBGEN_H
# include <libgen.h>	/* basename() */
#endif

#ifdef HAVE_COM_ERR_H
# include <com_err.h>
#else
# if defined HAVE_ET_COM_ERR_H
#  include <et/com_err.h>
# endif
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif

#include "wipefreespace.h"
#include "wfs_wrappers.h"
#include "wfs_secure.h"
#include "wfs_signal.h"
#include "wfs_cmdline.h"

#if (defined WFS_REISER) || (defined WFS_MINIXFS) /* after #include "wipefreespace.h" */
# ifdef HAVE_SYS_WAIT_H
#  include <sys/wait.h>
# else
#  ifdef HAVE_WAIT_H
#   include <wait.h>
#  endif
# endif
# ifndef WEXITSTATUS
#  define WEXITSTATUS(stat_val) ((unsigned int)(stat_val) >> 8)
# endif
# ifndef WIFEXITED
#  define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
# endif
# ifndef WIFSIGNALED
#  define WIFSIGNALED(status) (((signed char) (((status) & 0x7f) + 1) >> 1) > 0)
# endif
#endif

/* Error messages explaining the stage during which an error occurred. */
const char * const wfs_err_msg         = N_("error");
const char * const wfs_err_msg_open    = N_("during opening");
const char * const wfs_err_msg_flush   = N_("while flushing");
const char * const wfs_err_msg_close   = N_("during closing");
const char * const wfs_err_msg_malloc  = N_("during malloc while working on");
const char * const wfs_err_msg_checkmt = N_("during checking if the file system is mounted");
const char * const wfs_err_msg_mtrw    = N_("- Device is mounted in read-write mode");
const char * const wfs_err_msg_rdblbm  = N_("during reading block bitmap from");
const char * const wfs_err_msg_wrtblk  = N_("during writing of a block on");
const char * const wfs_err_msg_rdblk   = N_("during reading of a block on");
const char * const wfs_err_msg_rdino   = N_("during reading of an inode on");
const char * const wfs_err_msg_signal  = N_("while trying to set a signal handler for");
const char * const wfs_err_msg_fserr   = N_("Filesystem has errors");
const char * const wfs_err_msg_openscan= N_("during opening a scan of");
const char * const wfs_err_msg_blkiter = N_("during iterating over blocks on");
const char * const wfs_err_msg_diriter = N_("during iterating over a directory on");
const char * const wfs_err_msg_nowork  = N_("Nothing selected for wiping.");
const char * const wfs_err_msg_suid    = N_("PLEASE do NOT set this program's suid bit. Use sgid instead.");
const char * const wfs_err_msg_capset  = N_("during setting capabilities");
const char * const wfs_err_msg_fork    = N_("during creation of child process");
const char * const wfs_err_msg_nocache = N_("during disabling device cache");
const char * const wfs_err_msg_cacheon = N_("during enabling device cache");
const char * const wfs_err_msg_attopen = N_("during opening an attribute");
const char * const wfs_err_msg_runlist = N_("during mapping a runlist");
const char * const wfs_err_msg_srchctx = N_("during creating a search context");
const char * const wfs_err_msg_param   = N_("during checking parameters");
const char * const wfs_err_msg_pipe    = N_("during creating a pipe");
const char * const wfs_err_msg_exec    = N_("during starting a sub-process");
const char * const wfs_err_msg_seek    = N_("during seeking to position");
const char * const wfs_err_msg_ioctl   = N_("during performing a control operation on");

/* Signal-related stuff */
#ifdef HAVE_SIGNAL_H
const char * const wfs_sig_unk = N_("unknown");
#endif /* HAVE_SIGNAL_H */

static /*@observer@*/ const char *wfs_progname;	/* The name of the program */
static int stdout_open = 1;
static int stderr_open = 1;

#if (defined TEST_COMPILE) && (defined WFS_ANSIC)
# undef WFS_ANSIC
#endif

/* ======================================================================== */

/**
 * Tells if the standard output is open for use.
 * @return a non-zero value if the standard output is open for use.
 */
int
wfs_is_stdout_open (WFS_VOID)
{
	return stdout_open;
}

/* ======================================================================== */

/**
 * Tells if the standard error output is open for use.
 * @return a non-zero value if the standard error output is open for use.
 */
int
wfs_is_stderr_open (WFS_VOID)
{
	return stderr_open;
}

/* ======================================================================== */

/**
 * Sets if the standard output is open for use.
 * @param value a non-zero value if the standard output is open for use.
 */
void
wfs_set_stdout_open (
#ifdef WFS_ANSIC
	int value)
#else
	value)
	int value;
#endif
{
	stdout_open = value;
}

/* ======================================================================== */

/**
 * Sets if the standard error output is open for use.
 * @param value a non-zero value if the standard error output is open for use.
 */
void
wfs_set_stderr_open (
#ifdef WFS_ANSIC
	int value)
#else
	value)
	int value;
#endif
{
	stderr_open = value;
}

/* ======================================================================== */

/**
 * Gets the program's name.
 * @return the program's name.
 */
const char *
wfs_get_program_name (WFS_VOID)
{
	return wfs_progname;
}

/* ======================================================================== */

/**
 * Gets a suitalbe error message for the given error code.
 * @param wfs_err the error code (result) to get a message for.
 * @return a suitalbe error message for the given error code.
 */
const char *
wfs_get_err_msg (
#ifdef WFS_ANSIC
	const wfs_errcode_t wfs_err)
#else
	wfs_err)
	const wfs_errcode_t wfs_err;
#endif
{
	if ( wfs_err == WFS_MNTCHK )
	{
		return wfs_err_msg_checkmt;
	}
	else if ( wfs_err == WFS_MNTRW )
	{
		return wfs_err_msg_mtrw;
	}
	else if ( wfs_err == WFS_OPENFS )
	{
		return wfs_err_msg_open;
	}
	else if ( wfs_err == WFS_FLUSHFS )
	{
		return wfs_err_msg_flush;
	}
	else if ( wfs_err == WFS_FSCLOSE )
	{
		return wfs_err_msg_close;
	}
	else if ( wfs_err == WFS_MALLOC )
	{
		return wfs_err_msg_malloc;
	}
	else if ( wfs_err == WFS_BLBITMAPREAD )
	{
		return wfs_err_msg_rdblbm;
	}
	else if ( wfs_err == WFS_BLKWR )
	{
		return wfs_err_msg_wrtblk;
	}
	else if ( wfs_err == WFS_BLKRD )
	{
		return wfs_err_msg_rdblk;
	}
	else if ( wfs_err == WFS_INOREAD )
	{
		return wfs_err_msg_rdino;
	}
	else if ( wfs_err == WFS_FSHASERROR )
	{
		return wfs_err_msg_fserr;
	}
	else if ( wfs_err == WFS_INOSCAN )
	{
		return wfs_err_msg_openscan;
	}
	else if ( wfs_err == WFS_BLKITER )
	{
		return wfs_err_msg_blkiter;
	}
	else if ( wfs_err == WFS_DIRITER )
	{
		return wfs_err_msg_diriter;
	}
	else if ( wfs_err == WFS_NOTHING )
	{
		return wfs_err_msg_nowork;
	}
	else if ( wfs_err == WFS_SUID )
	{
		return wfs_err_msg_suid;
	}
	else if ( wfs_err == WFS_FORKERR )
	{
		return wfs_err_msg_fork;
	}
	else if ( wfs_err == WFS_ATTROPEN )
	{
		return wfs_err_msg_attopen;
	}
	else if ( wfs_err == WFS_NTFSRUNLIST )
	{
		return wfs_err_msg_runlist;
	}
	else if ( wfs_err == WFS_CTXERROR )
	{
		return wfs_err_msg_srchctx;
	}
	else if ( wfs_err == WFS_BADPARAM )
	{
		return wfs_err_msg_param;
	}
	else if ( wfs_err == WFS_PIPEERR )
	{
		return wfs_err_msg_pipe;
	}
	else if ( wfs_err == WFS_EXECERR )
	{
		return wfs_err_msg_exec;
	}
	else if ( wfs_err == WFS_SEEKERR )
	{
		return wfs_err_msg_seek;
	}
	else if ( wfs_err == WFS_IOCTL )
	{
		return wfs_err_msg_ioctl;
	}
	return "?";
}

/* ======================================================================== */

/**
 * Displays a progress message (verbose mode).
 * \param type Type of message (0 == "%s: %s: %s\n", 1 == "%s: %s: %s: '%s'\n")
 * \param msg The message.
 * \param extra Last element of the error message (fsname or signal).
 * \param wfs_fs The filesystem this message refers to.
 */
void
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_show_msg (
#ifdef WFS_ANSIC
	const int		type,
	const char * const	msg,
	const char * const	extra,
	const wfs_fsid_t	wfs_fs )
#else
	type, msg, extra, wfs_fs )
	const int		type;
	const char * const	msg;
	const char * const	extra;
	const wfs_fsid_t	wfs_fs;
#endif
{
	if ( (stdout_open == 0) || (msg == NULL) )
	{
		return;
	}

	if ( (type == 0) || (extra == NULL) )
	{
		printf ( "%s:%s: %s\n", wfs_progname,
			(wfs_fs.fsname != NULL)? wfs_fs.fsname : "", _(msg) );
	}
	else
	{
		printf ( "%s:%s: %s: '%s'\n", wfs_progname,
			(wfs_fs.fsname != NULL)? wfs_fs.fsname : "", _(msg), extra );
	}
	fflush (stdout);
}

/* ======================================================================== */

/**
 * Displays a progress bar (verbose mode).
 * \param type Type of the progress bar (0 = free space, 1 = partial blocks, 2 = undelete data).
 * \param percent Current percentage.
 * \param prev_percent Previous percentage (will be checked and filled with the current).
 */
void
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_show_progress (
#ifdef WFS_ANSIC
	const wfs_progress_type_t	type,
	unsigned int			percent,
	unsigned int * const		prev_percent
	)
#else
	type, percent, prev_percent )
	const wfs_progress_type_t	type;
	unsigned int			percent;
	unsigned int * const		prev_percent;
#endif
{
	unsigned int i;

	if ( (stdout_open == 0) || (wfs_is_verbose() == 0) || (prev_percent == NULL)
		|| (
			(type != WFS_PROGRESS_WFS)
			&& (type != WFS_PROGRESS_PART)
			&& (type != WFS_PROGRESS_UNRM)
		) )
	{
		return;
	}
	if ( (percent == *prev_percent) || (percent == 0) )
	{
		return;
	}
	if ( percent > 100 )
	{
		percent = 100;
	}

	for ( i = *prev_percent; i < percent; i++ )
	{
		if ( type == WFS_PROGRESS_WFS )
		{
			printf ("=");
		}
		else if ( type == WFS_PROGRESS_PART )
		{
			printf ("-");
		}
		else if ( type == WFS_PROGRESS_UNRM )
		{
			printf ("*");
		}
	}
	if ( (percent == 100) && (*prev_percent != 100) )
	{
		printf ("\n");
	}
	*prev_percent = percent;
	fflush (stdout);
}

/* ======================================================================== */
#ifndef WFS_ANSIC
int main WFS_PARAMS ((int argc, char* argv[]));
#endif

int
main (
#ifdef WFS_ANSIC
	int argc, char* argv[] )
#else
	argc, argv )
	int argc;
	char* argv[];
#endif
{
	int res;
	wfs_fsid_t wf_gen;
	wfs_errcode_t err;

	wf_gen.fsname = "";
	wf_gen.fs_error = &err;
	wf_gen.whichfs = WFS_CURR_FS_NONE;
	wf_gen.npasses = 0;
	wf_gen.zero_pass = 0;
	wf_gen.fs_backend = NULL;
	wf_gen.no_wipe_zero_blocks = 0;
	wf_gen.use_dedicated = 0;
	wf_gen.wipe_mode = WFS_WIPE_MODE_PATTERN;
	wfs_check_stds (&stdout_open, &stderr_open);

#ifdef HAVE_LIBINTL_H
# ifdef HAVE_SETLOCALE
	setlocale (LC_ALL, "");
# endif
	bindtextdomain (PACKAGE, LOCALEDIR);
	textdomain (PACKAGE);
#endif

#ifdef WFS_HAVE_LIBNETBLOCK
	libnetblock_enable ();
#endif
#ifdef WFS_HAVE_LIBHIDEIP
	libhideip_enable ();
#endif

	if ( (argc > 1) && (argv != NULL) && (argv[0] != NULL) )
	{
#if (defined HAVE_LIBGEN_H) && (defined HAVE_BASENAME)
		wfs_progname = basename (argv[0]);
#else
# if (defined HAVE_STRING_H)
		wfs_progname = strrchr (argv[0], (int)'/') + 1;
# else
		wfs_progname = argv[0];
# endif
#endif
		if ( wfs_progname == NULL )
		{
			wfs_progname = PROGRAM_NAME;
		}
	}
	else
	{
		wfs_progname = PROGRAM_NAME;
	}

	res = wfs_check_suid ();
	if ( res != WFS_SUCCESS )
	{
		err = 1L;
		wfs_show_error (wfs_err_msg_suid, wfs_progname, wf_gen);
	}

	res = wfs_clear_cap ();
	if ( res != WFS_SUCCESS )
	{
		err = res;
		wfs_show_error (wfs_err_msg_capset, wfs_progname, wf_gen);
	}

#if (!defined __STRICT_ANSI__) && (defined HAVE_SRANDOM)
# if (defined HAVE_TIME_H) || (defined HAVE_SYS_TIME_H) || (defined TIME_WITH_SYS_TIME)
	srandom (0xabadcafe * (unsigned int) time (NULL));
# else
	srandom (0xabadcafe);
# endif

#else

# if (defined HAVE_TIME_H) || (defined HAVE_SYS_TIME_H) || (defined TIME_WITH_SYS_TIME)
	srand (0xabadcafe*(unsigned long int) time (NULL));
# else
	srand (0xabadcafe);
# endif
#endif

	return wfs_parse_cmdline(argc, argv);	/* Value returned by main() ("last error") */
}	/* main() */
