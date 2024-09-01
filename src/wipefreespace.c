/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *
 * Copyright (C) 2007-2024 Bogdan Drozdowski, bogdro (at) users.sourceforge.net
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
#include "wfs_util.h"
#include "wfs_wiping.h"

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

#define	PROGRAM_NAME	PACKAGE /*"wipefreespace"*/

static const char ver_str[] = N_("version");
static const char author_str[] = "Copyright (C) 2007-2024 Bogdan 'bogdro' Drozdowski, bogdro@users.sourceforge.net\n";
static const char lic_str[] = N_(							\
	"Program for secure cleaning of free space on filesystems.\n"			\
	"\nThis program is Free Software; you can redistribute it and/or"		\
	"\nmodify it under the terms of the GNU General Public License"			\
	"\nas published by the Free Software Foundation; either version 2"		\
	"\nof the License, or (at your option) any later version."			\
	"\n\nThis program is distributed in the hope that it will be useful,"		\
	"\nbut WITHOUT ANY WARRANTY; without even the implied warranty of"		\
	"\nMERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\n");

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

/* Messages displayed when verbose mode is on */
static const char * const msg_signal   = N_("Setting signal handlers");
static const char * const msg_chkmnt   = N_("Checking if file system is mounted");
static const char * const msg_openfs   = N_("Opening file system");
static const char * const msg_flushfs  = N_("Flushing file system");
#ifdef WFS_WANT_WFS
static const char * const msg_wipefs   = N_("Wiping free space on file system");
#endif
#ifdef WFS_WANT_PART
static const char * const msg_wipeused = N_("Wiping unused space in used blocks on");
#endif
#ifdef WFS_WANT_UNRM
static const char * const msg_wipeunrm = N_("Wiping undelete data on");
#endif
static const char * const msg_closefs  = N_("Closing file system");
static const char * const msg_nobg     = N_("Going into background not supported or failed");
static const char * const msg_cacheoff = N_("Disabling cache");

/* Command-line options. */
static int opt_allzero       = 0;
static int opt_bg            = 0;
static int opt_force         = 0;
static int opt_ioctl         = 0;
static int opt_nopart        = 0;
static int opt_nounrm        = 0;
static int opt_nowfs         = 0;
static int opt_no_wipe_zero  = 0;
static int opt_use_dedicated = 0;
static int opt_verbose       = 0;
static int opt_zero          = 0;

static int wfs_optind        = 0;

#if (defined HAVE_GETOPT_H) && (defined HAVE_GETOPT_LONG)
static int opt_blksize       = 0;
static int opt_help          = 0;
static int opt_license       = 0;
static int opt_number        = 0;
static int opt_super         = 0;
static int opt_version       = 0;
static int opt_method        = 0;
static char * opt_method_name = NULL;
/* have to use a temp variable, to add both '-v' and '--verbose' together. */
static int opt_verbose_temp  = 0;
static int opt_char          = 0;

static const struct option opts[] =
{
	{ "all-zeros",           no_argument,       &opt_allzero,       1 },
	{ "background",          no_argument,       &opt_bg,            1 },
	{ "blocksize",           required_argument, &opt_blksize,       1 },
	{ "force",               no_argument,       &opt_force,         1 },
	{ "help",                no_argument,       &opt_help,          1 },
	{ "iterations",          required_argument, &opt_number,        1 },
	{ "last-zero",           no_argument,       &opt_zero,          1 },
	{ "licence",             no_argument,       &opt_license,       1 },
	{ "license",             no_argument,       &opt_license,       1 },
	{ "method",              required_argument, &opt_method,        1 },
	{ "nopart",              no_argument,       &opt_nopart,        1 },
	{ "nounrm",              no_argument,       &opt_nounrm,        1 },
	{ "nowfs",               no_argument,       &opt_nowfs,         1 },
	{ "no-wipe-zero-blocks", no_argument,       &opt_no_wipe_zero,  1 },
	{ "superblock",          required_argument, &opt_super,         1 },
	{ "use-dedicated",       no_argument,       &opt_use_dedicated, 1 },
	{ "use-ioctl",           no_argument,       &opt_ioctl,         1 },
	/* have to use a temp variable, to add both '-v' and '--verbose' together. */
	{ "verbose",             no_argument,       &opt_verbose_temp,  1 },
	{ "version",             no_argument,       &opt_version,       1 },
	{ NULL, 0, NULL, 0 }
};
#endif

#ifdef HAVE_IOCTL
static fs_ioctl_t * ioctls = NULL;	/* array of structures */
#endif

/* Signal-related stuff */
#ifdef HAVE_SIGNAL_H
const char * const wfs_sig_unk = N_("unknown");
#endif /* HAVE_SIGNAL_H */

static unsigned long int blocksize = 0;
static unsigned long int super_off = 0;

static /*@observer@*/ const char *wfs_progname;	/* The name of the program */
static int stdout_open = 1, stderr_open = 1;

static unsigned long int npasses = 0;		/* Number of passes (patterns used) */

#ifdef TEST_COMPILE
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
 * Gets the program's name.
 * @return the program's name.
 */
const char *
wfs_get_program_name (WFS_VOID)
{
	return wfs_progname;
}

/* ======================================================================== */

#ifndef WFS_ANSIC
static const char * wfs_get_err_msg WFS_PARAMS ((const wfs_errcode_t wfs_err));
#endif

/**
 * Gets a suitalbe error message for the given error code.
 * @param wfs_err the error code (result) to get a message for.
 * @return a suitalbe error message for the given error code.
 */
static const char *
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

	if ( (stdout_open == 0) || (opt_verbose == 0) || (prev_percent == NULL)
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
static void print_help WFS_PARAMS ((const char * const my_name));
#endif

/**
 * Prints the help screen.
 * \param my_name Program identifier, like argv[0], if available.
 */
static void
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
print_help (
#ifdef WFS_ANSIC
	const char * const my_name )
#else
	my_name )
	const char * const my_name;
#endif
{
	const char /*@observer@*/ *prog;
	if ( my_name == NULL )
	{
		prog = PROGRAM_NAME;
#ifdef HAVE_STRING_H
	}
	else if ( my_name[0] == '\0' /*strlen (my_name) == 0*/ )
	{
		prog = PROGRAM_NAME;
#endif
	}
	else
	{
		prog = my_name;
	}

	/* this has to be printf() because puts() adds a new line at the end. */
	printf ( "%s", PACKAGE_NAME );
	printf ( "%s",
		_(" - Program for secure cleaning of free space on filesystems\nSyntax: ") );
	printf ( "%s", prog );
	printf ( "%s", _(" [options] ") );
	printf ( "%s", "/dev/XY [...]\n\n" );
	puts ( _("Options:") );
	puts ( _("--all-zeros\t\tUse only zeros for wiping") );
	puts ( _("--background\t\tContinue work in the background, if possible") );
	puts ( _("-b|--superblock <off>\tSuperblock offset on the given filesystems") );
	puts ( _("-B|--blocksize <size>\tBlock size on the given filesystems") );
	puts ( _("-f|--force\t\tWipe even if the file system has errors") );
	puts ( _("-h|--help\t\tPrint help") );
	puts ( _("-n|--iterations NNN\tNumber of passes (greater than 0)") );
	puts ( _("--last-zero\t\tPerform additional wiping with zeros") );
	puts ( _("-l|--license\t\tPrint license information") );
	puts ( _("--method <name>\t\tUse the given method for wiping") );
	puts ( _("--nopart\t\tDo NOT wipe free space in partially used blocks") );
	puts ( _("--nounrm\t\tDo NOT wipe undelete information") );
	puts ( _("--nowfs\t\t\tDo NOT wipe free space on file system") );
	puts ( _("--no-wipe-zero-blocks\tDo NOT wipe all-zero blocks on file system") );
	puts ( _("--use-dedicated\t\tUse the program dedicated for the given filesystem type") );
	puts ( _("--use-ioctl\t\tDisable device caching during work (can be DANGEROUS)") );
	puts ( _("-v|--verbose\t\tVerbose output") );
	puts ( _("-V|--version\t\tPrint version number") );

}

/* ======================================================================== */

#ifndef WFS_ANSIC
static wfs_errcode_t GCC_WARN_UNUSED_RESULT wfs_wipe_filesytem
	WFS_PARAMS ((const char * const dev_name, const int total_fs));
#endif

static wfs_errcode_t GCC_WARN_UNUSED_RESULT
wfs_wipe_filesytem (
#ifdef WFS_ANSIC
	const char * const dev_name, const int total_fs)
#else
	dev_name, total_fs)
	const char * const dev_name;
	const int total_fs;
#endif
{
	wfs_errcode_t ret = WFS_SUCCESS;	/* Value returned */
	wfs_fsid_t fs;			/* The file system we're working on */
	wfs_fsdata_t data;
	wfs_errcode_t res;

	WFS_MEMSET ( &fs, 0, sizeof (wfs_fsid_t) );
	WFS_MEMSET ( &data, 0, sizeof (wfs_fsdata_t) );
	fs.fsname = dev_name;
	fs.zero_pass = opt_zero;
	fs.npasses = npasses;
	fs.fs_error = malloc (wfs_get_err_size ());
	fs.whichfs = WFS_CURR_FS_NONE;
	fs.no_wipe_zero_blocks = opt_no_wipe_zero;
	fs.use_dedicated = opt_use_dedicated;

	if ( dev_name == NULL )
	{
		if ( fs.fs_error != NULL )
		{
			free (fs.fs_error);
		}
		return WFS_BAD_CMDLN;
	}

	if ( dev_name[0] == '\0' /*strlen (dev_name) == 0*/ )
	{
		if ( fs.fs_error != NULL )
		{
			free (fs.fs_error);
		}
		return WFS_BAD_CMDLN;
	}

	if ( (sig_recvd == 0) && (opt_verbose > 0) )
	{
		wfs_show_msg (1, msg_chkmnt, dev_name, fs);
	}

	if ( sig_recvd != 0 )
	{
		if ( fs.fs_error != NULL )
		{
			free (fs.fs_error);
		}
		return WFS_SIGNAL;
	}

	/* checking if fs mounted */
	ret = wfs_chk_mount (fs);
	if ( ret != WFS_SUCCESS )
	{
		wfs_show_error ((ret==WFS_MNTCHK)? wfs_err_msg_checkmt : wfs_err_msg_mtrw,
			dev_name, fs);
		if ( fs.fs_error != NULL )
		{
			free (fs.fs_error);
		}
		return ret;
	}

	if ( sig_recvd != 0 )
	{
		if ( fs.fs_error != NULL )
		{
			free (fs.fs_error);
		}
		return WFS_SIGNAL;
	}

#ifdef HAVE_IOCTL
	if ( opt_ioctl != 0 )
	{
		/* disabling the hardware disk cache */
		if ( (sig_recvd == 0) && (opt_verbose > 0) )
		{
			wfs_show_msg (1, msg_cacheoff, dev_name, fs);
		}
		res = wfs_disable_drive_cache (fs, total_fs, ioctls);
		if ( res != WFS_SUCCESS )
		{
			wfs_show_error (wfs_err_msg_nocache,
				dev_name, fs);
		}
	}
#endif
	/* opening the file system */
	if ( (sig_recvd == 0) && (opt_verbose > 0) )
	{
		wfs_show_msg (1, msg_openfs, dev_name, fs);
	}

	data.e2fs.super_off = super_off;
	data.e2fs.blocksize = (unsigned int) (blocksize & 0x0FFFFFFFF);
	ret = wfs_open_fs (&fs, &data);
	if ( ret != WFS_SUCCESS )
	{
#ifdef HAVE_IOCTL
		if ( opt_ioctl != 0 )
		{
			/* re-enabling the hardware disk cache in case of errors */
			res = wfs_enable_drive_cache (fs, total_fs, ioctls);
			if ( res != WFS_SUCCESS )
			{
				wfs_show_error (wfs_err_msg_cacheon,
					dev_name, fs);
			}
		}
#endif
		wfs_show_error (wfs_err_msg_open, dev_name, fs);
		if ( fs.fs_error != NULL )
		{
			free (fs.fs_error);
		}
		return WFS_OPENFS;
	}
	if ( (fs.whichfs != WFS_CURR_FS_XFS) && (fs.use_dedicated == 0) )
	{
		/*
		 * NOTE: XFS support requires the $PATH environment variable
		 * right now, so don't clear the environment.
		 * Same thing with calling the dedicated wiping tools.
		 * For other filesystems we can clear the environment.
		 */
		wfs_clear_env ();
	}

	if ( (sig_recvd == 0) && (opt_verbose > 0) )
	{
		wfs_show_msg (0, wfs_convert_fs_to_name (fs.whichfs), dev_name, fs);
	}

	if ( sig_recvd != 0 )
	{
		/* close the filesystems if a signal was received */
		wfs_close_fs (fs);
#ifdef HAVE_IOCTL
		if ( opt_ioctl != 0 )
		{
			/* re-enabling the hardware disk cache */
			res = wfs_enable_drive_cache (fs, total_fs, ioctls);
			if ( res != WFS_SUCCESS )
			{
				wfs_show_error (wfs_err_msg_cacheon,
					dev_name, fs);
			}
		}
#endif
		if ( fs.fs_error != NULL )
		{
			free (fs.fs_error);
		}
		return WFS_SIGNAL;
	}

	/* checking for filesystem errors */
	if ( (opt_force == 0) && (wfs_check_err (fs) != 0) )
	{
		wfs_show_msg (1, wfs_err_msg_fserr, dev_name, fs);
		wfs_close_fs (fs);
#ifdef HAVE_IOCTL
		if ( opt_ioctl != 0 )
		{
			/* re-enabling the hardware disk cache in case of errors */
			res = wfs_enable_drive_cache (fs, total_fs, ioctls);
			if ( res != WFS_SUCCESS )
			{
				wfs_show_error (wfs_err_msg_cacheon,
					dev_name, fs);
			}
		}
#endif
		if ( fs.fs_error != NULL )
		{
			free (fs.fs_error);
		}
		return WFS_FSHASERROR;
	}

	/* ALWAYS flush the file system before starting. */
	/*if ( (sig_recvd == 0) && (wfs_is_dirty (fs) != 0) )*/
	{
		if ( (sig_recvd == 0) && (opt_verbose > 0) )
		{
			wfs_show_msg (1, msg_flushfs, dev_name, fs);
		}
		wfs_flush_fs (fs);
	}

        if ( sig_recvd != 0 )
        {
		/* close the filesystems if a signal was received */
		wfs_close_fs (fs);
#ifdef HAVE_IOCTL
		if ( opt_ioctl != 0 )
		{
			/* re-enabling the hardware disk cache */
			res = wfs_enable_drive_cache (fs, total_fs, ioctls);
			if ( res != WFS_SUCCESS )
			{
				wfs_show_error (wfs_err_msg_cacheon,
					dev_name, fs);
			}
		}
#endif
		if ( fs.fs_error != NULL )
		{
			free (fs.fs_error);
		}
        	return WFS_SIGNAL;
        }
#ifdef WFS_WANT_UNRM
        /* removing undelete information */
	if ( (opt_nounrm == 0) && (sig_recvd == 0) )
	{
		if ( opt_verbose > 0 )
		{
			wfs_show_msg (1, msg_wipeunrm, dev_name, fs);
		}
		res = wipe_unrm (fs);
		if ( res != WFS_SUCCESS )
		{
			if ( ret == WFS_SUCCESS )
			{
				ret = res;
			}
			wfs_show_error (wfs_get_err_msg (res),
				dev_name, fs);
		}
	}
#endif
#ifdef WFS_WANT_PART
	/* wiping partially occupied blocks */
	if ( (opt_nopart == 0) && (sig_recvd == 0) )
	{
		if ( opt_verbose > 0 )
		{
			wfs_show_msg (1, msg_wipeused, dev_name, fs);
		}

		res = wipe_part (fs);
		if ( res != WFS_SUCCESS )
		{
			if ( ret == WFS_SUCCESS )
			{
				ret = res;
			}
			wfs_show_error (wfs_get_err_msg (res),
				dev_name, fs);
		}
	}
#endif
#ifdef WFS_WANT_WFS
	/* wiping the free space in the filesystem */
	if ( (opt_nowfs == 0) && (sig_recvd == 0) )
	{
		if ( opt_verbose > 0 )
		{
			wfs_show_msg (1, msg_wipefs, dev_name, fs);
		}
		res = wipe_fs (fs);
		if ( res != WFS_SUCCESS )
		{
			if ( ret == WFS_SUCCESS )
			{
				ret = res;
			}
			wfs_show_error (wfs_get_err_msg (res),
				dev_name, fs);
		}
	}
#endif
	if ( opt_verbose > 0 )
	{
		wfs_show_msg (1, msg_closefs, dev_name, fs);
	}

	/* flush the changes and close the filesystem */
	wfs_flush_fs (fs);
	res = wfs_close_fs (fs);
	if ( res != WFS_SUCCESS )
	{
		if ( ret == WFS_SUCCESS )
		{
			ret = res;
		}
		wfs_show_error (wfs_get_err_msg (res),
			dev_name, fs);
	}
#ifdef HAVE_IOCTL
	if ( opt_ioctl != 0 )
	{
		/* re-enabling the hardware disk cache after work */
		res = wfs_enable_drive_cache (fs, total_fs, ioctls);
		if ( res != WFS_SUCCESS )
		{
			wfs_show_error (wfs_err_msg_cacheon,
				dev_name, fs);
		}
	}
#endif
	if ( fs.fs_error != NULL )
	{
		free (fs.fs_error);
	}
	return ret;
}

/* ======================================================================== */

#ifndef WFS_ANSIC
static int GCC_WARN_UNUSED_RESULT wfs_read_ulong_param
	WFS_PARAMS ((const char param[], unsigned long int * const result));
#endif

static int GCC_WARN_UNUSED_RESULT wfs_read_ulong_param (
#ifdef WFS_ANSIC
	const char param[], unsigned long int * const result)
#else
	param, result)
	const char param[];
	unsigned long int * const result;
#endif
{
	long int tmp_value;
#ifndef HAVE_STRTOL
	int res;
#endif

	if ( result == NULL )
	{
		return -1;
	}

	WFS_SET_ERRNO (0);
#ifdef HAVE_STRTOL
	tmp_value = strtol ( param, NULL, 10 );
#else
	res = sscanf ( param, "%ld", &tmp_value );
#endif
	if ( (tmp_value <= 0)
#ifndef HAVE_STRTOL
		|| (res == 0)
#else
# ifdef HAVE_ERRNO_H
		|| (errno != 0)
# endif
#endif
		)
	{
		return -2;
	}
	*result = (unsigned long int)tmp_value;
	return 0;
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
	int res, i, j;
	wfs_errcode_t ret = WFS_SUCCESS;	/* Value returned by main() ("last error") */
#if (defined WFS_REISER) || (defined WFS_MINIXFS)
	pid_t child_pid;
	pid_t res_pid;
	int child_status;
	int child_signaled = 0;
#endif
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

	if ( (argc <= 1) || (argv == NULL) )
	{
		if ( stdout_open == 1 )
		{
			print_help ("");
		}
		return WFS_BAD_CMDLN;
	}

	if ( argv[0] != NULL )
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

	/* Parsing the command line */
#if (defined HAVE_GETOPT_H) && (defined HAVE_GETOPT_LONG)
	optind = 0;
	while (1==1)
	{
		opt_char = getopt_long ( argc, argv, "Vhln:B:b:vf", opts, NULL );
		if ( opt_char == -1 )
		{
			break;
		}

		/* NOTE: these shouldn't be a sequence of else-ifs */
		if ( (opt_char == (int)'?') || (opt_char == (int)':') )
		{
			if ( stdout_open == 1 )
			{
				print_help (wfs_progname);
			}
			return WFS_BAD_CMDLN;
		}

		if ( (opt_char == (int)'h') || (opt_help == 1) )
		{
			if ( stdout_open == 1 )
			{
				print_help (wfs_progname);
			}
			return WFS_NOTHING;
		}

		if ( (opt_char == (int)'V') || (opt_version == 1) )
		{
			wfs_show_msg ( 1, ver_str, VERSION, wf_gen );
			wfs_print_version ();
			return WFS_NOTHING;
		}

		if ( (opt_char == (int)'l') || (opt_license == 1) )
		{
			if ( stdout_open == 1 )
			{
				wfs_show_msg ( 0, lic_str, "", wf_gen );
				puts ( author_str );
				wfs_print_version ();
			}
			return WFS_NOTHING;
		}

		if ( (opt_char == (int)'n') || (opt_number == 1) )
		{
			res = wfs_read_ulong_param ( optarg, &npasses );
			if ( res != 0 )
			{
				if ( stdout_open == 1 )
				{
					print_help (wfs_progname);
				}
				return WFS_BAD_CMDLN;
			}
			opt_number = 0;
		}

		if ( (opt_char == (int)'B') || (opt_blksize == 1) )
		{
			res = wfs_read_ulong_param ( optarg, &blocksize );
			if ( res != 0 )
			{
				if ( stdout_open == 1 )
				{
					print_help (wfs_progname);
				}
				return WFS_BAD_CMDLN;
			}
			opt_blksize = 0;
		}

		if ( (opt_char == (int)'b') || (opt_super == 1) )
		{
			res = wfs_read_ulong_param ( optarg, &super_off );
			if ( res != 0 )
			{
				if ( stdout_open == 1 )
				{
					print_help (wfs_progname);
				}
				return WFS_BAD_CMDLN;
			}
			opt_super = 0;
		}

		if ( (opt_char == (int)'v') /* do NOT check for opt_verbose here */ )
		{
			opt_verbose++;
		}

		if ( (opt_char == (int)'f') || (opt_force == 1) )
		{
			opt_force = 1;
		}
		if ( opt_method == 1 )
		{
			opt_method_name = optarg;
			opt_method = 0;
		}
	}
	wfs_optind = optind;
	/* add up '-v' and '--verbose'. */
	opt_verbose += opt_verbose_temp;

#else	/* no getopt_long */

	for ( i = 1; i < argc; i++ )	/* argv[0] is the program name */
	{
		if ( argv[i] == NULL )
		{
			continue;
		}
		/* NOTE: these shouldn't be a sequence of else-ifs */
		if ( (strcmp (argv[i], "-h") == 0) || (strcmp (argv[i], "-?") == 0)
			|| (strcmp (argv[i], "--help") == 0) )
		{
			if ( stdout_open == 1 )
			{
				print_help (wfs_progname);
			}
			return WFS_NOTHING;
		}

		if ( (strcmp (argv[i], "-V") == 0) || (strcmp (argv[i], "--version") == 0) )
		{
			wfs_show_msg ( 1, ver_str, VERSION, wf_gen );
			wfs_print_version ();
			return WFS_NOTHING;
		}

		if ( (strcmp (argv[i], "-l") == 0) || (strcmp (argv[i], "--licence") == 0)
			|| (strcmp (argv[i], "--license") == 0) )
		{
			if ( stdout_open == 1 )
			{
				wfs_show_msg ( 0, lic_str, "", wf_gen );
				puts ( author_str );
				wfs_print_version ();
			}
			return WFS_NOTHING;
		}

		if ( (strcmp (argv[i], "-n") == 0)
			|| (strcmp (argv[i], "--iterations") == 0) )
		{
			if ( i >= argc-1 )
			{
				if ( stdout_open == 1 )
				{
					print_help (wfs_progname);
				}
				return WFS_BAD_CMDLN;
			}
			res = wfs_read_ulong_param ( argv[i+1], &npasses );
			if ( res != 0 )
			{
				if ( stdout_open == 1 )
				{
					print_help (wfs_progname);
				}
				return WFS_BAD_CMDLN;
			}
			argv[i] = NULL;
			argv[i+1] = NULL;
			continue;
		}

		if ( (strcmp (argv[i], "-B") == 0) || (strcmp (argv[i], "--blocksize") == 0) )
		{
			if ( i >= argc-1 )
			{
				if ( stdout_open == 1 )
				{
					print_help (wfs_progname);
				}
				return WFS_BAD_CMDLN;
			}
			res = wfs_read_ulong_param ( argv[i+1], &blocksize );
			if ( res != 0 )
			{
				if ( stdout_open == 1 )
				{
					print_help (wfs_progname);
				}
				return WFS_BAD_CMDLN;
			}
			argv[i] = NULL;
			argv[i+1] = NULL;
			continue;
		}

		if ( (strcmp (argv[i], "-b") == 0)
			|| (strcmp (argv[i], "--superblock") == 0) )
		{
			if ( i >= argc-1 )
			{
				if ( stdout_open == 1 )
				{
					print_help (wfs_progname);
				}
				return WFS_BAD_CMDLN;
			}
			res = wfs_read_ulong_param ( argv[i+1], &super_off );
			if ( res != 0 )
			{
				if ( stdout_open == 1 )
				{
					print_help (wfs_progname);
				}
				return WFS_BAD_CMDLN;
			}
			argv[i] = NULL;
			argv[i+1] = NULL;
			continue;
		}

		if ( (strcmp (argv[i], "-v") == 0) || (strcmp (argv[i], "--verbose") == 0) )
		{
			opt_verbose++;
			argv[i] = NULL;
			continue;
		}

		if ( (strcmp (argv[i], "-f") == 0) || (strcmp (argv[i], "--force") == 0) )
		{
			opt_force = 1;
			argv[i] = NULL;
			continue;
		}

		if ( strcmp (argv[i], "--background") == 0 )
		{
			opt_bg = 1;
			argv[i] = NULL;
			continue;
		}

		if ( strcmp (argv[i], "--no-unrm") == 0 )
		{
			opt_nounrm = 1;
			argv[i] = NULL;
			continue;
		}

		if ( strcmp (argv[i], "--no-part") == 0 )
		{
			opt_nopart = 1;
			argv[i] = NULL;
			continue;
		}

		if ( strcmp (argv[i], "--no-wfs") == 0 )
		{
			opt_nowfs = 1;
			argv[i] = NULL;
			continue;
		}

		if ( strcmp (argv[i], "--use-ioctl") == 0 )
		{
			opt_ioctl = 1;
			argv[i] = NULL;
			continue;
		}

		if ( strcmp (argv[i], "--last-zero") == 0 )
		{
			opt_zero = 1;
			argv[i] = NULL;
			continue;
		}

		if ( strcmp (argv[i], "--all-zeros") == 0 )
		{
			opt_allzero = 1;
			argv[i] = NULL;
			continue;
		}

		if ( strcmp (argv[i], "--method") == 0 )
		{
			if ( i >= argc-1 )
			{
				if ( stdout_open == 1 )
				{
					print_help (wfs_progname);
				}
				return WFS_BAD_CMDLN;
			}
			opt_method_name = argv[i+1];
			argv[i] = NULL;
			argv[i+1] = NULL;
			continue;
		}

		if ( strcmp (argv[i], "--no-wipe-zero-blocks") == 0 )
		{
			opt_no_wipe_zero = 1;
			argv[i] = NULL;
			continue;
		}
		if ( strcmp (argv[i], "--use-dedicated") == 0 )
		{
			opt_use_dedicated = 1;
			argv[i] = NULL;
			continue;
		}

		if ( strcmp (argv[i], "--") == 0 )
		{
			/* end-of-arguments marker */
			argv[i] = NULL;
			break;
		}
	}
	wfs_optind = 1;
#endif
#ifdef __GNUC__
# pragma GCC poison optind
#endif

	if ( wfs_optind >= argc )
	{
		if ( stdout_open == 1 )
		{
			print_help (wfs_progname);
		}
		return WFS_BAD_CMDLN;
	}

	if ( (opt_nopart == 1) && (opt_nounrm == 1) && (opt_nowfs == 1) )
	{

		wfs_show_msg ( 0, wfs_err_msg_nowork, "", wf_gen );
		return WFS_BAD_CMDLN;
	}

	if ( stdout_open == 0 )
	{
		opt_verbose = 0;
	}

	if ( opt_bg == 1 )
	{
#ifdef HAVE_DAEMON
		if ( daemon (1, 0) != 0 )
		{
			puts ( msg_nobg );
		}
		else
		{
			opt_verbose = 0;
			stdout_open = 0;
			stderr_open = 0;
		}
#else
		puts ( msg_nobg );
#endif
	}

#ifdef HAVE_SIGNAL_H
	if ( opt_verbose > 0 )
	{
		wfs_show_msg ( 0, msg_signal, "", wf_gen );
	}
	wfs_set_sigh (opt_verbose);
#endif		/* HAVE_SIGNAL_H */

        if ( sig_recvd != 0 )
	{
		return WFS_SIGNAL;
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
	/* initialize wiping AFTER initializing the pseudorandom number generator */
	if ( npasses == 0 )
	{
		npasses = wfs_init_wiping (npasses, opt_verbose, opt_allzero, opt_method_name);
	}
	else
	{
		wfs_init_wiping (npasses, opt_verbose, opt_allzero, opt_method_name);
	}

	/* remove duplicate command-line parameters */
	res = wfs_optind;
	while ( wfs_optind < argc-1 )
	{
		if ( argv[wfs_optind] == NULL )
		{
			wfs_optind++;
			continue;
		}
		for ( i = wfs_optind+1; i < argc; i++ )
		{
			if ( argv[i] == NULL )
			{
				continue;
			}
			if ( strcmp (argv[wfs_optind], argv[i]) == 0 )
			{
				for ( j=0; j < argc-i-1; j++ )
				{
					argv[i+j] = argv[i+j+1];
				}
				argv[argc-1] = NULL;
				argc--;
				i--;
			}
		}
		wfs_optind++;
	}
	wfs_optind = res;

#ifdef HAVE_IOCTL
	if ( argc > wfs_optind )
	{
		ioctls = (fs_ioctl_t *) malloc (
			(size_t)(argc - wfs_optind) * sizeof (fs_ioctl_t));
		if ( ioctls != NULL )
		{
			for ( i = 0; i < argc - wfs_optind; i++ )
			{
				ioctls[i].how_many = 0;
				ioctls[i].was_enabled = 0;
				ioctls[i].fs_name[0] = '\0';
				if ( argv[wfs_optind+i] == NULL )
				{
					continue;
				}
				strncpy (ioctls[i].fs_name,
					argv[wfs_optind+i],
					sizeof (ioctls[i].fs_name)-1);
				ioctls[i].fs_name[sizeof (ioctls[i].fs_name)-1] = '\0';
			}
		}
	}
#endif

	wfs_lib_init ();
	/*
	 * Unrecognised command line options are assumed to be devices
	 * which we are supposed to wipe the free space on.
	 */
	while ( (wfs_optind < argc) && (sig_recvd == 0) )
	{
		if ( argv[wfs_optind] == NULL )
		{
			wfs_optind++;
			continue;
		}
#if (defined WFS_REISER) || (defined WFS_MINIXFS)
		/* We need a separate process for ReiserFSv3 & MinixFS, because the libraries can call
		exit() and abort(), which wouldn't be good for our program */
# ifdef HAVE_ERRNO_H
		errno = 0;	/* used for gerror */
# endif
# ifdef HAVE_WORKING_FORK /* HAVE_FORK */
		child_pid = fork ();
		if ( child_pid < 0 )
# endif
		{
			/* error */
# ifdef HAVE_ERRNO_H
			err = errno;
# else
			err = 1L;
# endif
			wfs_show_error (wfs_err_msg_fork, argv[wfs_optind], wf_gen);
# ifdef HAVE_IOCTL
			if ( ioctls != NULL )
			{
				free (ioctls);
			}
			ioctls = NULL;
# endif
			wfs_lib_deinit ();
			return WFS_FORKERR;
		}
		else
# ifdef HAVE_WORKING_FORK /* HAVE_FORK */
		if ( child_pid > 0 )	/* NOTE: do NOT write '>= 0' */
# endif
		{
			/* parent process: simply wait for the child */
			while ( 1 == 1 )
			{
# ifdef HAVE_KILL
				if ( sig_recvd != 0 )
				{
#  ifndef SIGINT
#   define SIGINT 2
#  endif
#  ifndef SIGKILL
#   define SIGKILL 9
#  endif
					if ( child_signaled == 0 )
					{
						kill (child_pid, SIGINT);
						child_signaled = 1;
					}
					else
					{
						kill (child_pid, SIGKILL);
					}
				}
# endif
				child_status = 0;
# ifdef HAVE_WORKING_FORK /* HAVE_FORK */
#  ifdef HAVE_WAITPID
				res_pid = waitpid (child_pid, &child_status, 0);
#  else
				res_pid = wait (&child_status);
#  endif
#  ifdef WIFEXITED
				if ( (res_pid == child_pid) && WIFEXITED (child_status) )
				{
					res = WEXITSTATUS (child_status);
					if ( res != 0 )
					{
						ret = res;
					}
					break;
				}
#  endif
#  ifdef WIFSIGNALED
				if ( (res_pid == child_pid) && WIFSIGNALED (child_status) )
				{
					ret = WFS_SIGNAL;
					break;
				}
#  endif
#  if (!defined WIFEXITED) && (!defined WIFSIGNALED)
				if ( res_pid == child_pid )
				{
					break;
				}
#  endif
# endif
			}
			sigchld_recvd = 0;
		}
# ifdef HAVE_WORKING_FORK /* HAVE_FORK */
		else
		{
			/* child process: wipe the given filesystem */
#  ifdef HAVE_IOCTL
/* Valgrind: when this is enabled, no memory leak in main() is reported, but the
subsequent loop iterations may fail, so don't enable. */
/*			if ( ioctls != NULL )
			{
				free (ioctls);
			}
			ioctls = NULL;*/
#  endif
			exit (wfs_wipe_filesytem (argv[wfs_optind], argc - wfs_optind));
		}
# endif
#else /* ! ((defined WFS_REISER) || (defined WFS_MINIXFS)) */
		res = wfs_wipe_filesytem (argv[wfs_optind], argc - wfs_optind);
		if ( res != 0 )
		{
			ret = res;
		}
#endif
		if ( (ret == WFS_SIGNAL) || (sig_recvd != 0) )
		{
			break;
		}
		wfs_optind++;
	} /* while optind<argc && !signal */

#ifdef HAVE_IOCTL
	if ( ioctls != NULL )
	{
		free (ioctls);
	}
	ioctls = NULL;
#endif
	wfs_lib_deinit ();

	if ( sig_recvd != 0 )
	{
		return WFS_SIGNAL;
	}
	else
	{
		return ret;	/* return the last error value or zero */
	}
}	/* main() */
