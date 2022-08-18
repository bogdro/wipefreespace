/*
 * A program for secure cleaning of free space on filesystems.
 *
 * Copyright (C) 2007-2012 Bogdan Drozdowski, bogdandr (at) op.pl
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
 * along with this program; if not, write to the Free Software Foudation:
 *		Free Software Foundation
 *		51 Franklin Street, Fifth Floor
 *		Boston, MA 02110-1301
 *		USA
 *
 * Thanks to:
 * - Theodore Ts'o, for the great ext2fs library and e2fsprogs
 * - The linux-ntfs team
 * - Colin Plumb, for the great 'shred' program, parts of which are used here.
 *	The 'shred' utility is:
 *	   Copyright (C) 1999-2006 Free Software Foundation, Inc.
 *	   Copyright (C) 1997, 1998, 1999 Colin Plumb.
 * - Mark Lord for the great 'hdparm' utility.
 * - knightray@gmail.com for The Tiny FAT FS library (on LGPL).
 *
 */

#include "wfs_cfg.h"
#ifdef STAT_MACROS_BROKEN
# if STAT_MACROS_BROKEN
#  error Stat macros broken. Change your C library.
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

/* redefine the inline sig function from hfsp, each time with a different name */
extern unsigned long int wfs_main_sig(char c0, char c1, char c2, char c3);
#define sig(a,b,c,d) wfs_main_sig(a,b,c,d)

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
static const char author_str[] = "Copyright (C) 2007-2012 Bogdan 'bogdro' Drozdowski, bogdandr@op.pl\n";
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
const char * const err_msg         = N_("error");
const char * const err_msg_open    = N_("during opening");
const char * const err_msg_flush   = N_("while flushing");
const char * const err_msg_close   = N_("during closing");
const char * const err_msg_malloc  = N_("during malloc while working on");
const char * const err_msg_checkmt = N_("during checking if the file system is mounted");
const char * const err_msg_mtrw    = N_("- Device is mounted in read-write mode");
const char * const err_msg_rdblbm  = N_("during reading block bitmap from");
const char * const err_msg_wrtblk  = N_("during writing of a block on");
const char * const err_msg_rdblk   = N_("during reading of a block on");
const char * const err_msg_rdino   = N_("during reading of an inode on");
const char * const err_msg_signal  = N_("while trying to set a signal handler for");
const char * const err_msg_fserr   = N_("Filesystem has errors");
const char * const err_msg_openscan= N_("during opening a scan of");
const char * const err_msg_blkiter = N_("during iterating over blocks on");
const char * const err_msg_diriter = N_("during iterating over a directory on");
const char * const err_msg_nowork  = N_("Nothing selected for wiping.");
const char * const err_msg_suid    = N_("PLEASE do NOT set this program's suid bit. Use sgid instead.");
const char * const err_msg_capset  = N_("during setting capabilities");
const char * const err_msg_fork    = N_("during creation of child process");
const char * const err_msg_nocache = N_("during disabling device cache");
const char * const err_msg_cacheon = N_("during enabling device cache");

/* Messages displayed when verbose mode is on */
static const char * const msg_signal   = N_("Setting signal handlers");
static const char * const msg_chkmnt   = N_("Checking if file system is mounted");
static const char * const msg_openfs   = N_("Opening file system");
static const char * const msg_flushfs  = N_("Flushing file system");
static const char * const msg_rdblbm   = N_("Reading block bitmap from");
static const char * const msg_wipefs   = N_("Wiping free space on file system");
static const char * const msg_wipeused = N_("Wiping unused space in used blocks on");
static const char * const msg_wipeunrm = N_("Wiping undelete data on");
static const char * const msg_closefs  = N_("Closing file system");
static const char * const msg_nobg     = N_("Going into background not supported or failed");

/* Command-line options. */
static int opt_allzero = 0;
static int opt_bg      = 0;
static int opt_force   = 0;
static int opt_ioctl   = 0;
static int opt_nopart  = 0;
static int opt_nounrm  = 0;
static int opt_nowfs   = 0;
static int opt_verbose = 0;
static int opt_zero    = 0;

static int wfs_optind  = 0;

#if (defined HAVE_GETOPT_H) && (defined HAVE_GETOPT_LONG)
static int opt_blksize = 0;
static int opt_help    = 0;
static int opt_license = 0;
static int opt_number  = 0;
static int opt_super   = 0;
static int opt_version = 0;
static int opt_method  = 0;
static char * opt_method_name = NULL;
/* have to use a temp variable, to add both '-v' and '--verbose' together. */
static int opt_verbose_temp = 0;
static int opt_char    = 0;

static const struct option opts[] =
{
	{ "all-zeros",  no_argument,       &opt_allzero, 1 },
	{ "background", no_argument,       &opt_bg,      1 },
	{ "blocksize",  required_argument, &opt_blksize, 1 },
	{ "force",      no_argument,       &opt_force,   1 },
	{ "help",       no_argument,       &opt_help,    1 },
	{ "iterations", required_argument, &opt_number,  1 },
	{ "last-zero",  no_argument,       &opt_zero,    1 },
	{ "licence",    no_argument,       &opt_license, 1 },
	{ "license",    no_argument,       &opt_license, 1 },
	{ "method",     required_argument, &opt_method,  1 },
	{ "nopart",     no_argument,       &opt_nopart,  1 },
	{ "nounrm",     no_argument,       &opt_nounrm,  1 },
	{ "nowfs",      no_argument,       &opt_nowfs,   1 },
	{ "superblock", required_argument, &opt_super,   1 },
	{ "use-ioctl",  no_argument,       &opt_ioctl,   1 },
	/* have to use a temp variable, to add both '-v' and '--verbose' together. */
	{ "verbose",    no_argument,       &opt_verbose_temp, 1 },
	{ "version",    no_argument,       &opt_version, 1 },
	{ NULL, 0, NULL, 0 }
};
#endif

#ifdef HAVE_IOCTL
static fs_ioctl * ioctls = NULL;	/* array of structures */
#endif

/* Signal-related stuff */
#ifdef HAVE_SIGNAL_H
const char * const sig_unk = N_("unknown");
#endif /* HAVE_SIGNAL_H */

static unsigned long int blocksize = 0;
static unsigned long int super_off = 0;

static /*@observer@*/ const char *wfs_progname;	/* The name of the program */
static int stdout_open = 1, stderr_open = 1;

unsigned long int npasses = 0;		/* Number of passes (patterns used) */

/* ======================================================================== */

/**
 * Displays an error message.
 * \param err Error code.
 * \param msg The message.
 * \param extra Last element of the error message (fsname or signal).
 * \param FS The filesystem this message refers to.
 */
void
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
show_error (
#ifdef WFS_ANSIC
	const error_type	err,
	const char * const	msg,
	const char * const	extra,
	const wfs_fsid_t	FS )
#else
	err, msg, extra, FS )
	const error_type	err;
	const char * const	msg;
	const char * const	extra;
	const wfs_fsid_t	FS;
#endif
{
	if ( (stderr_open == 0) || (msg == NULL) )
	{
		return;
	}

#if ((defined HAVE_ET_COM_ERR_H) || (defined HAVE_COM_ERR_H)) && (defined HAVE_LIBCOM_ERR)
# if (defined WFS_EXT234) || (defined WFS_OCFS)
	if ( (err.whichfs == CURR_EXT234FS) || (err.whichfs == CURR_OCFS) )
	{
		com_err ( wfs_progname, err.errcode.e2error, ERR_MSG_FORMATL,
			_(err_msg), err.errcode.e2error, _(msg),
			(extra != NULL)? extra : "",
			(FS.fsname != NULL)? FS.fsname : "" );
	}
	else
# endif
	{
		com_err ( wfs_progname, err.errcode.gerror, ERR_MSG_FORMAT,
			_(err_msg), err.errcode.gerror, _(msg),
			(extra != NULL)? extra : "",
			(FS.fsname != NULL)? FS.fsname : "" );
	}
#else
	fprintf ( stderr, "%s:%s: " ERR_MSG_FORMAT, wfs_progname,
		(FS.fsname != NULL)? FS.fsname : "", _(err_msg),
		err.errcode.gerror, _(msg),
		(extra != NULL)? extra : "",
		(FS.fsname != NULL)? FS.fsname : "" );
#endif
	fflush (stderr);
}

/* ======================================================================== */

/**
 * Displays a progress message (verbose mode).
 * \param type Type of message (0 == "%s: %s: %s\n", 1 == "%s: %s: %s: '%s'\n")
 * \param msg The message.
 * \param extra Last element of the error message (fsname or signal).
 * \param FS The filesystem this message refers to.
 */
void
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
show_msg (
#ifdef WFS_ANSIC
	const int		type,
	const char * const	msg,
	const char * const	extra,
	const wfs_fsid_t	FS )
#else
	type, msg, extra, FS )
	const int		type;
	const char * const	msg;
	const char * const	extra;
	const wfs_fsid_t	FS;
#endif
{
	if ( (stdout_open == 0) || (msg == NULL) )
	{
		return;
	}

	if ( (type == 0) || (extra == NULL) )
	{
		printf ( "%s:%s: %s\n", wfs_progname,
			(FS.fsname != NULL)? FS.fsname : "", _(msg) );
	}
	else
	{
		printf ( "%s:%s: %s: '%s'\n", wfs_progname,
			(FS.fsname != NULL)? FS.fsname : "", _(msg), extra );
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
show_progress (
#ifdef WFS_ANSIC
	const unsigned int		type,
	const unsigned int		percent,
	unsigned int * const		prev_percent
	)
#else
	type, percent, prev_percent )
	const unsigned int		type;
	const unsigned int		percent;
	unsigned int * const		prev_percent;
#endif
{
	unsigned int i;
	if ( (stdout_open == 0) || (opt_verbose == 0) || (prev_percent == NULL)
		|| ((type != 0) && (type != 1) && (type != 2)) )
	{
		return;
	}
	if ( (percent == *prev_percent) || (percent == 0) )
	{
		return;
	}
	if ( percent > 100 )
	{
		*prev_percent = percent;
		return;
	}

	for ( i=*prev_percent; i < percent; i++ )
	{
		if ( type == 0 ) printf ("=");
		else if ( type == 1 ) printf ("-");
		else if ( type == 2 ) printf ("*");
	}
	if ( percent == 100 )
	{
		printf ("\n");
	}
	*prev_percent = percent;
	fflush (stdout);
}

/* ======================================================================== */

#ifndef WFS_ANSIC
static void print_help PARAMS ((const char * const my_name));
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

	printf ("%s", prog);
	printf ( "%s",
		_(" - Program for secure cleaning of free space on filesystems\nSyntax: ") );
	printf ("%s", prog);
	printf ( "%s", _(" [options] ") );
	printf ( "%s", "/dev/XY [...]\n\n" );
	puts ( _("Options:\
\n--all-zeros\t\tUse only zeros for wiping\
\n--background\t\tContinue work in the background, if possible\
\n-b|--superblock <off>\tSuperblock offset on the given filesystems\
\n-B|--blocksize <size>\tBlock size on the given filesystems\
\n-f|--force\t\tWipe even if the file system has errors") );
	puts (
		_("-h|--help\t\tPrint help\
\n-n|--iterations NNN\tNumber of passes (greater than 0)\
\n--last-zero\t\tPerform additional wiping with zeros\
\n-l|--license\t\tPrint license information\
\n--method <name>\t\tUse the given method for wiping\
\n--nopart\t\tDo NOT wipe free space in partially used blocks")		);
	puts (
		_("--nounrm\t\tDo NOT wipe undelete information\
\n--nowfs\t\t\tDo NOT wipe free space on file system\
\n--use-ioctl\t\tDisable device caching during work (can be DANGEROUS)\
\n-v|--verbose\t\tVerbose output\
\n-V|--version\t\tPrint version number")
				);

}

/* ======================================================================== */

#ifndef WFS_ANSIC
static void print_versions PARAMS ((void));
#endif

static void print_versions (
#ifdef WFS_ANSIC
	void
#endif
)
{
#if (defined WFS_EXT234) || (defined WFS_NTFS) || (defined WFS_REISER4)
	const char *lib_ver = NULL;
#endif
#ifdef WFS_EXT234
	ext2fs_get_library_version ( &lib_ver, NULL );
	printf ( "Libext2fs %s Copyright (C) Theodore Ts'o\n",
		(lib_ver != NULL)? lib_ver: "<?>" );
#endif
#ifdef WFS_NTFS
# ifndef HAVE_LIBNTFS_3G
	lib_ver = ntfs_libntfs_version ();
	printf ( "LibNTFS %s, http://www.linux-ntfs.org\n",
		(lib_ver != NULL)? lib_ver : "<?>" );
# else
	printf ( "NTFS-3G: ?\n");
# endif
#endif
#ifdef WFS_XFS
	printf ( "XFS: ?\n");
#endif
#ifdef WFS_REISER
	printf ( "ReiserFSv3: ?\n");
#endif
#ifdef WFS_REISER4
	lib_ver = libreiser4_version ();
	printf ( "LibReiser4 %s\n",
		(lib_ver != NULL)? lib_ver : "<?>" );
#endif
#ifdef WFS_FATFS
	printf ( "FAT (TFFS): ?\n");
#endif
#ifdef WFS_MINIXFS
	printf ( "MinixFS: ?\n");
#endif
#ifdef WFS_JFS
	printf ( "JFS: ?\n");
#endif
#ifdef WFS_HFSP
	printf ( "HFS+: ?\n");
#endif
#ifdef WFS_OCFS
	printf ( "OCFS: ?\n");
#endif
}

/* ======================================================================== */

#ifndef WFS_ANSIC
static errcode_enum WFS_ATTR((warn_unused_result)) wfs_wipe_filesytem
	PARAMS ((const char * const dev_name, const int total_fs));
#endif

static errcode_enum WFS_ATTR((warn_unused_result))
wfs_wipe_filesytem (
#ifdef WFS_ANSIC
	const char * const dev_name, const int total_fs)
#else
	dev_name, total_fs)
	const char * const dev_name;
	const int total_fs;
#endif
{
	errcode_enum ret = WFS_SUCCESS;	/* Value returned */
	wfs_fsid_t fs;			/* The file system we're working on */
	fsdata data;
	error_type error;
	CURR_FS curr_fs = CURR_NONE;
	errcode_enum res;
#ifndef HAVE_MEMSET
	size_t i;
#endif

#ifdef HAVE_MEMSET
	memset ( &fs, 0, sizeof (wfs_fsid_t) );
	memset ( &error, 0, sizeof (error_type) );
	memset ( &data, 0, sizeof (fsdata) );
#else
	for (i = 0; i < sizeof (wfs_fsid_t); i++)
	{
		((char *)&fs)[i] = '\0';
	}
	for (i = 0; i < sizeof (error_type); i++)
	{
		((char *)&error)[i] = '\0';
	}
	for (i = 0; i < sizeof (fsdata); i++)
	{
		((char *)&data)[i] = '\0';
	}
#endif
	error.whichfs = CURR_NONE;
	fs.fsname = dev_name;
	fs.zero_pass = opt_zero;

	if ( dev_name == NULL )
	{
		return WFS_BAD_CMDLN;
	}

	if ( dev_name[0] == '\0' /*strlen (dev_name) == 0*/ )
	{
		return WFS_BAD_CMDLN;
	}

	if ( (sig_recvd == 0) && (opt_verbose > 0) )
	{
		show_msg ( 1, msg_chkmnt, dev_name, fs );
	}

	if ( sig_recvd != 0 )
	{
		return WFS_SIGNAL;
	}

	/* checking if fs mounted */
	ret = wfs_chk_mount ( dev_name, &error );
	if ( ret != WFS_SUCCESS )
	{
		show_error ( error, (ret==WFS_MNTCHK)? err_msg_checkmt : err_msg_mtrw,
			dev_name, fs );
		return ret;
	}

	/* opening the file system */
	if ( (sig_recvd == 0) && (opt_verbose > 0) )
	{
		show_msg ( 1, msg_openfs, dev_name, fs );
	}

	if ( sig_recvd != 0 )
	{
		return WFS_SIGNAL;
	}

#ifdef HAVE_IOCTL
	if ( opt_ioctl != 0 )
	{
		disable_drive_cache (dev_name, total_fs, ioctls);
	}
#endif
	data.e2fs.super_off = super_off;
	data.e2fs.blocksize = blocksize;
	ret = wfs_open_fs ( dev_name, &fs, &curr_fs, &data, &error );
	if ( ret != WFS_SUCCESS )
	{
#ifdef HAVE_IOCTL
		if ( opt_ioctl != 0 )
		{
			enable_drive_cache (dev_name, total_fs, ioctls);
		}
#endif
		show_error ( error, err_msg_open, dev_name, fs );
		return WFS_OPENFS;
	}

	if ( (sig_recvd == 0) && (opt_verbose > 0) )
	{
		show_msg ( 0, convert_fs_to_name (curr_fs), dev_name, fs );
	}

	error.whichfs = curr_fs;
	if ( sig_recvd != 0 )
	{
		wfs_close_fs ( fs, curr_fs, &error );
#ifdef HAVE_IOCTL
		if ( opt_ioctl != 0 )
		{
			enable_drive_cache (dev_name, total_fs, ioctls);
		}
#endif
		return WFS_SIGNAL;
	}

	if ( (opt_force == 0) && (wfs_check_err (fs, curr_fs, &error) != 0) )
	{
		show_msg ( 1, err_msg_fserr, dev_name, fs );
		wfs_close_fs ( fs, curr_fs, &error );
#ifdef HAVE_IOCTL
		if ( opt_ioctl != 0 )
		{
			enable_drive_cache (dev_name, total_fs, ioctls);
		}
#endif
		return WFS_FSHASERROR;
	}

	/* ALWAYS flush the file system before starting. */
	/*if ( (sig_recvd == 0) && ( wfs_is_dirty (fs, curr_fs) != 0) )*/
	{
		if ( (sig_recvd == 0) && (opt_verbose > 0) )
		{
			show_msg ( 1, msg_flushfs, dev_name, fs );
		}
		wfs_flush_fs ( fs, curr_fs, &error );
	}

        if ( sig_recvd != 0 )
        {
		wfs_close_fs ( fs, curr_fs, &error );
#ifdef HAVE_IOCTL
		if ( opt_ioctl != 0 )
		{
			enable_drive_cache (dev_name, total_fs, ioctls);
		}
#endif
        	return WFS_SIGNAL;
        }
#ifdef WFS_WANT_UNRM
        /* removing undelete information */
	if ( (opt_nounrm == 0) && (sig_recvd == 0) )
	{
		if ( opt_verbose > 0 )
		{
			show_msg ( 1, msg_wipeunrm, dev_name, fs );
		}
		res = wipe_unrm (fs, curr_fs, &error);
		if ( (res != WFS_SUCCESS) && (ret == WFS_SUCCESS) )
		{
			ret = res;
		}
	}
#endif
#ifdef WFS_WANT_PART
	/* wiping partially occupied blocks */
	if ( (opt_nopart == 0) && (sig_recvd == 0) )
	{
		if ( opt_verbose > 0 )
		{
			show_msg ( 1, msg_wipeused, dev_name, fs );
		}

		res = wipe_part (fs, curr_fs, &error);
		if ( (res != WFS_SUCCESS) && (ret == WFS_SUCCESS) )
		{
			ret = res;
		}
	}
#endif
#ifdef WFS_WANT_WFS
	if ( (opt_nowfs == 0) && (sig_recvd == 0) )
	{
		if ( opt_verbose > 0 )
		{
			show_msg ( 1, msg_wipefs, dev_name, fs );
		}
		res = wipe_fs (fs, curr_fs, &error);
		if ( (res != WFS_SUCCESS) && (ret == WFS_SUCCESS) )
		{
			ret = res;
		}
	}
#endif
	if ( opt_verbose > 0 )
	{
		show_msg ( 1, msg_closefs, dev_name, fs );
	}

	wfs_flush_fs ( fs, curr_fs, &error );
	res = wfs_close_fs ( fs, curr_fs, &error );
	if ( (res != WFS_SUCCESS) && (ret == WFS_SUCCESS) )
	{
		ret = res;
	}
#ifdef HAVE_IOCTL
	if ( opt_ioctl != 0 )
	{
		enable_drive_cache (dev_name, total_fs, ioctls);
	}
#endif
	return ret;
}

/* ======================================================================== */
#ifndef WFS_ANSIC
int main PARAMS ((int argc, char* argv[]));
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
	errcode_enum ret = WFS_SUCCESS;	/* Value returned by main() ("last error") */
#if (defined WFS_REISER) || (defined WFS_MINIXFS)
	pid_t child_pid;
	int child_status;
#endif
	error_type error;
	wfs_fsid_t wf_gen;

	wf_gen.fsname = "";
	wfs_check_stds (&stdout_open, &stderr_open);

#ifdef HAVE_LIBINTL_H
# ifdef HAVE_SETLOCALE
	setlocale (LC_ALL, "");
# endif
	bindtextdomain (PACKAGE, LOCALEDIR);
	textdomain (PACKAGE);
#endif

#ifdef IMYP_HAVE_LIBNETBLOCK
	libnetblock_enable ();
#endif
#ifdef IMYP_HAVE_LIBHIDEIP
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
#ifdef HAVE_LIBGEN_H
		wfs_progname = basename (argv[0]);
#else
# if (defined HAVE_STRING_H)
		wfs_progname = strrchr (argv[0], (int)'/');
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
		error.errcode.gerror = 1L;
		show_error ( error, err_msg_suid, wfs_progname, wf_gen );
	}

	res = wfs_clear_cap (&error);
	if ( res != WFS_SUCCESS )
	{
		show_error ( error, err_msg_capset, wfs_progname, wf_gen );
	}

	/* NOTE: XFS support requires the $PATH environment variable right now,
		so don't clear the environment. */
	/*wfs_clear_env ();*/

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
			show_msg ( 1, ver_str, VERSION, wf_gen );
			print_versions ();
			return WFS_NOTHING;
		}

		if ( (opt_char == (int)'l') || (opt_license == 1) )
		{
			if ( stdout_open == 1 )
			{
				show_msg ( 0, lic_str, "", wf_gen );
				puts ( author_str );
				print_versions ();
			}
			return WFS_NOTHING;
		}

		if ( (opt_char == (int)'n') || (opt_number == 1) )
		{
# ifdef HAVE_ERRNO_H
			errno = 0;
# endif
# ifdef HAVE_STRTOUL
			npasses = strtoul ( optarg, NULL, 10 );
# else
			res = sscanf ( optarg, "%u", &npasses );
# endif
			if ( (npasses == 0)
# ifndef HAVE_STRTOUL
				&& (res == 0)
# else
#  ifdef HAVE_ERRNO_H
				|| (errno != 0)
#  endif
# endif
			   )
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
# ifdef HAVE_ERRNO_H
			errno = 0;
# endif

# ifdef HAVE_STRTOUL
			blocksize = strtoul ( optarg, NULL, 10 );
# else
			res = sscanf ( optarg, "%u", &blocksize );
# endif
			if (
# ifndef HAVE_STRTOUL
				(res == 0)
# else
#  ifdef HAVE_ERRNO_H
				(errno != 0)
#  else
				0
#  endif
# endif
			   )
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
# ifdef HAVE_ERRNO_H
			errno = 0;
# endif

# ifdef HAVE_STRTOUL
			super_off = strtoul ( optarg, NULL, 10 );
# else
			res = sscanf ( optarg, "%u", &super_off );
# endif
			if (
# ifndef HAVE_STRTOUL
				(res == 0)
# else
#  ifdef HAVE_ERRNO_H
				(errno != 0)
#  else
				0
#  endif
# endif
			   )
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
		if ( argv[i] == NULL ) continue;
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
			show_msg ( 1, ver_str, VERSION, wf_gen );
			print_versions ();
			return WFS_NOTHING;
		}

		if ( (strcmp (argv[i], "-l") == 0) || (strcmp (argv[i], "--licence") == 0)
			|| (strcmp (argv[i], "--license") == 0) )
		{
			if ( stdout_open == 1 )
			{
				show_msg ( 0, lic_str, "", wf_gen );
				puts ( author_str );
				print_versions ();
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
# ifdef HAVE_ERRNO_H
			errno = 0;
# endif
# ifdef HAVE_STRTOUL
			npasses = strtoul ( argv[i+1], NULL, 10 );
# else
			res = sscanf ( argv[i+1], "%u", &npasses );
# endif
			if ( (npasses == 0)
# ifndef HAVE_STRTOUL
				&& (res == 0)
# else
#  ifdef HAVE_ERRNO_H
				|| (errno != 0)
#  endif
# endif
			   )
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
# ifdef HAVE_ERRNO_H
			errno = 0;
# endif

# ifdef HAVE_STRTOUL
			blocksize = strtoul ( argv[i+1], NULL, 10 );
# else
			res = sscanf ( argv[i+1], "%u", &blocksize );
# endif
			if (
# ifndef HAVE_STRTOUL
				(res == 0)
# else
#  ifdef HAVE_ERRNO_H
				(errno != 0)
#  else
				0
#  endif
# endif
			   )
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
# ifdef HAVE_ERRNO_H
			errno = 0;
# endif

# ifdef HAVE_STRTOUL
			super_off = strtoul ( argv[i+1], NULL, 10 );
# else
			res = sscanf ( argv[i+1], "%u", &super_off );
# endif
			if (
# ifndef HAVE_STRTOUL
				(res == 0)
# else
#  ifdef HAVE_ERRNO_H
				(errno != 0)
#  else
				0
#  endif
# endif
			   )
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
				if ( stdout_open == 1 ) print_help (wfs_progname);
				return WFS_BAD_CMDLN;
			}
			opt_method_name = argv[i+1];
			argv[i] = NULL;
			argv[i+1] = NULL;
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

		show_msg ( 0, err_msg_nowork, "", wf_gen );
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
		show_msg ( 0, msg_signal, "", wf_gen );
	}
	wfs_set_sigh (&error, opt_verbose);
#endif		/* HAVE_SIGNAL_H */

        if ( sig_recvd != 0 )
	{
		return WFS_SIGNAL;
	}

#if (!defined __STRICT_ANSI__) && (defined HAVE_SRANDOM)
# if (defined HAVE_TIME_H) || (defined HAVE_SYS_TIME_H) || (defined TIME_WITH_SYS_TIME)
	srandom (0xabadcafe*(unsigned long int) time (NULL));
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
		npasses = init_wiping (npasses, opt_verbose, opt_allzero, opt_method_name);
	}
	else
	{
		init_wiping (npasses, opt_verbose, opt_allzero, opt_method_name);
	}

	/* remove duplicate command-line parameters */
	res = wfs_optind;
	while ( wfs_optind < argc-1 )
	{
		if (argv[wfs_optind] == NULL)
		{
			wfs_optind++;
			continue;
		}
		for ( i = wfs_optind+1; i < argc; i++ )
		{
			if (argv[i] == NULL) continue;
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
		ioctls = (fs_ioctl *) malloc ( (size_t)(argc - wfs_optind) * sizeof (fs_ioctl) );
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
				strncpy (ioctls[i].fs_name, argv[wfs_optind+i], sizeof (ioctls[i].fs_name)-1);
				ioctls[i].fs_name[sizeof (ioctls[i].fs_name)-1] = '\0';
			}
		}
	}
#endif

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
# ifdef HAVE_FORK
		child_pid = fork ();
		if ( child_pid < 0 )
# endif
		{
# ifdef HAVE_ERRNO_H
			error.errcode.gerror = errno;
# else
			error.errcode.gerror = 1L;
# endif
			show_error ( error, err_msg_fork, argv[wfs_optind], wf_gen );
#ifdef HAVE_IOCTL
			if ( ioctls != NULL )
			{
				free (ioctls);
			}
			ioctls = NULL;
#endif
			return WFS_FORKERR;
		}
		else
# ifdef HAVE_FORK
		if ( child_pid > 0 )	/* NOTE: do NOT write '>= 0' */
# endif
		{
			/* parent process simply waits for the child */
			while ( 1 == 1 )
			{
# ifdef HAVE_FORK
#  ifdef HAVE_WAITPID
				waitpid (child_pid, &child_status, 0);
#  else
				wait (&child_status);
#  endif
#  ifdef WIFEXITED
				if ( WIFEXITED (child_status) )
				{
					ret = WEXITSTATUS (child_status);
					break;
				}
#  endif
#  ifdef WIFSIGNALED
				if ( WIFSIGNALED (child_status) )
				{
					ret = WFS_SIGNAL;
					break;
				}
#  endif
#  if (!defined WIFEXITED) && (!defined WIFSIGNALED)
				break;
#  endif
# endif
			}
			sigchld_recvd = 0;
		}
# ifdef HAVE_FORK
		else
		{
#ifdef HAVE_IOCTL
/* Valgrind: when this is enabled, no memory leak in main() is reported, but the
subsequent loop iterations may fail, so don't enable. */
/*			if ( ioctls != NULL )
			{
				free (ioctls);
			}
			ioctls = NULL;*/
#endif
			/* child */
			exit (wfs_wipe_filesytem (argv[wfs_optind], argc - wfs_optind));
		}
# endif
#else /* ! ((defined WFS_REISER) || (defined WFS_MINIXFS)) */
		ret = wfs_wipe_filesytem (argv[wfs_optind], argc - wfs_optind);
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
#if ((defined HAVE_COM_ERR_H) || (defined HAVE_ET_COM_ERR_H)) && (defined WFS_EXT234)
	remove_error_table (&et_ext2_error_table);
#endif

	if ( sig_recvd != 0 )
	{
		return WFS_SIGNAL;
	}
	else
	{
		return ret;	/* return the last error value or zero */
	}
}	/* main() */

