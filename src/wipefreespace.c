/*
 * A program for secure cleaning of free space on filesystems.
 *
 * Copyright (C) 2007 Bogdan Drozdowski, bogdandr (at) op.pl
 * License: GNU General Public License, v3+
 *
 * Syntax example: wipefreespace /dev/hdd1
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
 *
 * Thanks to:
 * - Theodore Ts'o, for the great ext2fs library and e2fsprogs
 * - The linux-ntfs team
 * - Colin Plumb, for the great 'shred' program, parts of which are used here.
 *	The 'shred' utility is:
	   Copyright (C) 1999-2006 Free Software Foundation, Inc.
	   Copyright (C) 1997, 1998, 1999 Colin Plumb.
 *
 */

#include "wfs_cfg.h"

#include <stdio.h>

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* strtoul(), random(), srandom(), rand(), srand() */
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_STRING_H
# if (!STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#if (defined HAVE_GETOPT_H) && (defined HAVE_GETOPT_LONG)
# define _GNU_SOURCE	1	/* getopt_long() */
# include <getopt.h>
#else
# error Getopt missing.
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#ifdef HAVE_TIME_H
# include <time.h>	/* time() for randomization purposes */
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
#elif defined HAVE_ET_COM_ERR_H
# include <et/com_err.h>
#endif

#include "wipefreespace.h"
#include "wrappers.h"
#include "secure.h"
#include "wfs_signal.h"

#define	PROGRAM_NAME	PACKAGE
/*"wipefreespace"*/

static const char ver_str[] = N_("version");
static const char author_str[] = "Copyright (C) 2007 Bogdan 'bogdro' Drozdowski, bogdandr@op.pl\n";
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
const char * const err_msg_checkmt = N_("during checking if the file system is mounted:");
const char * const err_msg_mtrw    = N_("- Device is mounted in read-write mode:");
const char * const err_msg_rdblbm  = N_("during reading block bitmap from");
const char * const err_msg_wrtblk  = N_("during writing of a block on");
const char * const err_msg_rdblk   = N_("during reading of a block on");
const char * const err_msg_rdino   = N_("during reading of an inode on");
const char * const err_msg_signal  = N_("while trying to set a signal handler for");
const char * const err_msg_fserr   = N_("Filesystem has errors:");
const char * const err_msg_openscan= N_("during opening a scan of");
const char * const err_msg_blkiter = N_("during iterating over blocks on");
const char * const err_msg_diriter = N_("during iterating over a directory on");
const char * const err_msg_nowork  = N_("Nothing selected for wiping.");
const char * const err_msg_suid    = N_("PLEASE do NOT set this program's suid bit. Use sgid instead.");
const char * const err_msg_capset  = N_("during setting capabilities");

/* Messages displayed when verbose mode is on */
const char * const msg_signal      = N_("Setting signal handlers");
const char * const msg_chkmnt      = N_("Checking if file system is mounted");
const char * const msg_openfs      = N_("Opening file system");
const char * const msg_flushfs     = N_("File system invalid or dirty, flushing");
const char * const msg_rdblbm      = N_("Reading block bitmap from");
const char * const msg_wipefs      = N_("Wiping free space on file system");
const char * const msg_pattern     = N_("Using pattern");
const char * const msg_random      = N_("random");
const char * const msg_wipeused    = N_("Wiping unused space in used blocks on");
const char * const msg_wipeunrm    = N_("Wiping undelete data on");
const char * const msg_closefs     = N_("Closing file system");
const char * const msg_nobg	   = N_("Going into background not supported or failed");

/* Command-line options. */
static int opt_bg      = 0;
static int opt_blksize = 0;
static int opt_force   = 0;
static int opt_help    = 0;
static int opt_license = 0;
static int opt_nopart  = 0;
static int opt_nounrm  = 0;
static int opt_nowfs   = 0;
static int opt_number  = 0;
static int opt_super   = 0;
static int opt_verbose = 0;
static int opt_version = 0;

static int opt_char    = 0;
static int wfs_optind  = 0;

static const struct option opts[] =
{
	{ "background", no_argument,       &opt_bg,      1 },
	{ "blocksize",  required_argument, &opt_blksize, 1 },
	{ "force",      no_argument,       &opt_force,   1 },
	{ "help",       no_argument,       &opt_help,    1 },
	{ "iterations", required_argument, &opt_number,  1 },
	{ "licence",    no_argument,       &opt_license, 1 },
	{ "license",    no_argument,       &opt_license, 1 },
	{ "nopart",     no_argument,       &opt_nopart,  1 },
	{ "nounrm",     no_argument,       &opt_nounrm,  1 },
	{ "nowfs",      no_argument,       &opt_nowfs,   1 },
	{ "superblock", required_argument, &opt_super,   1 },
	{ "verbose",    no_argument,       &opt_verbose, 1 },
	{ "version",    no_argument,       &opt_version, 1 },
	{ NULL, 0, NULL, 0 }
};

/* Signal-related stuff */
#ifdef HAVE_SIGNAL_H
const char * const sig_unk = N_("unknown");
#endif /* HAVE_SIGNAL_H */

unsigned long int npasses = NPAT+3;		/* Number of passes (patterns used) */
static unsigned long int blocksize = 0;
static unsigned long int super_off = 0;

static /*@observer@*/ char *wfs_progname;	/* The name of the program */
static int stdout_open = 1, stderr_open = 1;

const char *fsname;				/* Current file system device name */

/* Taken from `shred' source */
static unsigned const int patterns[NPAT] =
{
	0x000, 0xFFF,					/* 1-bit */
	0x555, 0xAAA,					/* 2-bit */
	0x249, 0x492, 0x6DB, 0x924, 0xB6D, 0xDB6,	/* 3-bit */
	0x111, 0x222, 0x333, 0x444, 0x666, 0x777,
	0x888, 0x999, 0xBBB, 0xCCC, 0xDDD, 0xEEE	/* 4-bit */
};

/**
 * Displays an error message.
 * \param err Error code.
 * \param msg The message.
 * \param extra Last element of the error message (fsname or signal).
 */
WFS_ATTR ((nonnull)) void
show_error ( const error_type err, const char * const msg, const char * const extra )
{
	if ( (stderr_open == 0)  || (msg == NULL) || (extra == NULL) ) return;

#if (defined HAVE_ET_COM_ERR_H) || (defined HAVE_COM_ERR_H)
	if ( (err.whichfs == CURR_EXT2FS) /*|| (err.whichfs == CURR_NONE)*/ )
	{
		com_err ( wfs_progname, err.errcode.e2error, ERR_MSG_FORMATL, _(err_msg),
			err.errcode.e2error, _(msg), extra );
	}
	else
	{
		com_err ( wfs_progname, err.errcode.gerror, ERR_MSG_FORMAT, _(err_msg),
			err.errcode.gerror, _(msg), extra );
	}
#else
	fprintf ( stderr, "%s: " ERR_MSG_FORMAT, wfs_progname, _(err_msg),
		err.errcode.gerror, _(msg), extra );
#endif
	fflush (stderr);
}

/**
 * Displays a progress message (verbose mode).
 * \param type Type of message (0 == "%s: %s\n", 1 == "%s: %s: '%s'\n")
 * \param msg The message.
 * \param extra Last element of the error message (fsname or signal).
 */
WFS_ATTR ((nonnull)) void
show_msg ( const int type, const char * const msg, const char * const extra )
{
	if ( (stdout_open == 0) || (msg == NULL) ) return;

	if ( (type == 0) || (extra == NULL) )
	{
		printf ( "%s: %s\n", wfs_progname, _(msg) );
	}
	else
	{
		printf ( "%s: %s: '%s'\n", wfs_progname, _(msg), extra );
	}
	fflush (stdout);
}


/**
 * Prints the help screen.
 * \param my_name Program identifier, like argv[0], if available.
 */
static WFS_ATTR ((nonnull)) void
print_help ( const char * const my_name )
{
	const char /*@observer@*/ *prog;
	if ( my_name == NULL )
	{
		prog = PROGRAM_NAME;
#ifdef HAVE_STRING_H
	}
	else if ( strlen (my_name) == 0 )
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
\n--background\t\tContinue work in the background, if possible\
\n-b|--superblock <off>\tSuperblock offset on the given filesystems\
\n-B|--blocksize <size>\tBlock size on the given filesystems\
\n-f|--force\t\tWipe even if the file system has errors") );
	puts (
		_("-h|--help\t\tPrint help\
\n-l|--license\t\tPrint license information\
\n-n|--iterations NNN\tNumber of passes (>0, default: 25)\
\n--nopart\t\tDo NOT wipe free space in partially used blocks")		);
	puts (
		_("--nounrm\t\tDo NOT wipe undelete information\
\n--nowfs\t\t\tDo NOT wipe free space on file system\
\n-v|--verbose\t\tVerbose output\
\n-V|--version\t\tPrint version number\n")				);

}

/**
 * Fills the given buffer with one of predefined patterns.
 * \param pat_no Pass number.
 * \param buffer Buffer to be filled.
 * \param buflen Length of the buffer.
 */
void WFS_ATTR ((nonnull))
fill_buffer (
		unsigned long int 		pat_no,
		unsigned char * const 		buffer,
		const size_t 			buflen,
		int * const			selected )
		/*@requires notnull buffer @*/ /*@sets *buffer @*/
{

	size_t i;
#if (!defined HAVE_MEMCPY) && (!defined HAVE_STRING_H)
	size_t j;
#endif
	unsigned int bits;
	char tmp[8];
	int res;

	if ( (buffer == NULL) || (buflen == 0) ) return;

	/* De-select all patterns once every npasses calls. */
	if ( pat_no % npasses == 0 )
	{
		for ( i = 0; (i < NPAT) && (sig_recvd==0); i++ ) { selected[i] = 0; }
        }
        if ( sig_recvd != 0 ) return;
        pat_no %= npasses;

	/* The first, last and middle passess will be using a random pattern */
	if ( (pat_no == 0) || (pat_no == npasses-1) || (pat_no == npasses/2) )
	{
#if (!defined __STRICT_ANSI__) && (defined HAVE_RANDOM)
		bits = (unsigned int) (random () & 0xFFF);
#else
		bits = (unsigned int) (rand () & 0xFFF);
#endif
	}
	else
	{	/* For other passes, one of the fixed patterns is selected. */
		do
		{
#if (!defined __STRICT_ANSI__) && (defined HAVE_RANDOM)
			i = (size_t) (random () % NPAT);
#else
			i = (size_t) (rand () % NPAT);
#endif
		}
		while ( (selected[i] == 1) && (sig_recvd == 0) );
		if ( sig_recvd != 0 ) return;
		bits = patterns[i];
		selected[i] = 1;
    	}

        if ( sig_recvd != 0 ) return;
	/* Taken from `shred' source and modified */
	bits |= bits << 12;
	buffer[0] = (unsigned char) ((bits >> 4) & 0xFF);
	buffer[1] = (unsigned char) ((bits >> 8) & 0xFF);
	buffer[2] = (unsigned char) (bits & 0xFF);
	if ( opt_verbose == 1 )
	{
		if ( (pat_no == 0) || (pat_no == npasses-1) || (pat_no == npasses/2) )
		{
			show_msg ( 1, msg_pattern, msg_random );
		}
		else
		{
#if (!defined __STRICT_ANSI__) && (defined HAVE_SNPRINTF)
			res = snprintf (tmp, 7, "%02x%02x%02x", buffer[0], buffer[1], buffer[2] );
#else
			res = sprintf (tmp, "%02x%02x%02x", buffer[0], buffer[1], buffer[2] );
#endif
			tmp[7] = '\0';
			show_msg ( 1, msg_pattern, (res>0)?tmp:_(sig_unk) );
		}
	}
	for (i = 3; (i < buflen / 2) && (sig_recvd == 0); i *= 2)
	{
#ifdef HAVE_MEMCPY
		memcpy (buffer + i, buffer, i);
#elif defined HAVE_STRING_H
		strncpy ((char *) (buffer + i), (char *) buffer, i);
#else
		for ( j=0; j < i; j++ )
		{
			buffer [ i + j ] = buffer[j];
		}
#endif
	}
        if ( sig_recvd != 0 ) return;
	if (i < buflen)
	{
#ifdef HAVE_MEMCPY
		memcpy (buffer + i, buffer, buflen - i);
#elif defined HAVE_STRING_H
		strncpy ((char *) (buffer + i), (char *) buffer, buflen - i);
#else
		for ( j=0; j<buflen - i; j++ )
		{
			buffer [ i + j ] = buffer[j];
		}
#endif
	}
}

/* ======================================================================== */
int
main ( int argc, char* argv[] )
{
	int res;
	errcode_enum ret = WFS_SUCCESS;	/* Value returned by main() ("last error") */
	wfs_fsid_t fs;			/* The file system we're working on */
	CURR_FS curr_fs = CURR_NONE;
	fsdata data;
#ifdef WFS_EXT2
	const char *e2libver = NULL;
#endif
	error_type error;

	wfs_check_stds (&stdout_open, &stderr_open);

#ifdef HAVE_LIBINTL_H
# ifdef HAVE_SETLOCALE
	setlocale (LC_ALL, "");
# endif
	bindtextdomain (PACKAGE, LOCALEDIR);
	textdomain (PACKAGE);
#endif

	if ( (argc <= 1) || (argv == NULL) )
	{
		if ( stdout_open == 1 )
			print_help ("");
		return WFS_BAD_CMDLN;
	}

	if ( argv[0] != NULL )
	{
#ifdef HAVE_LIBGEN_H
		wfs_progname = basename (argv[0]);
#elif (defined HAVE_STRING_H)
		wfs_progname = strrchr (argv[0], (int)'/');
#else
		wfs_progname = argv[0];
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
		show_error ( error, err_msg_suid, wfs_progname );
	}

	res = wfs_clear_cap (&error);
	if ( res != WFS_SUCCESS )
	{
		error.errcode.gerror = 1L;
		show_error ( error, err_msg_capset, wfs_progname );
	}

	/* NOTE: XFS support requires the $PATH environment variable right now */
	/*wfs_clear_env ();*/

	/* Parsing the command line */
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
				print_help (wfs_progname);
			return WFS_BAD_CMDLN;
		}

		if ( (opt_char == (int)'h') || (opt_help == 1) )
		{
			if ( stdout_open == 1 )
				print_help (wfs_progname);
			return WFS_NOTHING;
		}

		if ( (opt_char == (int)'V') || (opt_version == 1) )
		{
			show_msg ( 1, ver_str, VERSION );
			return WFS_NOTHING;
		}

		if ( (opt_char == (int)'l') || (opt_license == 1) )
		{
			if ( stdout_open == 1 )
			{
				show_msg ( 0, lic_str, "" );
				puts ( author_str );
#ifdef WFS_EXT2
				ext2fs_get_library_version ( &e2libver, NULL );
				printf ( "Libext2fs version %s Copyright (C) Theodore Ts'o\n",
					(e2libver!=NULL)? e2libver: "" );
#endif
#ifdef WFS_NTFS
				printf("LibNTFS version %s, http://www.linux-ntfs.org\n",
					ntfs_libntfs_version () );
#endif
			}
			return WFS_NOTHING;
		}

		if ( (opt_char == (int)'n') || (opt_number == 1) )
		{
#ifdef HAVE_ERRNO_H
			errno = 0;
#endif
#ifdef HAVE_STRTOUL
			npasses = strtoul ( optarg, NULL, 10 );
#else
			sscanf ( optarg, "%u", &npasses );
#endif
			if ( (npasses == 0)
#ifdef HAVE_ERRNO_H
				|| (errno != 0)
#endif
			   )
			{
				if ( stdout_open == 1 )
					print_help (wfs_progname);
				return WFS_BAD_CMDLN;
			}
		}

		if ( (opt_char == (int)'B') || (opt_blksize == 1) )
		{
#ifdef HAVE_ERRNO_H
			errno = 0;
#endif

#ifdef HAVE_STRTOUL
			blocksize = strtoul ( optarg, NULL, 10 );
#else
			res = sscanf ( optarg, "%u", &blocksize );
#endif
#ifdef HAVE_ERRNO_H
			if ( (errno != 0)
# ifndef HAVE_STRTOUL
				|| (res == 0)
# endif
			   )
			{
				if ( stdout_open == 1 )
					print_help (wfs_progname);
				return WFS_BAD_CMDLN;
			}
#endif
		}

		if ( (opt_char == (int)'b') || (opt_super == 1) )
		{
#ifdef HAVE_ERRNO_H
			errno = 0;
#endif

#ifdef HAVE_STRTOUL
			super_off = strtoul ( optarg, NULL, 10 );
#else
			res = sscanf ( optarg, "%u", &super_off );
#endif
#ifdef HAVE_ERRNO_H
			if ( (errno != 0)
# ifndef HAVE_STRTOUL
				|| (res == 0)
# endif
			   )
			{
				if ( stdout_open == 1 )
					print_help (wfs_progname);
				return WFS_BAD_CMDLN;
			}
#endif
		}

		if ( (opt_char == (int)'v') || (opt_verbose == 1) )
		{
			opt_verbose = 1;
		}

		if ( (opt_char == (int)'f') || (opt_force == 1) )
		{
			opt_force = 1;
		}

	}
	wfs_optind = optind;
#ifdef __GNUC__
# pragma GCC poison optind
#endif

	if ( (wfs_optind >= argc) || (argv[wfs_optind] == NULL) )
	{
		if ( stdout_open == 1 )
			print_help (wfs_progname);
		return WFS_BAD_CMDLN;
	}

	if ( (opt_nopart == 1) && (opt_nounrm == 1) && (opt_nowfs == 1) )
	{

		show_msg ( 0, err_msg_nowork, "" );
		return WFS_BAD_CMDLN;
	}

	if ( stdout_open == 0 ) opt_verbose = 0;

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
	if ( opt_verbose == 1 )
	{
		show_msg ( 0, msg_signal, "" );
	}
	wfs_set_sigh (&error, opt_verbose);
#endif		/* HAVE_SIGNAL_H */

        if ( sig_recvd != 0 ) return WFS_SIGNAL;

#if (!defined __STRICT_ANSI__) && (defined HAVE_SRANDOM)
# ifdef HAVE_TIME_H
	srandom (0xabadcafe*(unsigned long) time (NULL));
# else
	srandom (0xabadcafe);
# endif

#else

# ifdef HAVE_TIME_H
	srand (0xabadcafe*(unsigned long) time (NULL));
# else
	srand (0xabadcafe);
# endif
#endif

	/*
	 * Unrecognised command line options are assumed to be devices
	 * which we are supposed to wipe the free space on.
	 */
	while ( (wfs_optind < argc) && (sig_recvd == 0) )
	{
		curr_fs = CURR_NONE;
		error.whichfs = CURR_NONE;

		ret = WFS_SUCCESS;
		fsname = argv[wfs_optind];

                if ( strlen (fsname) == 0 )
                {
			wfs_optind++;
			continue;
                }

		if ( (sig_recvd == 0) && (opt_verbose == 1) )
		{
			show_msg ( 1, msg_chkmnt, fsname );
		}

	        if ( sig_recvd != 0 ) return WFS_SIGNAL;

		/* checking if fs mounted */
		ret = wfs_chk_mount ( fsname, &error );
	        if ( ret != WFS_SUCCESS )
	        {
	        	show_error ( error, (ret==WFS_MNTCHK)? err_msg_checkmt : err_msg_mtrw, fsname );
			wfs_optind++;
			continue;
		}

		/* opening the file system */
		if ( (sig_recvd == 0) && (opt_verbose == 1) )
		{
			show_msg ( 1, msg_openfs, fsname );
		}

	        if ( sig_recvd != 0 ) return WFS_SIGNAL;

		data.e2fs.super_off = super_off;
		data.e2fs.blocksize = blocksize;
	        ret = wfs_open_fs ( fsname, &fs, &curr_fs, &data, &error );
	        if ( ret != WFS_SUCCESS )
	        {
	        	show_error ( error, err_msg_open, fsname );
			wfs_optind++;
			ret = WFS_OPENFS;
			continue;
		}
		error.whichfs = curr_fs;

	        if ( sig_recvd != 0 )
	        {
	        	wfs_close_fs ( fs, curr_fs, &error );
	        	return WFS_SIGNAL;
	        }

		if ( (opt_force == 0) && (wfs_check_err (fs, curr_fs) != 0) )
		{

			show_msg ( 1, err_msg_fserr, fsname );
			wfs_close_fs ( fs, curr_fs, &error );
			wfs_optind++;
			ret = WFS_FSHASERROR;
			continue;
		}

		/* flush the file system before starting, if there seems to be need. */
		if ( (sig_recvd == 0) && ( wfs_is_dirty (fs, curr_fs) != 0) )
		{

			if ( (sig_recvd == 0) && (opt_verbose == 1) )
			{
				show_msg ( 1, msg_flushfs, fsname );
			}
			wfs_flush_fs ( fs, curr_fs, &error );
		}

	        if ( sig_recvd != 0 )
	        {
			wfs_close_fs ( fs, curr_fs, &error );
	        	return WFS_SIGNAL;
	        }

	        /* removing undelete information */
		if ( (opt_nounrm == 0) && (sig_recvd == 0) )
		{

			if ( opt_verbose == 1 )
			{
				show_msg ( 1, msg_wipeunrm, fsname );
			}

			res = wipe_unrm (fs, curr_fs, &error);
			if ( (res != WFS_SUCCESS) && (ret == WFS_SUCCESS) ) ret = res;
		}

		/* wiping partially occupied blocks */
		if ( (opt_nopart == 0) && (sig_recvd == 0) )
		{

			if ( opt_verbose == 1 )
			{
				show_msg ( 1, msg_wipeused, fsname );
			}

			res = wipe_part (fs, curr_fs, &error);
			if ( (res != WFS_SUCCESS) && (ret == WFS_SUCCESS) ) ret = res;
		}

		if ( (opt_nowfs == 0) && (sig_recvd == 0) )
		{

			if ( opt_verbose == 1 )
			{
				show_msg ( 1, msg_wipefs, fsname );
			}

			res = wipe_fs (fs, curr_fs, &error);
			if ( (res != WFS_SUCCESS) && (ret == WFS_SUCCESS) ) ret = res;
                }

		if ( opt_verbose == 1 )
		{
			show_msg ( 1, msg_closefs, fsname );
		}

		res = wfs_close_fs ( fs, curr_fs, &error );
		if ( (res != WFS_SUCCESS) && (ret == WFS_SUCCESS) ) ret = res;

		wfs_optind++;	/* next device */

#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H)
		sync ();
#endif

	} /* while optind<argc && !signal */

	if ( sig_recvd != 0 ) return WFS_SIGNAL;
	else return ret;	/* return the last error value or zero */
}

