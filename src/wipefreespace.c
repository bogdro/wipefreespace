/*
 * A program for secure cleaning of free space on filesystems.
 *
 * Copyright (C) 2007 Bogdan Drozdowski, bogdandr (at) op.pl
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
 * - Colin Plumb, for the great 'shred' program, parts of which are used here.
 *	The 'shred' utility is:
	   Copyright (C) 1999-2006 Free Software Foundation, Inc.
	   Copyright (C) 1997, 1998, 1999 Colin Plumb.
 *
 */

/*
 * 0.7:
 * TODO: start playing with XFS: libxfs.h
 * TODO: pthread
 * TODO: option for going into background (verbose=0 then)
 * TODO: SUSv2-compliance
 * TODO: GNU Coding Style (info standards)
 */

#include "cfg.h"

#include <stdio.h>

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* strtoul(), random(), srandom(), rand(), srand() */
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#if HAVE_STRING_H
# if (!STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#if (defined HAVE_GETOPT_H) && (defined HAVE_GETOPT_LONG)
# include <getopt.h>
#else
# error Getopt missing.
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#ifdef HAVE_SIGNAL_H
# include <signal.h>
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

#ifdef HAVE_COM_ERR_H
# include <com_err.h>
#elif defined HAVE_ET_COM_ERR_H
# include <et/com_err.h>
#endif

#include "wipefreespace.h"
#include "wrappers.h"
#include "secure.h"

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
const char *err_msg         = N_("error");
const char *err_msg_open    = N_("during opening");
const char *err_msg_flush   = N_("while flushing");
const char *err_msg_close   = N_("during closing");
const char *err_msg_malloc  = N_("during malloc while working on");
const char *err_msg_checkmt = N_("during checking if the file system is mounted:");
const char *err_msg_mtrw    = N_("- Device is mounted in read-write mode:");
const char *err_msg_rdblbm  = N_("during reading block bitmap from");
const char *err_msg_wrtblk  = N_("during writing of a block on");
const char *err_msg_rdblk   = N_("during reading of a block on");
const char *err_msg_rdino   = N_("during reading of an inode on");
const char *err_msg_signal  = N_("while trying to set a signal handler for");
const char *err_msg_fserr   = N_("Filesystem has errors:");
const char *err_msg_openscan= N_("during opening a scan of");
const char *err_msg_blkiter = N_("during iterating over blocks on");
const char *err_msg_diriter = N_("during iterating over a directory on");
const char *err_msg_nowork  = N_("Nothing selected for wiping.");
const char *err_msg_suid    = N_("PLEASE do NOT set this program's suid bit. Use sgid instead.");
const char *err_msg_capset  = N_("during setting capabilities");

/* Messages displayed when verbose mode is on */
const char *msg_signal      = N_("Setting signal handlers");
const char *msg_chkmnt      = N_("Checking if file system is mounted");
const char *msg_openfs      = N_("Opening file system");
const char *msg_flushfs     = N_("File system invalid or dirty, flushing");
const char *msg_rdblbm      = N_("Reading block bitmap from");
const char *msg_wipefs      = N_("Wiping free space on file system");
const char *msg_pattern     = N_("Using pattern");
const char *msg_random      = N_("random");
const char *msg_wipeused    = N_("Wiping unused space in used blocks on");
const char *msg_wipeunrm    = N_("Wiping undelete data on");
const char *msg_closefs     = N_("Closing file system");

/* Command-line options. */
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

static int opt_char = 0;

static const struct option opts[] = {

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

# if !defined __STRICT_ANSI__
static struct sigaction sa/* = { .sa_handler = &term_signal_received }*/;
# endif
/* Handled signals which will cause the program to exit cleanly. */
static const int signals[] = { SIGINT, SIGQUIT,	SIGILL,	SIGABRT, SIGFPE, SIGSEGV, SIGPIPE,
	SIGALRM, SIGTERM, SIGUSR1, SIGUSR2, SIGTTIN, SIGTTOU, SIGBUS, SIGPOLL, SIGPROF,
	SIGSYS, SIGTRAP, SIGXCPU, SIGXFSZ, SIGPWR, SIGVTALRM, SIGUNUSED
# if defined SIGEMT
	, SIGEMT
# endif
# if defined SIGLOST
	, SIGLOST
# endif
	};
static const char sig_unk[] = N_("unknown");
#endif /* HAVE_SIGNAL_H */
volatile int sig_recvd = 0;			/* non-zero after signal received */


unsigned long int npasses = NPAT+3;		/* Number of passes (patterns used) */
static unsigned long int blocksize = 0;
static unsigned long int super_off = 0;

static /*@observer@*/ char *progname;		/* The name of the program */
static int stdout_open = 1, stderr_open = 1;

unsigned char /*@only@*/ *buf;			/* Buffer to be written to empty blocks */

char *fsname;					/* Current file system device name */
error_type error;

/* Taken from `shred' source */
static unsigned const int patterns[NPAT] =
{
	0x000, 0xFFF,					/* 1-bit */
	0x555, 0xAAA,					/* 2-bit */
	0x249, 0x492, 0x6DB, 0x924, 0xB6D, 0xDB6,	/* 3-bit */
	0x111, 0x222, 0x333, 0x444, 0x666, 0x777,
	0x888, 0x999, 0xBBB, 0xCCC, 0xDDD, 0xEEE	/* 4-bit */
};

static int selected[NPAT];

/**
 * Displays an error message.
 * \param err Error code.
 * \param msg The message.
 * \param extra Last element of the error message (fsname or signal).
 */
ATTR((nonnull)) void show_error ( const error_type err, const char*const msg,
	const char*const extra ) {

	if ( (stderr_open == 0)  || (msg == NULL) || (extra == NULL) ) return;

#if (defined HAVE_ET_COM_ERR_H) || (defined HAVE_COM_ERR_H)
	if ( err.whichfs == CURR_EXT2FS ) {
		com_err ( progname, err.errcode.e2error, ERR_MSG_FORMAT, _(err_msg),
			err.errcode.e2error, _(msg), extra );
	} else {
		com_err ( progname, err.errcode.gerror, ERR_MSG_FORMAT, _(err_msg),
			err.errcode.gerror, _(msg), extra );
	}
#else
	(void)fprintf ( stderr, "%s: " ERR_MSG_FORMAT, progname, _(err_msg),
		err.errcode.gerror, _(msg), extra );
#endif
	(void)fflush(stderr);
}

/**
 * Displays a progress message (verbose mode).
 * \param type Type of message (0 == "%s: %s\n", 1 == "%s: %s: '%s'\n")
 * \param msg The message.
 * \param extra Last element of the error message (fsname or signal).
 */
ATTR((nonnull)) void show_msg ( const int type, const char*const msg,
	const char*const extra ) {

	if ( (stdout_open == 0) || (msg == NULL) ) return;

	if ( (type == 0) || (extra == NULL) ) {
		(void)printf ( "%s: %s\n", progname, _(msg) );
	} else {
		(void)printf ( "%s: %s: '%s'\n", progname, _(msg), extra );
	}
	(void)fflush(stdout);
}


/**
 * Prints the help screen.
 * \param my_name Program identifier, like argv[0], if available.
 */
static ATTR((nonnull)) void print_help ( const char* const my_name ) {

	const char /*@observer@*/ *prog;
	if ( my_name == NULL ) {
		prog = PROGRAM_NAME;
#ifdef HAVE_STRING_H
	} else if ( strlen(my_name) == 0 ) {
		prog = PROGRAM_NAME;
#endif
	} else {
		prog = my_name;
	}

	(void)printf("%s", prog);
	(void)printf( "%s",
		_(" - Program for secure cleaning of free space on filesystems\nSyntax: ") );
	(void)printf("%s", prog);
	(void)printf( "%s", _(" [options] ") );
	(void)printf( "%s", "/dev/XY [...]\n\n" );
	(void)puts ( _("Options:\
\n-b|--superblock <off>\tSuperblock offset on the given filesystems\
\n-B|--blocksize <size>\tBlock size on the given filesystems\
\n-f|--force\t\tWipe even if the file system has errors") );
	(void)puts (
		_("-h|--help\t\tPrint help\
\n-l|--license\t\tPrint license information\
\n-n|--iterations NNN\tNumber of passes (>0, default: 25)\
\n--nopart\t\tDo NOT wipe free space in partially used blocks")		);
	(void)puts (
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
void ATTR((nonnull)) fill_buffer ( 	unsigned long int 		pat_no,
					unsigned char* const 		buffer,
					const size_t 			buflen )
		/*@requires notnull buffer @*/ /*@sets *buffer @*/ {

	size_t i;
#if (!defined HAVE_MEMCPY) && (!defined HAVE_STRING_H)
	size_t j;
#endif
	unsigned int bits;
	char tmp[8];
	int res;

	if ( (buffer == NULL) || (buflen == 0) ) return;

	/* De-select all patterns once every npasses calls. */
	if ( pat_no % npasses == 0 ) {
		for ( i = 0; (i < NPAT) && (sig_recvd==0); i++ ) { selected[i] = 0; }
        }
        if ( sig_recvd != 0 ) return;
        pat_no %= npasses;

	/* The first, last and middle passess will be using a random pattern */
	if ( (pat_no == 0) || (pat_no == npasses-1) || (pat_no == npasses/2) ) {
#if (!defined __STRICT_ANSI__) && (defined HAVE_RANDOM)
		bits = (unsigned int)(random() & 0xFFF);
#else
		bits = (unsigned int)(rand() & 0xFFF);
#endif
	} else {	/* For other passes, one of the fixed patterns is selected. */
		do {
#if (!defined __STRICT_ANSI__) && (defined HAVE_RANDOM)
			i = (size_t)(random()%NPAT);
#else
			i = (size_t)(rand()%NPAT);
#endif
		} while ( (selected[i] == 1) && (sig_recvd == 0) );
		if ( sig_recvd != 0 ) return;
		bits = patterns[i];
		selected[i] = 1;
    	}

        if ( sig_recvd != 0 ) return;
	/* Taken from `shred' source and modified */
	bits |= bits << 12;
	buffer[0] = (unsigned char)((bits >> 4) & 0xFF);
	buffer[1] = (unsigned char)((bits >> 8) & 0xFF);
	buffer[2] = (unsigned char)(bits & 0xFF);
	if ( opt_verbose == 1 ) {
		if ( (pat_no == 0) || (pat_no == npasses-1) || (pat_no == npasses/2) ) {
			show_msg ( 1, msg_pattern, msg_random );
		} else {
#if (!defined __STRICT_ANSI__) && (defined HAVE_SNPRINTF)
			res = snprintf(tmp, 7, "%02x%02x%02x", buffer[0], buffer[1], buffer[2] );
#else
			res = sprintf(tmp, "%02x%02x%02x", buffer[0], buffer[1], buffer[2] );
#endif
			tmp[7] = '\0';
			show_msg ( 1, msg_pattern, (res>0)?tmp:_(sig_unk) );
		}
	}
	for (i = 3; (i < buflen / 2) && (sig_recvd == 0); i *= 2) {
#ifdef HAVE_MEMCPY
		(void)memcpy (buffer + i, buffer, i);
#elif defined HAVE_STRING_H
		(void)strncpy ((char *)(buffer + i), (char *)buffer, i);
#else
		for ( j=0; j<i; j++ ) {
			buffer [ i + j ] = buffer[j];
		}
#endif
	}
        if ( sig_recvd != 0 ) return;
	if (i < buflen) {
#ifdef HAVE_MEMCPY
		(void)memcpy (buffer + i, buffer, buflen - i);
#elif defined HAVE_STRING_H
		(void)strncpy ((char *)(buffer + i), (char *)buffer, buflen - i);
#else
		for ( j=0; j<buflen - i; j++ ) {
			buffer [ i + j ] = buffer[j];
		}
#endif
	}
}

#ifdef HAVE_SIGNAL_H
# ifndef RETSIGTYPE
#  define RETSIGTYPE void
#  undef RETSIG_ISINT
# endif
/**
 * Signal handler - Sets a flag which will stop further program operations, when a
 * signal which would normally terminate the program is received.
 * \param signum Signal number.
 */
static RETSIGTYPE term_signal_received ( const int signum ) {

	sig_recvd = signum;
# ifdef RETSIG_ISINT
	return 0;
# endif
}
#endif

/* ======================================================================== */
int main ( int argc, char* argv[] ) {

	int ret = WFS_SUCCESS;		/* Value returned by main() ("last error") */
	int res;			/* s(n)printf result */
# define 	TMPSIZE	12
	char tmp[TMPSIZE];		/* Place for a signal number in case of error. */
	int i;
	wfs_fsid_t fs;			/* The file system we're working on */
	int curr_fs = 0;
	fsdata data;

	size_t s;			/* sizeof(signals) */
#if (defined __STRICT_ANSI__) && (defined HAVE_SIGNAL_H)
	typedef void (*sighandler_t)(int);
	sighandler_t shndlr;
#endif

	wfs_checkstds(&stdout_open, &stderr_open);

#ifdef HAVE_LIBINTL_H
# ifdef HAVE_SETLOCALE
	setlocale (LC_ALL, "");
# endif
	bindtextdomain (PACKAGE, LOCALEDIR);
	textdomain (PACKAGE);
#endif

	if ( (argc <= 1) || (argv == NULL) ) {
		if ( stdout_open == 1 )
			print_help("");
		return WFS_BAD_CMDLN;
	}

	if ( argv[0] != NULL ) {
		progname = argv[0];
	} else {
		progname = PROGRAM_NAME;
	}

	res = wfs_checksuid();
	if ( res != WFS_SUCCESS ) {
		error.errcode.gerror = 1L;
		show_error ( error, err_msg_suid, progname );
	}

	res = wfs_clearcap();
	if ( res != WFS_SUCCESS ) {
		error.errcode.gerror = 1L;
		show_error ( error, err_msg_capset, progname );
	}

	wfs_clearenv();

	/* Parsing the command line */
	optind = 0;
	while (1==1) {

		opt_char = getopt_long ( argc, argv, "Vhln:B:b:vf", opts, NULL );
		if ( opt_char == -1 ) {
			break;
		}

		/* NOTE: these shouldn't be a sequence of else-ifs */
		if ( (opt_char == (int)'?') || (opt_char == (int)':') ) {
			if ( stdout_open == 1 )
				print_help(progname);
			return WFS_BAD_CMDLN;
		}

		if ( (opt_char == (int)'h') || (opt_help == 1) ) {
			if ( stdout_open == 1 )
				print_help(progname);
			return WFS_NOTHING;
		}

		if ( (opt_char == (int)'V') || (opt_version == 1) ) {
			show_msg ( 1, ver_str, VERSION );
			return WFS_NOTHING;
		}

		if ( (opt_char == (int)'l') || (opt_license == 1) ) {
			if ( stdout_open == 1 ) {
				show_msg ( 0, lic_str, "" );
				(void)puts ( author_str );
			}
			return WFS_NOTHING;
		}

		if ( (opt_char == (int)'n') || (opt_number == 1) ) {
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
			 ) {
				if ( stdout_open == 1 )
					print_help(progname);
				return WFS_BAD_CMDLN;
			}
		}

		if ( (opt_char == (int)'B') || (opt_blksize == 1) ) {
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
			   ) {
				if ( stdout_open == 1 )
					print_help(progname);
				return WFS_BAD_CMDLN;
			}
#endif
		}

		if ( (opt_char == (int)'b') || (opt_super == 1) ) {
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
			   ) {
				if ( stdout_open == 1 )
					print_help(progname);
				return WFS_BAD_CMDLN;
			}
#endif
		}

		if ( (opt_char == (int)'v') || (opt_verbose == 1) ) {
			opt_verbose = 1;
		}

		if ( (opt_char == (int)'f') || (opt_force == 1) ) {
			opt_force = 1;
		}
	}

	if ( (optind >= argc) || (argv[optind] == NULL) ) {
		if ( stdout_open == 1 )
			print_help(progname);
		return WFS_BAD_CMDLN;
	}
/*
	if ( (opt_nopart == 1) && (opt_nounrm == 1) && (opt_nowfs == 1) ) {

		show_msg ( 0, err_msg_nowork, "" );
		return WFS_BAD_CMDLN;
	}
*/
	if ( stdout_open == 0 ) opt_verbose = 0;

	if ( opt_verbose == 1 ) {
		show_msg ( 0, msg_signal, "" );
	}

#ifdef HAVE_SIGNAL_H
	/*
	 * Setting signal handlers. We need to catch signals in order to close (and flush)
	 * an opened file system, to prevent unconsistencies.
	 */

# if defined __STRICT_ANSI__
	/* ANSI C */
	for ( s=0; s < sizeof(signals)/sizeof(signals[0]); s++ ) {
#  ifdef HAVE_ERRNO_H
		errno = 0;
#  endif
		shndlr = signal ( signals[s], &term_signal_received );
		if ( (shndlr == SIG_ERR)
#  ifdef HAVE_ERRNO_H
			|| (errno != 0)
#  endif
		   ) {
#  ifdef HAVE_ERRNO_H
			error.errcode.gerror = errno;
#  else
			error.errcode.gerror = 1L;
#  endif
			res = sprintf(tmp, "%.*d", TMPSIZE-1, signals[s] );
			tmp[TMPSIZE-1] = '\0';
			if ( error.errcode.gerror == 0 ) error.errcode.gerror = 1L;
			if ( opt_verbose == 1 ) {
				show_error ( error, err_msg_signal, (res>0)?tmp:_(sig_unk) );
			}
		}
	}

# else
	/* more than ANSI C */
#  ifdef HAVE_MEMSET
	(void)memset(&sa, 0, sizeof(struct sigaction));
#  else
	for ( i=0; i < sizeof(struct sigaction); i++ ) {
		((char *)&sa)[i] = '\0';
	}
#  endif
	sa.sa_handler = &term_signal_received;
	for ( s=0; s < sizeof(signals)/sizeof(signals[0]); s++ ) {
#  ifdef HAVE_ERRNO_H
		errno = 0;
#  endif
		res = sigaction( signals[s], &sa, NULL);
		if ( (res != 0)
#  ifdef HAVE_ERRNO_H
			|| (errno != 0)
#  endif
			) {
#  ifdef HAVE_ERRNO_H
			error.errcode.gerror = errno;
#  else
			error.errcode.gerror = 1L;
#  endif

#  ifdef HAVE_SNPRINTF
			res = snprintf(tmp, TMPSIZE-1, "%.*d", TMPSIZE-1, signals[s] );
#  else
			res = sprintf(tmp, "%.*d", TMPSIZE-1, signals[s] );
#  endif
			tmp[TMPSIZE-1] = '\0';
			if ( error.errcode.gerror == 0 ) error.errcode.gerror = 1L;
			if ( opt_verbose == 1 ) {
				show_error ( error, err_msg_signal, (res>0)?tmp:_(sig_unk) );
			}
		}
	}
# endif		/* ! ANSI C */
#endif		/* HAVE_SIGNAL_H */

	/* Set all patterns as unused */
	for ( i = 0; i < NPAT; i++ ) { selected[i] = 0; }
        if ( sig_recvd != 0 ) return WFS_SIGNAL;

#if (!defined __STRICT_ANSI__) && (defined HAVE_SRANDOM)
# ifdef HAVE_TIME_H
	srandom(0xabadcafe*(unsigned long)time(NULL));
# else
	srandom(0xabadcafe);
# endif

#else

# ifdef HAVE_TIME_H
	srand(0xabadcafe*(unsigned long)time(NULL));
# else
	srand(0xabadcafe);
# endif
#endif

	/*
	 * Unrecognised command line options are assumed to be devices, on which we are supposed to
	 * wipe the free space.
	 */
	while ( (optind < argc) && (sig_recvd == 0) ) {

		curr_fs = 0;
		error.whichfs = 0;

		ret = WFS_SUCCESS;
		fsname = argv[optind];
		if ( (sig_recvd == 0) && (opt_verbose == 1) ) {
			show_msg ( 1, msg_chkmnt, fsname );
		}

	        if ( sig_recvd != 0 ) return WFS_SIGNAL;

		/* checking if fs mounted */
		ret = wfs_chkmount ( fsname );
	        if ( ret != WFS_SUCCESS ) {
	        	show_error ( error, (ret==WFS_MNTCHK)?err_msg_checkmt:err_msg_mtrw, fsname );
			optind++;
			continue;
		}

		/* opening the file system */
		if ( (sig_recvd == 0) && (opt_verbose == 1) ) {
			show_msg ( 1, msg_openfs, fsname );
		}

	        if ( sig_recvd != 0 ) return WFS_SIGNAL;

		data.e2fs.super_off = super_off;
		data.e2fs.blocksize = blocksize;
	        ret = wfs_openfs( fsname, &fs, &curr_fs, &data );
	        if ( ret != WFS_SUCCESS ) {
	        	show_error ( error, err_msg_open, fsname );
			optind++;
			ret = WFS_OPENFS;
			continue;
		}
		error.whichfs = curr_fs;

	        if ( sig_recvd != 0 ) {
	        	(void)wfs_closefs ( fs, curr_fs );
	        	return WFS_SIGNAL;
	        }

		if ( (opt_force == 0) && (wfs_checkerr(fs, curr_fs) != 0) ) {

			show_msg ( 1, err_msg_fserr, fsname );
			(void)wfs_closefs ( fs, curr_fs );
			optind++;
			ret = WFS_FSHASERROR;
			continue;
		}

		/* flush the file system before starting, if there seems to be need. */
		if ( (sig_recvd == 0) && ( wfs_isdirty(fs, curr_fs) != 0) ) {

			if ( (sig_recvd == 0) && (opt_verbose == 1) ) {
				show_msg ( 1, msg_flushfs, fsname );
			}
			(void)wfs_flushfs ( fs, curr_fs );
		}

	        if ( sig_recvd != 0 ) {
			(void)wfs_closefs ( fs, curr_fs );
	        	return WFS_SIGNAL;
	        }

		/* reserving space for one block */
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		buf = (unsigned char *) malloc (wfs_getblocksize(fs,curr_fs)*sizeof(char));
		if ( (buf == NULL)
#ifdef HAVE_ERRNO_H
			|| (errno != 0)
#endif
		) {
			show_error ( error, err_msg_malloc, fsname );
			(void)wfs_closefs ( fs, curr_fs );
			optind++;
			ret = WFS_MALLOC;
			continue;
		}

	        /* removing undelete information */
		if ( (opt_nounrm == 0) && (sig_recvd == 0) ) {

			if ( opt_verbose == 1 ) {
				show_msg ( 1, msg_wipeunrm, fsname );
			}

			res = wipe_unrm(fs, curr_fs);
			if ( (res != WFS_SUCCESS) && (ret == WFS_SUCCESS) ) ret = res;
		}

		/* wiping partially occupied blocks */
		if ( (opt_nopart == 0) && (sig_recvd == 0) ) {

			if ( opt_verbose == 1 ) {
				show_msg ( 1, msg_wipeused, fsname );
			}

			res = wipe_part(fs, curr_fs);
			if ( (res != WFS_SUCCESS) && (ret == WFS_SUCCESS) ) ret = res;
		}

		if ( (opt_nowfs == 0) && (sig_recvd == 0) ) {

			if ( opt_verbose == 1 ) {
				show_msg ( 1, msg_wipefs, fsname );
			}

			res = wipe_fs(fs, curr_fs);
			if ( (res != WFS_SUCCESS) && (ret == WFS_SUCCESS) ) ret = res;
                }

		if ( opt_verbose == 1 ) {
			show_msg ( 1, msg_closefs, fsname );
		}

		res = wfs_closefs ( fs, curr_fs );
		if ( (res != WFS_SUCCESS) && (ret == WFS_SUCCESS) ) ret = res;

		free ( buf );
		buf = NULL;
		optind++;	/* next device */

#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H)
		sync();
#endif

	} /* while optind<argc && !signal */

	if ( sig_recvd != 0 ) return WFS_SIGNAL;
	else return ret;	/* return the last error value or zero */
}

