/*
 * A program for secure cleaning of free space on ext2/3 partitions.
 *
 * Copyright (C) 2007 Bogdan Drozdowski, bogdandr (at) op.pl
 * License: GNU General Public License, v2+
 *
 * Syntax example: e2wipefreespace /dev/hdd1
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

/* TODO: wipe unused space in partially occupied blocks, if possible
 * TODO: try also to wipe removed files' names, if possible
 * TODO: flush the fs before starting
 * TODO: allow translations
 * TODO: write a man page
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>	/* just for ext2fs.h ... */
#include <getopt.h>
#include <et/com_err.h>
#include <ext2fs/ext2fs.h>
#include <malloc.h>
#include <signal.h>
#include <time.h>	/* time() for randomization purposes */

static const char ver_str[]  = "This is e2wipefreespace, version 0.1\n";
static const char help_str[] =
	"e2wipefreespace - program for secure cleaning of free space on ext2/3 partitions."	\
	"\nSyntax: e2wipefreespace [options] /dev/XY [...]\n\n"					\
	"Options:\n-V|--version\t\tPrint version number\n-h|--help\t\tPrint help\n"		\
	"-l|--license\t\tPrint license information\n"						\
	"-n|--iterations NNN\tNumber of passes (>0, default: 25)\n"				\
	"-B|--blocksize\t\tBlock size on the given filesystems\n"				\
	"-b|--superblock\t\tSuperblock offset on the given filesystems\n"			\
	;
static const char author_str[] = "Copyright (C) 2007 Bogdan 'bogdro' Drozdowski, bogdandr@op.pl\n";
static const char lic_str[]  =
	"e2wipefreespace - program for secure cleaning of free space on ext2/3 partitions.\n"	\
	"\nThis program is free software; you can redistribute it and/or"			\
	"\nmodify it under the terms of the GNU General Public License"				\
	"\nas published by the Free Software Foundation; either version 2"			\
	"\nof the License, or (at your option) any later version."				\
	"\n\nThis program is distributed in the hope that it will be useful,"			\
	"\nbut WITHOUT ANY WARRANTY; without even the implied warranty of"			\
	"\nMERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\n";

/* Error messages explaining the stage during which an error occurred. */
static const char err_msg_format[]  = "(%s %ld) %s '%s'";
static const char err_msg[]         = "error";
static const char err_msg_open[]    = "during opening";
static const char err_msg_close[]   = "during closing";
static const char err_msg_malloc[]  = "during malloc while working on";
static const char err_msg_checkmt[] = "during checking if the file system is mounted: ";
static const char err_msg_mtrw[]    = "- Device is mounted in read-write mode:";
static const char err_msg_rdblbm[]  = "during reading block bitmap from";
static const char err_msg_wrtblk[]  = "during writing of a block on";
static const char err_msg_signal[]  = "while trying to set a signal handler for";

/* Command-line options. */
static int opt_version = 0;
static int opt_help    = 0;
static int opt_license = 0;
static int opt_number  = 0;
static int opt_blksize = 0;
static int opt_super   = 0;
static int opt_char = 0;

static const struct option opts[] = {

		{ "version",    no_argument,       &opt_version, 1 },
		{ "help",       no_argument,       &opt_help,    1 },
		{ "license",    no_argument,       &opt_license, 1 },
		{ "licence",    no_argument,       &opt_license, 1 },
		{ "iterations", required_argument, &opt_number,  1 },
		{ "blocksize",  required_argument, &opt_blksize, 1 },
		{ "superblock", required_argument, &opt_super,   1 },
		{ NULL, 0, NULL, 0 }
	};

#ifndef __STDC__
static struct sigaction sa;
#endif
/* Handled signals which will cause the program to exit cleanly. */
static const int signals[] = { SIGINT, SIGQUIT,	SIGILL,	SIGABRT, SIGFPE, SIGSEGV, SIGPIPE,
	SIGALRM, SIGTERM, SIGUSR1, SIGUSR2, SIGTSTP, SIGTTIN, SIGTTOU, SIGBUS, SIGPOLL, SIGPROF,
	SIGSYS, SIGTRAP, SIGXCPU, SIGXFSZ, SIGPWR, SIGVTALRM, SIGUNUSED,
#ifndef __STDC__
	SIGEMT, SIGLOST,
#endif
	};
static const char sig_unk[] = "unknown";

#define	NPAT	22
static unsigned long int npasses = NPAT+3;	/* Number of passes (patterns used) */
static unsigned long int blocksize = 0;
static unsigned long int super_off = 0;

static char *progname;				/* The name of the program */
static int ret;					/* Value returned by main() ("last error") */

static char *fsname;				/* Current file system device name */
static int mtflags;				/* Mount flags */
static errcode_t error;
static ext2_filsys fs;				/* The file system we're working on */
static char /*@only@*/ *buf;			/* Buffer to be written to empty blocks */

/* Taken from `shred' source */
static unsigned const int patterns[NPAT] =
{
	0x000, 0xFFF,					/* 1-bit */
	0x555, 0xAAA,					/* 2-bit */
	0x249, 0x492, 0x6DB, 0x924, 0xB6D, 0xDB6,	/* 3-bit */
	0x111, 0x222, 0x333, 0x444, 0x666, 0x777,
	0x888, 0x999, 0xBBB, 0xCCC, 0xDDD, 0xEEE	/* 4-bit */
};

static short int selected[NPAT];

/*
 * This function fills the given buffer with one of predefined patterns.
 */
static void fill_buffer ( const unsigned long int pat_no, char* const buffer,
	const size_t buflen ) /*@requires notnull buffer @*/ /*@sets *buffer @*/  {

	size_t i;
	unsigned int bits;

	/* De-select all patterns once every npasses calls. */
	if ( pat_no%npasses == 0 ) {
		for ( i = 0; i < NPAT; i++ ) { selected[i] = 0; }
        }

	/* The first, last and middle passess will be using a random pattern */
	if ( pat_no == 0 || pat_no == npasses-1 || pat_no == npasses/2 ) {
#ifndef __STDC__
		bits = (unsigned int)(random() /* & 0xFFF */);
#else
		bits = (unsigned int)(rand() /* & 0xFFF */);
#endif
	} else {	/* For other passes, one of the fixed patterns is selected. */
		do {
#ifndef __STDC__
			i = (size_t)(random()%NPAT);
#else
			i = (size_t)(rand()%NPAT);
#endif
		} while ( selected[i] == 1 );
		bits = patterns[i];
		selected[i] = 1;
    	}

	/* Taken from `shred' source and modified */
	bits |= bits << 12;
	buffer[0] = (char)((bits >> 4) & 0xFF);
	buffer[1] = (char)((bits >> 8) & 0xFF);
	buffer[2] = (char)(bits & 0xFF);
	for (i = 3; i < buflen / 2; i *= 2) {
		(void)memcpy (buffer + i, buffer, i);
	}
	if (i < buflen) {
		(void)memcpy (buffer + i, buffer, buflen - i);
	}
}

/*
 * When a signal which would normally terminate the program is received, close the file system,
 * free allocated memory and exit.
 */
static void term_signal_received ( const int signum ) {

	if ( fs != NULL ) {
		error = ext2fs_close ( fs );
		if ( error != 0 ) {
			com_err ( progname, error, err_msg_format, err_msg, error,
				err_msg_close, fsname );
		}
	}
	if ( buf != NULL ) free ( buf );
	exit ( signum );
}

int main ( int argc, char* argv[] ) {

	__u32 i;
	int res;			/* s(n)printf result */
	unsigned long int j;
	size_t s;			/* sizeof(signals) and size of the buffer */
	char tmp[5];			/* Place for a signal number in case of error. */

	progname = argv[0];

	/* Parsing the command line */
	optind = 0;
	while (1==1) {

		opt_char = getopt_long ( argc, argv, "Vhln:B:b:", opts, NULL );
		if ( opt_char == -1 ) break;

		if ( opt_char == (int)'?' || opt_char == (int)':' ) {
			printf ( "%s", help_str );
			return -1;
		}

		if ( opt_char == (int)'h' || opt_help == 1 ) {
			printf ( "%s", help_str );
			return 1;
		}

		if ( opt_char == (int)'V' || opt_version == 1 ) {
			printf ( "%s", ver_str );
			return 1;
		}

		if ( opt_char == (int)'l' || opt_license == 1 ) {
			printf ( "%s%s", lic_str, author_str );
			return 1;
		}

		if ( opt_char == (int)'n' || opt_number == 1 ) {
			errno = 0;
			npasses = strtoul ( optarg, NULL, 10 );
			if ( errno != 0 || npasses == 0 ) {
				printf ( "%s", help_str );
				return -1;
			}
		}

		if ( opt_char == (int)'B' || opt_blksize == 1 ) {
			errno = 0;
			blocksize = strtoul ( optarg, NULL, 10 );
			if ( errno != 0 ) {
				printf ( "%s", help_str );
				return -1;
			}
		}

		if ( opt_char == (int)'b' || opt_super == 1 ) {
			errno = 0;
			super_off = strtoul ( optarg, NULL, 10 );
			if ( errno != 0 ) {
				printf ( "%s", help_str );
				return -1;
			}
		}
	}

	if ( optind >= argc || argv[optind] == NULL ) {
		printf ( "%s", help_str );
		return -1;
	}

	/*
	 * Setting signal handlers. We need to catch signals in order to close (and flush)
	 * an opened file system, to prevent unconsistencies.
	 */

#ifdef __STDC__
	/* ANSI C */
	for ( s=0; s < sizeof(signals)/sizeof(signals[0]); s++ ) {
		errno = 0;
		if ( signal ( signals[s], &term_signal_received ) == SIG_ERR || errno != 0 ) {
			error = errno;
			res = sprintf(tmp, "%d", signals[s] );
			if ( error != 0 ) {
				com_err ( progname, error, err_msg_format, err_msg, error,
					err_msg_signal, (res>0)?tmp:sig_unk );
			} else {
				com_err ( progname, 1L, err_msg_format, err_msg, 1L,
					err_msg_signal, (res>0)?tmp:sig_unk );
			}
		}
	}

#else
	/* ISO C */
	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = &term_signal_received;
	for ( s=0; s < sizeof(signals)/sizeof(signals[0]); s++ ) {
		errno = 0;
		if ( sigaction( signals[s], &sa, NULL) != 0 || errno != 0 ) {
			error = errno;
			res = snprintf(tmp, 5, "%d", signals[s] );
			com_err ( progname, error, err_msg_format, err_msg, error,
				err_msg_signal, (res>0)?tmp:sig_unk );
		}
	}
#endif

	/* Set all patterns as unused */
	for ( i = 0; i < NPAT; i++ ) { selected[i] = 0; }
#ifndef __STDC__
	srandom(0xabadcafe*(unsigned long)time(NULL));
#else
	srand(0xabadcafe*(unsigned long)time(NULL));
#endif

	/*
	 * Unrecognised command line options are assumed to be devices, on which we are supposed to
	 * wipe the free space.
	 */
	while ( optind < argc ) {

		ret = 0;
		fsname = argv[optind];
		/* reject if mounted for read and write (when we can't go on with our work) */
		error = ext2fs_check_if_mounted ( fsname, &mtflags );
		if ( error != 0 ) {
			com_err ( progname, error, err_msg_format, err_msg, error,
				err_msg_checkmt, fsname );
			/* go to the next device on the command line and set the "last error" value */
			optind++;
			ret = -2;
			continue;
		}
		if ( ((mtflags & EXT2_MF_MOUNTED) != 0) && ((mtflags & EXT2_MF_READONLY) == 0) ) {
			com_err ( progname, 1L, err_msg_format, err_msg, 1L,
				err_msg_mtrw, fsname );
			optind++;
			ret = -3;
			continue;
		}

		/* opening the file system */
		error = ext2fs_open ( argv[optind], EXT2_FLAG_RW
#ifdef EXT2_FLAG_EXCLUSIVE
			| EXT2_FLAG_EXCLUSIVE
#endif
			, (int)super_off, blocksize, unix_io_manager, &fs );
		if ( error != 0 ) {
			com_err ( progname, error, err_msg_format, err_msg, error,
				err_msg_open, fsname );
			optind++;
			ret = -4;
			continue;
		}

		/* read the bitmap of blocks */
		error = ext2fs_read_block_bitmap ( fs );
		if ( error != 0 ) {
			com_err ( progname, error, err_msg_format, err_msg, error,
				err_msg_rdblbm, fsname );
			error = ext2fs_close ( fs );
			if ( error != 0 ) {
				com_err ( progname, error, err_msg_format, err_msg, error,
					err_msg_close, fsname );
			}
			optind++;
			ret = -5;
			continue;
		}

		/* reserving space for one block */
		s = EXT2_BLOCK_SIZE(fs->super)*sizeof(char);
		errno = 0;
		buf = (char *) malloc (s);
		if ( buf == NULL || errno != 0 ) {
			com_err ( progname, errno, err_msg_format, err_msg, (long)errno,
				err_msg_malloc, fsname );
			error = ext2fs_close ( fs );
			if ( error != 0 ) {
				com_err ( progname, error, err_msg_format, err_msg, error,
					err_msg_close, fsname );
			}
			optind++;
			ret = -6;
			continue;
		}

		for ( i = 0; i < fs->super->s_blocks_count; i++ ) {

			/* if we find an empty block, we shred it */
			if ( ext2fs_test_block_bitmap ( fs->block_map, (blk_t)i ) == 0 ) {

				for ( j = 0; j < npasses; j++ ) {
					fill_buffer ( j%NPAT, buf, s );
					error = io_channel_write_blk(fs->io, (blk_t)i, 1, buf);
					if ( error != 0 ) {
						com_err ( progname, error, err_msg_format, err_msg, error,
							err_msg_wrtblk, fsname );
						ret = -7;
					}
				}
			}
		}

		error = ext2fs_close ( fs );
		if ( error != 0 ) {
			com_err ( progname, error, err_msg_format, err_msg, error,
				err_msg_close, fsname );
			ret = -8;
		}
		free ( buf );
		buf = NULL;
		optind++;	/* next device */

	} /* while optind<argc */

	return ret;	/* return the last error value or zero */
}
