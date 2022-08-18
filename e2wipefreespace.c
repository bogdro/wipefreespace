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
 *
 * Thanks to:
 * - Theodore Ts'o, for the great ext2fs library and e2fsprogs
 * - Colin Plumb, for the great 'shred' program, parts of which are used here
 */

/*
 * TODO: try to wipe removed files' names, if possible BEFORE wiping free blocks
    look at the source of ext2fs_get_pathname, ext2fs_lookup, ext2fs_namei*
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

#ifdef __GNUC__
# define UNUSED __attribute__((unused))
# define NONNULL __attribute__((nonnull))
#else
# define UNUSED
# define NONNULL
#endif

static const char ver_str[]  = "This is e2wipefreespace, version 0.3\n";
static const char help_str[] =
	"e2wipefreespace - program for secure cleaning of free space on ext2/3 partitions."	\
	"\nSyntax: e2wipefreespace [options] /dev/XY [...]\n\n"					\
	"Options:\n"										\
	"-b|--superblock <off>\tSuperblock offset on the given filesystems\n"			\
	"-B|--blocksize <size>\tBlock size on the given filesystems\n"				\
	"-f|--force\t\tWipe even if the file system has errors\n"				\
	"-h|--help\t\tPrint help\n"								\
	"-l|--license\t\tPrint license information\n"						\
	"-n|--iterations NNN\tNumber of passes (>0, default: 25)\n"				\
	"-v|--verbose\t\tVerbose output\n"							\
	"-V|--version\t\tPrint version number\n"						\
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
static const char err_msg_flush[]   = "while flushing";
static const char err_msg_close[]   = "during closing";
static const char err_msg_malloc[]  = "during malloc while working on";
static const char err_msg_checkmt[] = "during checking if the file system is mounted: ";
static const char err_msg_mtrw[]    = "- Device is mounted in read-write mode:";
static const char err_msg_rdblbm[]  = "during reading block bitmap from";
static const char err_msg_wrtblk[]  = "during writing of a block on";
static const char err_msg_rdblk[]   = "during reading of a block on";
static const char err_msg_wrtino[]  = "during writing of an inode on";
static const char err_msg_signal[]  = "while trying to set a signal handler for";
static const char err_msg_fserr[]   = "Filesystem has errors:";
static const char err_msg_openscan[]= "during opening a scan of";
static const char err_msg_blkiter[] = "during iterating over blocks on";

/* Messages displayed when verbose mode is on */
static const char msg_signal[]      = "Setting signal handlers";
static const char msg_chkmnt[]      = "Checking if file system is mounted";
static const char msg_openfs[]      = "Opening file system";
static const char msg_flushfs[]     = "File system invalid or dirty, flushing";
static const char msg_rdblbm[]      = "Reading block bitmap from";
static const char msg_wipefs[]      = "Wiping free space on file system";
static const char msg_pattern[]     = "Using pattern";
static const char msg_random[]      = "random";
static const char msg_wipeused[]    = "Wiping unused space in used blocks and undelete data on";
static const char msg_closefs[]     = "Closing file system";

/* Command-line options. */
static int opt_blksize = 0;
static int opt_help    = 0;
static int opt_license = 0;
static int opt_number  = 0;
static int opt_super   = 0;
static int opt_verbose = 0;
static int opt_version = 0;
static int opt_force   = 0;

static int opt_char = 0;

static const struct option opts[] = {

		{ "blocksize",  required_argument, &opt_blksize, 1 },
		{ "force",      no_argument,       &opt_force,   1 },
		{ "help",       no_argument,       &opt_help,    1 },
		{ "iterations", required_argument, &opt_number,  1 },
		{ "licence",    no_argument,       &opt_license, 1 },
		{ "license",    no_argument,       &opt_license, 1 },
		{ "superblock", required_argument, &opt_super,   1 },
		{ "verbose",    no_argument,       &opt_verbose, 1 },
		{ "version",    no_argument,       &opt_version, 1 },
		{ NULL, 0, NULL, 0 }
	};

/* Signal-related stuff */

#ifndef __STDC__
static struct sigaction sa/* = { .sa_handler = &term_signal_received }*/;
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
static volatile int sig_recvd = 0;


#define	NPAT	22
static unsigned long int npasses = NPAT+3;	/* Number of passes (patterns used) */
static unsigned long int blocksize = 0;
static unsigned long int super_off = 0;

static /*@observer@*/ char *progname;		/* The name of the program */
static int ret;					/* Value returned by main() ("last error") */

static unsigned char /*@only@*/ *buf;		/* Buffer to be written to empty blocks */
static size_t s;				/* sizeof(signals) and size of the buffer */

static char *fsname;				/* Current file system device name */
static int mtflags;				/* Mount flags */
static errcode_t error;
static ext2_filsys fs;				/* The file system we're working on */
static ext2_inode_scan ino_scan;
static ext2_ino_t ino_number;
static struct ext2_inode ino;
static blk_t last_block_no;

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
 * Fills the given buffer with one of predefined patterns.
 * \param pat_no Pass number.
 * \param buffer Buffer to be filled.
 * \param buflen Length of the buffer.
 */
static void NONNULL fill_buffer ( 	unsigned long int 		pat_no,
					unsigned char* const 		buffer,
					const size_t 			buflen )
		/*@requires notnull buffer @*/ /*@sets *buffer @*/ {

	size_t i;
	unsigned int bits;

	/* De-select all patterns once every npasses calls. */
	if ( pat_no % npasses == 0 ) {
		for ( i = 0; (i < NPAT) && (sig_recvd==0); i++ ) { selected[i] = 0; }
        }
        if ( sig_recvd != 0 ) return;
        pat_no %= npasses;

	/* The first, last and middle passess will be using a random pattern */
	if ( pat_no == 0 || pat_no == npasses-1 || pat_no == npasses/2 ) {
#ifndef __STDC__
		bits = (unsigned int)(random() & 0xFFF);
#else
		bits = (unsigned int)(rand() & 0xFFF);
#endif
	} else {	/* For other passes, one of the fixed patterns is selected. */
		do {
#ifndef __STDC__
			i = (size_t)(random()%NPAT);
#else
			i = (size_t)(rand()%NPAT);
#endif
		} while ( selected[i] == 1 && sig_recvd == 0 );
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
		if ( pat_no == 0 || pat_no == npasses-1 || pat_no == npasses/2 ) {
			printf ( "%s: %s: '%s'\n", progname, msg_pattern, msg_random );
			fflush(stdout);
		} else {
			printf ( "%s: %s: '%02x%02x%02x'\n", progname, msg_pattern,
				buffer[0], buffer[1], buffer[2] );
			fflush(stdout);
		}
	}
	for (i = 3; (i < buflen / 2) && (sig_recvd == 0); i *= 2) {
		(void)memcpy (buffer + i, buffer, i);
	}
        if ( sig_recvd != 0 ) return;
	if (i < buflen) {
		(void)memcpy (buffer + i, buffer, buflen - i);
	}
}

#ifdef __GNUC__
 __attribute__((nonnull(2)))
#endif
/**
 * Wipes a block and writes it to the media.
 * \param FS The filesystem which the block is on.
 * \param BLOCKNR Pointer to physical block number.
 * \param BLOCKCNT Block type (<0 for metadata blocks, >=0 is the number of the block in the i-node).
 * \param PRIVATE Private data. If not NULL, is a pointer to an i-node, whose last block
 *	is to be partially wiped. We need the object size from the i-node.
 */
static int do_block ( 	const ext2_filsys 		FS,
			blk_t * const 			BLOCKNR,
			/*@unused@*/ const int 		BLOCKCNT UNUSED,
			/*@null@*/ void *		PRIVATE)
		/*@requires notnull FS, BLOCKNR @*/ {

	unsigned long int j;
	int returns = 0;
	size_t buf_start = 0;

	if ( PRIVATE != NULL ) {
		buf_start = EXT2_BLOCK_SIZE(FS->super) -
			( ((struct ext2_inode *)PRIVATE)->i_size % EXT2_BLOCK_SIZE(FS->super) );
		/* The beginning of the block must NOT be wiped, read it here. */
		error = io_channel_read_blk(FS->io, *BLOCKNR, 1, buf);
		if ( error != 0 ) {
			com_err ( progname, error, err_msg_format, err_msg, error,
				err_msg_rdblk, fsname );
			return BLOCK_ABORT;
		}
	}

	/* do nothing on metadata blocks *
	if ( BLOCKCNT < 0 ) return 0; */

	if ( *BLOCKNR == 0 ) return 0;

	for ( j = 0; (j < npasses) && (sig_recvd == 0); j++ ) {

		fill_buffer ( j, buf+buf_start, s-buf_start );
		if ( sig_recvd != 0 ) {
			returns = BLOCK_ABORT;
		       	break;
		}
		error = io_channel_write_blk(FS->io, *BLOCKNR, 1, buf);
		if ( error != 0 ) {
			com_err ( progname, error, err_msg_format, err_msg, error,
				err_msg_wrtblk, fsname );
			returns = BLOCK_ABORT;
		}
		/* Flush after each writing, if more than 1 overwriting needs to be done.
		   Allow I/O bufferring (efficiency), if just one pass is needed. */
		if ( npasses > 1 ) {
			error = ext2fs_flush ( FS );
			if ( error != 0 ) {
				com_err ( progname, error, err_msg_format, err_msg, error,
					err_msg_flush, fsname );
			}
		}
	}

	return returns;
}

/**
 * Signal handler - Sets a flag which will stop further program operations, when a
 * signal which would normally terminate the program is received.
 * \param signum Signal number.
 */
static void term_signal_received ( const int signum ) {

	sig_recvd = signum;
}

#ifdef __GNUC__
 __attribute__((nonnull(2)))
#endif
/**
 * Finds the last block number used by an i-node. Simply gets all block numbers one at
 * a time and saves the last one.
 * \param FS The filesystem which the block is on (unused).
 * \param BLOCKNR Pointer to physical block number.
 * \param BLOCKCNT Block type (<0 for metadata blocks, >=0 is the number of the block in the i-node), unused.
 * \param PRIVATE Private data (unused).
 */
static int count_blocks ( 	/*@unused@*/ const ext2_filsys	FS UNUSED,
				blk_t * const			BLOCKNR,
				/*@unused@*/ const int		BLOCKCNT UNUSED,
				/*@unused@*/ /*@null@*/ void *	PRIVATE UNUSED)
		/*@requires notnull BLOCKNR @*/ {

	last_block_no = *BLOCKNR;
	return 0;
}

/* ======================================================================== */
int main ( int argc, char* argv[] ) {

	__u32 i;
	int res;			/* s(n)printf result */
	unsigned long int j;
	char tmp[5];			/* Place for a signal number in case of error. */

	if ( argc <= 1 || argv == NULL ) {
		printf ( "%s", help_str );
		return -1;
	}

	if ( argv[0] != NULL ) {
		progname = argv[0];
	} else {
		progname = "e2wipefreespace";
	}

	/* Parsing the command line */
	optind = 0;
	while (1==1) {

		opt_char = getopt_long ( argc, argv, "Vhln:B:b:vf", opts, NULL );
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

		if ( opt_char == (int)'v' || opt_verbose == 1 ) {
			opt_verbose = 1;
		}

		if ( opt_char == (int)'f' || opt_force == 1 ) {
			opt_force = 1;
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

	if ( opt_verbose == 1 ) {
		printf ( "%s: %s\n", progname, msg_signal );
		fflush(stdout);
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
	(void)memset(&sa, 0, sizeof(struct sigaction));
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
        if ( sig_recvd != 0 ) return -100;
#ifndef __STDC__
	srandom(0xabadcafe*(unsigned long)time(NULL));
#else
	srand(0xabadcafe*(unsigned long)time(NULL));
#endif

	initialize_ext2_error_table();

	/*
	 * Unrecognised command line options are assumed to be devices, on which we are supposed to
	 * wipe the free space.
	 */
	while ( optind < argc && sig_recvd == 0 ) {

		ret = 0;
		fsname = argv[optind];
		if ( sig_recvd == 0 && opt_verbose == 1 ) {
			printf ( "%s: %s: '%s'\n", progname, msg_chkmnt, fsname );
			fflush(stdout);
		}

	        if ( sig_recvd != 0 ) return -100;
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
		if ( sig_recvd == 0 && opt_verbose == 1 ) {
			printf ( "%s: %s: '%s'\n", progname, msg_openfs, fsname );
			fflush(stdout);
		}

	        if ( sig_recvd != 0 ) return -100;
		error = ext2fs_open ( argv[optind], EXT2_FLAG_RW
#ifdef EXT2_FLAG_EXCLUSIVE
			| EXT2_FLAG_EXCLUSIVE
#endif
			, (int)super_off, (unsigned int)blocksize, unix_io_manager, &fs );
		if ( error != 0 ) {
			error = ext2fs_open ( argv[optind], EXT2_FLAG_RW, (int)super_off,
				(unsigned int)blocksize, unix_io_manager, &fs );
			if ( error != 0 ) {
				com_err ( progname, error, err_msg_format, err_msg, error,
					err_msg_open, fsname );
				optind++;
				ret = -4;
				continue;
			}
		}

	        if ( sig_recvd != 0 ) {
			error = ext2fs_close ( fs );
			if ( error != 0 ) {
				com_err ( progname, error, err_msg_format, err_msg, error,
					err_msg_close, fsname );
			}
	        	return -100;
	        }

		if ( opt_force == 0 && (fs->super->s_state & EXT2_ERROR_FS) != 0 ) {

			fprintf ( stderr, "%s: %s '%s'\n", progname, err_msg_fserr, fsname );
			fflush(stderr);
			optind++;
			ret = -7;
			continue;
		}

		/* flush the file system before starting, if there seems to be need. */
		if ( sig_recvd == 0 &&
			((fs->super->s_state & EXT2_VALID_FS) == 0 ||
			 (fs->flags & EXT2_FLAG_DIRTY) != 0 ||
			 ext2fs_test_changed(fs) != 0)
		   ) {

			if ( sig_recvd == 0 && opt_verbose == 1 ) {
				printf ( "%s: %s: '%s'\n", progname, msg_flushfs, fsname );
				fflush(stdout);
			}
			error = ext2fs_flush ( fs );
			if ( error != 0 ) {
				com_err ( progname, error, err_msg_format, err_msg, error,
					err_msg_flush, fsname );
			}
		}

		if ( sig_recvd == 0 && opt_verbose == 1 ) {
			printf ( "%s: %s: '%s'\n", progname, msg_rdblbm, fsname );
			fflush(stdout);
		}
	        if ( sig_recvd != 0 ) {
			error = ext2fs_close ( fs );
			if ( error != 0 ) {
				com_err ( progname, error, err_msg_format, err_msg, error,
					err_msg_close, fsname );
			}
	        	return -100;
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
		buf = (unsigned char *) malloc (s);
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

	        if ( sig_recvd != 0 ) break;
		if ( opt_verbose == 1 ) {
			printf ( "%s: %s: '%s'\n", progname, msg_wipeused, fsname );
			fflush(stdout);
		}

		/* wiping partially occupied blocks & removing undelete information */
		error = ext2fs_open_inode_scan ( fs, 0, &ino_scan );
		if ( error != 0 ) {
			com_err ( progname, error, err_msg_format, err_msg, error,
				err_msg_openscan, fsname );
			ret = -9;
		} else {

			do {
				error = ext2fs_get_next_inode (ino_scan, &ino_number, &ino);
				if ( error != 0 ) continue;
				if ( ino_number == 0 ) break;	/* 0 means "last done" */

				if ( ino_number < EXT2_FIRST_INO(fs->super) ) continue;
			        if ( sig_recvd != 0 ) break;

				/* removing undelete information */
				if ( (ino.i_flags & EXT2_UNRM_FL) != 0 || ino.i_dtime != 0 ) {

					/* If the i-node does not contain data blocks
					   (symlink or device), the array of blocks itself
					   contains the name (libext2fs->namei.c) */
					if ( ext2fs_inode_data_blocks(fs, &ino) == 0 && (
						LINUX_S_ISLNK(ino.i_mode) ||
						LINUX_S_ISCHR(ino.i_mode) ||
						LINUX_S_ISBLK(ino.i_mode) )
					   ) {
						/* wipe the array of blocks (part of inode) */
						for ( j = 0; (j < npasses) && (sig_recvd == 0); j++ ) {

							fill_buffer ( j, (unsigned char*)ino.i_block,
								EXT2_N_BLOCKS*sizeof(__u32) );

							error = ext2fs_write_inode ( fs, ino_number, &ino );
							if ( error != 0 ) {
								com_err ( progname, error, err_msg_format, err_msg, error,
									err_msg_wrtino, fsname );
								ret = -11;
							}
							error = ext2fs_flush ( fs );
							if ( error != 0 ) {
								com_err ( progname, error, err_msg_format, err_msg, error,
									err_msg_flush, fsname );
							}
						}
						for ( j=0; j<EXT2_N_BLOCKS; j++ ) ino.i_block[j] = 0;

					} else {
						/* FIXME: this doesn't seem to work. */
						if ( do_block (fs, &ino.i_block[0], 1, NULL) != 0 ) break;

					}
					/* marking the i-node as not deleted and writing it back */
					ino.i_flags &= ~EXT2_UNRM_FL;
					error = ext2fs_write_inode ( fs, ino_number, &ino );
					if ( error != 0 ) {
						com_err ( progname, error, err_msg_format, err_msg, error,
							err_msg_wrtino, fsname );
						ret = -11;
					}
					error = ext2fs_flush ( fs );
					if ( error != 0 ) {
						com_err ( progname, error, err_msg_format, err_msg, error,
							err_msg_flush, fsname );
					}
				}
			        if ( sig_recvd != 0 ) break;
				if ( ino.i_blocks == 0 ) continue;

				/* e2fsprogs:
			 	 * If i_blocks is non-zero, or the index flag is set, then
			 	 * this is a bogus device/fifo/socket
			 	 */
				if ((ext2fs_inode_data_blocks(fs, &ino) != 0) ||
					(ino.i_flags & EXT2_INDEX_FL) != 0)
						continue;

			        if ( sig_recvd != 0 ) break;

				last_block_no = 0;

				/* find the last data block number. */
				error = ext2fs_block_iterate (fs, ino_number, BLOCK_FLAG_DATA_ONLY, NULL,
					&count_blocks, NULL);
				if ( error != 0 ) {
					com_err ( progname, error, err_msg_format, err_msg, error,
						err_msg_blkiter, fsname );
					ret = -10;
				}
				/* check if there's unused space in a block */
				if ( (ino.i_size % EXT2_BLOCK_SIZE(fs->super)) == 0 ) continue;
				/* partially wipe the last block */
				if ( do_block (fs, &last_block_no, 1, &ino) != 0 ) break;

			} while ( (error == 0 || error == EXT2_ET_BAD_BLOCK_IN_INODE_TABLE) &&
				sig_recvd == 0 );

			ext2fs_close_inode_scan (ino_scan);
		}

		if ( sig_recvd == 0 && opt_verbose == 1 ) {
			printf ( "%s: %s: '%s'\n", progname, msg_wipefs, fsname );
			fflush(stdout);
		}
		/* wiping free blocks on the whole device */
		for ( i = 1; (i < fs->super->s_blocks_count) && (sig_recvd == 0); i++ ) {

			/* if we find an empty block, we shred it */
			if ( ext2fs_test_block_bitmap ( fs->block_map, (blk_t)i ) == 0 ) {

				if ( do_block (fs, (blk_t*)(&i), 1, NULL) != 0 ) break;
			}
		}

		if ( opt_verbose == 1 ) {
			printf ( "%s: %s: '%s'\n", progname, msg_closefs, fsname );
			fflush(stdout);
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

	if ( sig_recvd != 0 ) return -100;
	else return ret;	/* return the last error value or zero */
}

