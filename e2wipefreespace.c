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
 * TODO: code rebuild to allow other FS than ext2/3
 * TODO: allow translations?
 * TODO: write a man page?
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#if defined __STDC__ || defined __STRICT_ANSI__
# include <sys/types.h>		/* just for ext2fs.h */
#endif
#include <et/com_err.h>
#include <ext2fs/ext2fs.h>
#include <malloc.h>
#include <signal.h>
#include <time.h>	/* time() for randomization purposes */
#include <unistd.h>	/* sync() */
#include <sys/stat.h>

#ifdef __GNUC__
# define UNUSED		__attribute__((unused))
# define NONNULL	__attribute__((nonnull))
#else
# define UNUSED
# define NONNULL
#endif

#define	PROGRAM_NAME	"e2wipefreespace"

#define ver_str "This is %s, version 0.4\n"
#define author_str "Copyright (C) 2007 Bogdan 'bogdro' Drozdowski, bogdandr@op.pl\n"
#define lic_str										\
	"%s - program for secure cleaning of free space on ext2/3 partitions.\n"	\
	"\nThis program is free software; you can redistribute it and/or"		\
	"\nmodify it under the terms of the GNU General Public License"			\
	"\nas published by the Free Software Foundation; either version 2"		\
	"\nof the License, or (at your option) any later version."			\
	"\n\nThis program is distributed in the hope that it will be useful,"		\
	"\nbut WITHOUT ANY WARRANTY; without even the implied warranty of"		\
	"\nMERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\n"

/* Error messages explaining the stage during which an error occurred. */
#define err_msg_format			"(%s %ld) %s '%s'"
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
static const char err_msg_rdino[]   = "during reading of an inode on";
static const char err_msg_signal[]  = "while trying to set a signal handler for";
static const char err_msg_fserr[]   = "Filesystem has errors:";
static const char err_msg_openscan[]= "during opening a scan of";
static const char err_msg_blkiter[] = "during iterating over blocks on";
static const char err_msg_diriter[] = "during iterating over a directory on";
static const char err_msg_nowork[]  = ": Nothing selected for wiping.";

/* Messages displayed when verbose mode is on */
#define msg_format			"%s: %s: '%s'\n"
static const char msg_signal[]      = "Setting signal handlers";
static const char msg_chkmnt[]      = "Checking if file system is mounted";
static const char msg_openfs[]      = "Opening file system";
static const char msg_flushfs[]     = "File system invalid or dirty, flushing";
static const char msg_rdblbm[]      = "Reading block bitmap from";
static const char msg_wipefs[]      = "Wiping free space on file system";
static const char msg_pattern[]     = "Using pattern";
static const char msg_random[]      = "random";
static const char msg_wipeused[]    = "Wiping unused space in used blocks on";
static const char msg_wipeunrm[]    = "Wiping undelete data on";
static const char msg_closefs[]     = "Closing file system";

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

#if !defined __STDC__ && !defined __STRICT_ANSI__
static struct sigaction sa/* = { .sa_handler = &term_signal_received }*/;
#endif
/* Handled signals which will cause the program to exit cleanly. */
static const int signals[] = { SIGINT, SIGQUIT,	SIGILL,	SIGABRT, SIGFPE, SIGSEGV, SIGPIPE,
	SIGALRM, SIGTERM, SIGUSR1, SIGUSR2, SIGTTIN, SIGTTOU, SIGBUS, SIGPOLL, SIGPROF,
	SIGSYS, SIGTRAP, SIGXCPU, SIGXFSZ, SIGPWR, SIGVTALRM, SIGUNUSED,
#if !defined __STDC__ && !defined __STRICT_ANSI__
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

static unsigned char /*@only@*/ *buf;		/* Buffer to be written to empty blocks */

static char *fsname;				/* Current file system device name */
static ext2_filsys fs;				/* The file system we're working on */
static errcode_t error;
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
 * Prints the help screen.
 * \param my_name Program identifier, like argv[0], if available.
 */
static NONNULL void print_help ( const char* const my_name ) {

	const char /*@observer@*/ *prog;
	if ( my_name == NULL ) {
		prog = PROGRAM_NAME;
	} else if ( strlen(my_name) == 0 ) {
		prog = PROGRAM_NAME;
	} else {
		prog = my_name;
	}

	printf (
		"%s - Program for secure cleaning of free space on ext2/3 partitions"	\
		"\nSyntax: %s [options] /dev/XY [...]\n\n"			\
		"Options:\n"								\
		"-b|--superblock <off>\tSuperblock offset on the given filesystems\n"	\
		"-B|--blocksize <size>\tBlock size on the given filesystems\n"		\
		"-f|--force\t\tWipe even if the file system has errors\n", prog, prog	);
	(void)puts (
		"-h|--help\t\tPrint help\n"						\
		"-l|--license\t\tPrint license information\n"				\
		"-n|--iterations NNN\tNumber of passes (>0, default: 25)\n"		\
		"--nopart\t\tDo NOT wipe free space in partially used blocks"		);
	(void)puts (
		"--nounrm\t\tDo NOT wipe undelete information\n"			\
		"--nowfs\t\t\tDo NOT wipe free space on file system\n"			\
		"-v|--verbose\t\tVerbose output\n"					\
		"-V|--version\t\tPrint version number\n"				);

}

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
#if !defined __STDC__ && !defined __STRICT_ANSI__
		bits = (unsigned int)(random() & 0xFFF);
#else
		bits = (unsigned int)(rand() & 0xFFF);
#endif
	} else {	/* For other passes, one of the fixed patterns is selected. */
		do {
#if !defined __STDC__ && !defined __STRICT_ANSI__
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
		if ( pat_no == 0 || pat_no == npasses-1 || pat_no == npasses/2 ) {
			printf ( msg_format, progname, msg_pattern, msg_random );
			(void)fflush(stdout);
		} else {
			printf ( "%s: %s: '%02x%02x%02x'\n", progname, msg_pattern,
				buffer[0], buffer[1], buffer[2] );
			(void)fflush(stdout);
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
 __attribute__((warn_unused_result))
#endif
/**
 * Wipes a block and writes it to the media.
 * \param FS The filesystem which the block is on.
 * \param BLOCKNR Pointer to physical block number.
 * \param BLOCKCNT Block type (<0 for metadata blocks, >=0 is the number of the block in the i-node).
 * \param PRIVATE Private data. If not NULL, is a pointer to an i-node, whose last block
 *	is to be partially wiped. We need the object size from the i-node.
 * \return 0 in case of no errors, and BLOCK_ABORT in case of signal or error.
 */
static int do_block ( 	const ext2_filsys		FS,
			const blk_t * const 		BLOCKNR,
			const int			BLOCKCNT,
			/*@null@*/ void * const		PRIVATE)
		/*@requires notnull FS, BLOCKNR @*/ {

	unsigned long int j;
	int returns = 0;
	size_t buf_start = 0;

	if ( (PRIVATE != NULL) && (sig_recvd == 0) ) {
		buf_start = (size_t)(EXT2_BLOCK_SIZE(FS->super) -
			( ((struct ext2_inode *)PRIVATE)->i_size % EXT2_BLOCK_SIZE(FS->super) ) );
		/* The beginning of the block must NOT be wiped, read it here. */
		error = io_channel_read_blk(FS->io, *BLOCKNR, 1, buf);
		if ( error != 0 ) {
			com_err ( progname, error, err_msg_format, err_msg, error,
				err_msg_rdblk, fsname );
			return BLOCK_ABORT;
		}
	}

	/* do nothing on metadata blocks or if incorrect block number given */
	if ( BLOCKCNT < 0 || *BLOCKNR == 0 ) return 0;

	for ( j = 0; (j < npasses) && (sig_recvd == 0); j++ ) {

		fill_buffer ( j, buf+buf_start, EXT2_BLOCK_SIZE(FS->super)-buf_start );
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
		if ( (npasses > 1) && (sig_recvd == 0) ) {
			error = ext2fs_flush ( FS );
			if ( error != 0 ) {
				com_err ( progname, error, err_msg_format, err_msg, error,
					err_msg_flush, fsname );
			}
#if !defined __STDC__ && !defined __STRICT_ANSI__
			sync();
#endif
		}
	}
	if ( sig_recvd != 0 ) {
		return BLOCK_ABORT;
	} else {
		return returns;
	}
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
 * \return This function always returns 0.
 */
static int count_blocks (
		/*@unused@*/ 		const ext2_filsys	FS UNUSED,
					blk_t * const		BLOCKNR,
		/*@unused@*/ 		const int		BLOCKCNT UNUSED,
		/*@unused@*/ /*@null@*/	void *			PRIVATE UNUSED)
		/*@requires notnull BLOCKNR @*/ {

	last_block_no = *BLOCKNR;
	return 0;
}

/**
 * Wipes undelete information from the given directory i-node.
 * \param dir I-node number of the direcotry being browsed (unused).
 * \param entry Type of directory entry.
 * \param DIRENT Pointer to a ext2_dir_entry structure describing current directory entry.
 * \param OFFSET Offset of the ext2_dir_entry structure from beginning of the directory block.
 * \param BLOCKSIZE Size of a block on the file system (unused).
 * \param BUF Pointer to contents of the directory block.
 * \param PRIVATE Points to an unsigned long int, which holds the current pass number.
 * \return 0 in case of no errors, DIRENT_ABORT in case of error and DIRENT_CHANGED in case
 *	data was moified.
 */
static NONNULL int wipe_unrm_dir (
		/*@unused@*/		ext2_ino_t		dir UNUSED,
					int			entry,
			 		struct ext2_dir_entry*	DIRENT,
					int 			OFFSET,
		/*@unused@*/		int 			BLOCKSIZE UNUSED,
					char* const		BUF,
          				void* const		PRIVATE )
	/*@requires notnull DIRENT,BUF,PRIVATE @*/ {

	unsigned long int j = *((unsigned long int *)PRIVATE);
	int ret_unrm = 0;
	int changed = 0;
	struct ext2_inode unrm_ino;
	char* filename = BUF + OFFSET + sizeof(__u32) + 2*sizeof(__u16);

	/* is the current entry deleted? */
	if ( (entry == DIRENT_DELETED_FILE) && (sig_recvd == 0) ) {

		fill_buffer ( j, (unsigned char *)filename, (size_t)(DIRENT->name_len) );
		changed = 1;

	/* is the current i-node a directory? If so, dig into it. */
	} else if ( (DIRENT->inode != 0) && (sig_recvd == 0) ) {

		error = ext2fs_read_inode ( fs, DIRENT->inode, &unrm_ino );
		if ( error != 0 ) {
			com_err ( progname, error, err_msg_format, err_msg, error,
				err_msg_rdino, fsname );
			ret_unrm = -12;
		}

	 	if (    (ret_unrm == 0)
	 		&& (sig_recvd == 0)
	 		&& LINUX_S_ISDIR(unrm_ino.i_mode)
			&& (strncmp("." , filename, (size_t)DIRENT->name_len) != 0)
			&& (strncmp("..", filename, (size_t)DIRENT->name_len) != 0)
		) {

			error = ext2fs_dir_iterate2 ( fs, DIRENT->inode, DIRENT_FLAG_INCLUDE_EMPTY |
				DIRENT_FLAG_INCLUDE_REMOVED, NULL, &wipe_unrm_dir, PRIVATE );
			if ( error != 0 ) {
				com_err ( progname, error, err_msg_format, err_msg, error,
					err_msg_diriter, fsname );
				ret_unrm = -13;
			}
		}

	} /* do nothing on non-deleted, non-directory i-nodes */

	if ( ret_unrm != 0 || sig_recvd != 0 ) {
		return DIRENT_ABORT;
	} else if ( changed != 0 ) {
		return DIRENT_CHANGED;
	} else {
		return 0;
	}
}

#ifdef	__GNUC__
 __attribute__((warn_unused_result))
#endif
/**
 * Starts recursive directory search for deleted inodes and undelete data.
 * \param FS The filesystem.
 * \param node Directory i-node number.
 * \return 0 in case of no errors, other values otherwise.
 */
static int wipe_unrm ( ext2_filsys FS, ext2_ino_t node ) {

	unsigned long int j;

	for ( j = 0; (j < npasses) && (sig_recvd == 0); j++ ) {

		error = ext2fs_dir_iterate2 ( FS, node, DIRENT_FLAG_INCLUDE_EMPTY |
			DIRENT_FLAG_INCLUDE_REMOVED, NULL, &wipe_unrm_dir, &j );
		if ( error != 0 ) {
			com_err ( progname, error, err_msg_format, err_msg, error,
				err_msg_diriter, fsname );
			return -13;
		}
		if ( (npasses > 1) && (sig_recvd == 0) ) {
			error = ext2fs_flush ( FS );
			if ( error != 0 ) {
				com_err ( progname, error, err_msg_format, err_msg, error,
					err_msg_flush, fsname );
			}
#if !defined __STDC__ && !defined __STRICT_ANSI__
			sync();
#endif
		}
	}

	return 0;
}

/**
 * Wipes the free space on the given filesystem.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
static int wipe_fs ( ext2_filsys FS ) {

	int ret_wfs = 0;
	blk_t blno;			/* block number */

	/* read the bitmap of blocks */
	error = ext2fs_read_block_bitmap ( FS );
	if ( error != 0 ) {
		com_err ( progname, error, err_msg_format, err_msg, error,
			err_msg_rdblbm, fsname );
		error = ext2fs_close ( FS );
		if ( error != 0 ) {
			com_err ( progname, error, err_msg_format, err_msg, error,
				err_msg_close, fsname );
		}
		optind++;
		return -5;
	}

	if ( (sig_recvd == 0) && (opt_verbose == 1) ) {
		printf ( msg_format, progname, msg_wipefs, fsname );
		(void)fflush(stdout);
	}

	/* wiping free blocks on the whole device */
	for ( blno = 1; (blno < FS->super->s_blocks_count) && (sig_recvd == 0); blno++ ) {

		/* if we find an empty block, we shred it */
		if ( ext2fs_test_block_bitmap ( FS->block_map, blno ) == 0 ) {

			if ( (do_block (FS, &blno, 1, NULL) != 0) || (sig_recvd != 0) ) break;
		}
	}
	if ( sig_recvd != 0 ) return -100;
	return ret_wfs;
}

/**
 * Wipes the free space in partially used blocks on the given filesystem.
 * \param FS The filesystem.
 * \return 0 in case of no errors, other values otherwise.
 */
static int wipe_part ( ext2_filsys FS ) {

	ext2_inode_scan ino_scan = 0;
	ext2_ino_t ino_number = 0;
	struct ext2_inode ino;
	int ret_part = 0;

	error = ext2fs_open_inode_scan ( FS, 0, &ino_scan );
	if ( error != 0 ) {
		com_err ( progname, error, err_msg_format, err_msg, error,
			err_msg_openscan, fsname );
		return -9;
	} else {

		do {
			error = ext2fs_get_next_inode (ino_scan, &ino_number, &ino);
			if ( error != 0 ) continue;
			if ( ino_number == 0 ) break;	/* 0 means "last done" */

			if ( ino_number < (ext2_ino_t)EXT2_FIRST_INO(FS->super) ) continue;
	        	if ( sig_recvd != 0 ) break;

			if ( ino.i_blocks == 0 ) continue;

			/* e2fsprogs:
		 	 * If i_blocks is non-zero, or the index flag is set, then
		 	 * this is a bogus device/fifo/socket
		 	 */
			if ((ext2fs_inode_data_blocks(FS, &ino) != 0) ||
				(ino.i_flags & EXT2_INDEX_FL) != 0)
					continue;

		        if ( sig_recvd != 0 ) break;

			/* check if there's unused space in any block */
			if ( (ino.i_size % EXT2_BLOCK_SIZE(FS->super)) == 0 ) continue;

			/* find the last data block number. */
			last_block_no = 0;
			error = ext2fs_block_iterate (FS, ino_number, BLOCK_FLAG_DATA_ONLY, NULL,
				&count_blocks, NULL);
			if ( error != 0 ) {
				com_err ( progname, error, err_msg_format, err_msg, error,
					err_msg_blkiter, fsname );
				ret_part = -10;
			}
	        	if ( sig_recvd != 0 ) break;
			/* partially wipe the last block */
			if ( do_block (FS, &last_block_no, 1, &ino) != 0 ) break;

		} while ( (
				(error == 0) || (error == EXT2_ET_BAD_BLOCK_IN_INODE_TABLE)
			  ) && (sig_recvd == 0) );

		ext2fs_close_inode_scan (ino_scan);
#if !defined __STDC__ && !defined __STRICT_ANSI__
		sync();
#endif
	}
	if ( sig_recvd != 0 ) return -100;
	return ret_part;
}

/* ======================================================================== */
int main ( int argc, char* argv[] ) {

	int ret = 0;			/* Value returned by main() ("last error") */
	int res;			/* s(n)printf & fstat result */
	char tmp[12];			/* Place for a signal number in case of error. */
	int i;

	int mtflags = 0;		/* Mount flags */
	size_t s;			/* sizeof(signals) */

	struct stat stat_buf;

	errno = 0;
	res = fstat(STDOUT_FILENO, &stat_buf);
	if ( (res < 0) || (errno != 0) ) {
		freopen (NULL, "w", stdout);
	}

	errno = 0;
	res = fstat(STDERR_FILENO, &stat_buf);
	if ( (res < 0) || (errno != 0) ) {
		freopen (NULL, "w", stderr);
	}

	if ( argc <= 1 || argv == NULL ) {
		print_help("");
		return -1;
	}

	if ( argv[0] != NULL ) {
		progname = argv[0];
	} else {
		progname = PROGRAM_NAME;
	}

	/* Parsing the command line */
	optind = 0;
	while (1==1) {

		opt_char = getopt_long ( argc, argv, "Vhln:B:b:vf", opts, NULL );
		if ( opt_char == -1 ) break;

		if ( opt_char == (int)'?' || opt_char == (int)':' ) {
			print_help(progname);
			return -1;
		}

		if ( opt_char == (int)'h' || opt_help == 1 ) {
			print_help(progname);
			return 1;
		}

		if ( opt_char == (int)'V' || opt_version == 1 ) {
			printf ( ver_str, progname );
			return 1;
		}

		if ( opt_char == (int)'l' || opt_license == 1 ) {
			printf ( lic_str, progname );
			(void)puts ( author_str );
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
				print_help(progname);
				return -1;
			}
		}

		if ( opt_char == (int)'B' || opt_blksize == 1 ) {
			errno = 0;
			blocksize = strtoul ( optarg, NULL, 10 );
			if ( errno != 0 ) {
				print_help(progname);
				return -1;
			}
		}

		if ( opt_char == (int)'b' || opt_super == 1 ) {
			errno = 0;
			super_off = strtoul ( optarg, NULL, 10 );
			if ( errno != 0 ) {
				print_help(progname);
				return -1;
			}
		}
	}

	if ( optind >= argc || argv[optind] == NULL ) {
		print_help(progname);
		return -1;
	}

	if ( opt_nopart == 1 && opt_nounrm == 1 && opt_nowfs == 1 ) {

		printf ( "%s%s\n", progname, err_msg_nowork );
		return -1;
	}

	if ( opt_verbose == 1 ) {
		printf ( "%s: %s\n", progname, msg_signal );
		(void)fflush(stdout);
	}
	/*
	 * Setting signal handlers. We need to catch signals in order to close (and flush)
	 * an opened file system, to prevent unconsistencies.
	 */

#if defined __STDC__ || defined __STRICT_ANSI__
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
#if !defined __STDC__ && !defined __STRICT_ANSI__
	srandom(0xabadcafe*(unsigned long)time(NULL));
#else
	srand(0xabadcafe*(unsigned long)time(NULL));
#endif

	initialize_ext2_error_table();

	/*
	 * Unrecognised command line options are assumed to be devices, on which we are supposed to
	 * wipe the free space.
	 */
	while ( (optind < argc) && (sig_recvd == 0) ) {

		ret = 0;
		fsname = argv[optind];
		if ( (sig_recvd == 0) && (opt_verbose == 1) ) {
			printf ( msg_format, progname, msg_chkmnt, fsname );
			(void)fflush(stdout);
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
		if ( (sig_recvd == 0) && (opt_verbose == 1) ) {
			printf ( msg_format, progname, msg_openfs, fsname );
			(void)fflush(stdout);
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

		if ( (opt_force == 0) && ((fs->super->s_state & EXT2_ERROR_FS) != 0) ) {

			fprintf ( stderr, msg_format, progname, err_msg_fserr, fsname );
			(void)fflush(stderr);
			optind++;
			ret = -7;
			continue;
		}

		/* flush the file system before starting, if there seems to be need. */
		if ( (sig_recvd == 0) && (
			((fs->super->s_state & EXT2_VALID_FS) == 0) ||
			((fs->flags & EXT2_FLAG_DIRTY) != 0) ||
			(ext2fs_test_changed(fs) != 0)
			)
		   ) {

			if ( (sig_recvd == 0) && (opt_verbose == 1) ) {
				printf ( msg_format, progname, msg_flushfs, fsname );
				(void)fflush(stdout);
			}
			error = ext2fs_flush ( fs );
			if ( error != 0 ) {
				com_err ( progname, error, err_msg_format, err_msg, error,
					err_msg_flush, fsname );
			}
#if !defined __STDC__ && !defined __STRICT_ANSI__
			sync();
#endif
		}

	        if ( sig_recvd != 0 ) {
			error = ext2fs_close ( fs );
			if ( error != 0 ) {
				com_err ( progname, error, err_msg_format, err_msg, error,
					err_msg_close, fsname );
			}
	        	return -100;
	        }

		/* reserving space for one block */
		errno = 0;
		buf = (unsigned char *) malloc (EXT2_BLOCK_SIZE(fs->super)*sizeof(char));
		if ( (buf == NULL) || (errno != 0) ) {
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

	        /* removing undelete information */
		if ( (opt_nounrm == 0) && (sig_recvd == 0) ) {

			if ( opt_verbose == 1 ) {
				printf ( msg_format, progname, msg_wipeunrm, fsname );
				(void)fflush(stdout);
			}

			if ( wipe_unrm(fs, EXT2_ROOT_INO) != 0 ) ret = -13;
		}

		/* wiping partially occupied blocks */
		if ( (opt_nopart == 0) && (sig_recvd == 0) ) {

			if ( opt_verbose == 1 ) {
				printf ( msg_format, progname, msg_wipeused, fsname );
				(void)fflush(stdout);
			}

			res = wipe_part(fs);
			if ( res != 0 ) ret = res;
		}

		if ( (opt_nowfs == 0) && (sig_recvd == 0) ) {

			if ( (sig_recvd == 0) && (opt_verbose == 1) ) {
				printf ( msg_format, progname, msg_rdblbm, fsname );
				(void)fflush(stdout);
			}

			res = wipe_fs(fs);
			if ( res != 0 ) ret = res;
                }

		if ( opt_verbose == 1 ) {
			printf ( msg_format, progname, msg_closefs, fsname );
			(void)fflush(stdout);
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

#if !defined __STDC__ && !defined __STRICT_ANSI__
		sync();
#endif

	} /* while optind<argc && !signal */

	if ( sig_recvd != 0 ) return -100;
	else return ret;	/* return the last error value or zero */
}

