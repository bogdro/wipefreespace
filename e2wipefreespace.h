/*
 * A program for secure cleaning of free space on ext2/3 partitions.
 *	-- header file.
 *
 * Copyright (C) 2007 Bogdan Drozdowski, bogdandr (at) op.pl
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
 */

#ifndef WFS_HEADER
# define WFS_HEADER

# ifdef __GNUC__
#  define ATTR(x)	__attribute__(x)
# else
#  define ATTR(x)
# endif

# define 	ERR_MSG_FORMAT			"(%s %ld) %s '%s'"
# define 	MSG_FORMAT1			"%s: %s\n"
# define 	MSG_FORMAT2			"%s: %s: '%s'\n"

# define	NPAT	22

# define 	TMPSIZE	12

# define	WFS_SUCCESS		0
# define	WFS_NOTHING		1
# define	WFS_BAD_CMDLN		-1
# define	WFS_MNTCHK		-2
# define	WFS_MNTRW		-3
# define	WFS_OPENFS		-4
# define	WFS_BLBITMAPREAD	-5
# define	WFS_MALLOC		-6
# define	WFS_FSHASERROR		-7
# define	WFS_FSCLOSE		-8
# define	WFS_INOSCAN		-9
# define	WFS_BLKITER		-10
# define	WFS_INOREAD		-11
# define	WFS_DIRITER		-12
# define	WFS_SUID		-13
# define	WFS_FLUSHFS		-14
# define	WFS_SIGNAL		-100

# define 	_(String)		gettext (String)
# define	gettext_noop(String)	String

# define	CURR_EXT2FS		1

# ifndef WFS_EXT2
/* TODO: to be expanded, when other FS come into the program */
#  define WFS_EXT2
# endif

# ifdef 	WFS_EXT2
#  define WFS_BLOCKSIZE(E2FS) EXT2_BLOCK_SIZE(E2FS->super)
#  ifdef __STRICT_ANSI__
#   include <sys/types.h>		/* just for ext2fs.h */
#  endif
#  include <et/com_err.h>
#  include <ext2fs/ext2fs.h>

	/* TODO: to be expanded, when other FS come into the program */
# endif


typedef struct {

	unsigned long int passno;
# ifdef 	WFS_EXT2
	ext2_filsys fs;
# endif
	/* TODO: to be expanded, when other FS come into the program */

} wipedata;


typedef union {

# ifdef 	WFS_EXT2
	errcode_t	e2error;
# endif
	/* TODO: to be expanded, when other FS come into the program */

} error_type;

typedef union {

# ifdef 	WFS_EXT2
	ext2_filsys	e2fs;
# endif
	/* TODO: to be expanded, when other FS come into the program */

} fsid;

typedef union {

# ifdef 	WFS_EXT2
	ext2_ino_t	e2elem;
# endif
	/* TODO: to be expanded, when other FS come into the program */

} fselem;

typedef union {

	struct {
		int super_off;
		unsigned int blocksize;
	} e2fs;

	/* TODO: to be expanded, when other FS come into the program */

} fsdata;

/* ========================= Common to all ================================ */
extern void ATTR((nonnull)) 	show_error ( const error_type err, const char*const msg,
	const char*const extra );

extern void ATTR((nonnull)) 	show_msg ( const int type, const char*const msg,
	const char*const extra );

extern void ATTR((nonnull)) 	fill_buffer ( 	unsigned long int 		pat_no,
						unsigned char* const 		buffer,
						const size_t 			buflen );

extern volatile int sig_recvd;

extern const char *err_msg;
extern const char *err_msg_open;
extern const char *err_msg_flush;
extern const char *err_msg_close;
extern const char *err_msg_malloc;
extern const char *err_msg_checkmt;
extern const char *err_msg_mtrw;
extern const char *err_msg_rdblbm;
extern const char *err_msg_wrtblk;
extern const char *err_msg_rdblk;
extern const char *err_msg_rdino;
extern const char *err_msg_signal;
extern const char *err_msg_fserr;
extern const char *err_msg_openscan;
extern const char *err_msg_blkiter;
extern const char *err_msg_diriter;
extern const char *err_msg_nowork;
extern const char *err_msg_suid;

/* Messages displayed when verbose mode is on */
extern const char *msg_signal;
extern const char *msg_chkmnt;
extern const char *msg_openfs;
extern const char *msg_flushfs;
extern const char *msg_rdblbm;
extern const char *msg_wipefs;
extern const char *msg_pattern;
extern const char *msg_random;
extern const char *msg_wipeused;
extern const char *msg_wipeunrm;
extern const char *msg_closefs;

extern char *fsname;

extern error_type error;
extern unsigned char /*@only@*/ *buf;
extern unsigned long int npasses;


#include "wrappers.h"

#endif	/* WFS_HEADER */
