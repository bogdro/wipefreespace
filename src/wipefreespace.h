/*
 * A program for secure cleaning of free space on filesystems.
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

# define	NPAT	22

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
# define	WFS_BLKWR		-15
# define	WFS_ATTROPEN		-16
# define	WFS_NTFSRUNLIST		-17
# define	WFS_GETNAME		-18
# define	WFS_CTXERROR		-19
# define	WFS_SIGNAL		-100

# ifdef HAVE_GETTEXT
#  define 	_(String)		gettext (String)
# else
#  define 	_(String)		String
# endif

# define	gettext_noop(String)	String
# define	N_(String)		String

# define	CURR_EXT2FS		1
# define	CURR_NTFS		2

# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# elif !defined HAVE_SIZE_T
typedef unsigned size_t;
# endif

# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>		/* dev_t: just for ext2fs.h */
# elif defined HAVE_SYS_STAT_H
#  include <sys/stat.h>
# elif (!defined HAVE_DEV_T) && ((defined HAVE_EXT2FS_EXT2FS_H) || (defined HAVE_EXT2FS_H))
#  error No dev_t
# endif

# if (defined HAVE_EXT2FS_EXT2FS_H) && (defined HAVE_LIBEXT2FS)
#  include <ext2fs/ext2fs.h>
#  define	WFS_EXT2	1
# elif (defined HAVE_EXT2FS_H) && (defined HAVE_LIBEXT2FS)
#  include <ext2fs.h>
#  define	WFS_EXT2	1
# else
#  undef	WFS_EXT2
# endif

# if (defined HAVE_NTFS_VOLUME_H) && (defined HAVE_LIBNTFS)
#  include <ntfs/volume.h>
#  define	WFS_NTFS	1
# elif (defined HAVE_VOLUME_H) && (defined HAVE_LIBNTFS)
#  include <volume.h>
#  define	WFS_NTFS	1
# else
#  undef	WFS_NTFS
# endif

typedef struct {

	int whichfs;

	union {
		long int	gerror;
# ifdef 	WFS_EXT2
		errcode_t	e2error;
# endif
	/* TODO: to be expanded, when other FS come into the program */
	} errcode;

} error_type;

typedef union {

# ifdef 	WFS_EXT2
	ext2_filsys	e2fs;
# endif
# ifdef		WFS_NTFS
	ntfs_volume	ntfs;
# endif
	/* TODO: to be expanded, when other FS come into the program */

} wfs_fsid_t;

typedef struct {

	unsigned long int passno;
	wfs_fsid_t		filesys;

} wipedata;


typedef union {

# ifdef 	WFS_EXT2
	ext2_ino_t	e2elem;
# endif
# ifdef		WFS_NTFS
	ntfs_inode 	*ntfselem;
# endif
	/* TODO: to be expanded, when other FS come into the program */

} fselem_t;

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

extern char *fsname;

extern error_type error;
extern unsigned char /*@only@*/ *buf;
extern unsigned long int npasses;


#endif	/* WFS_HEADER */
