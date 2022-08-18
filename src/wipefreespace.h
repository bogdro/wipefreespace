/*
 * A program for secure cleaning of free space on filesystems.
 *	-- header file.
 *
 * Copyright (C) 2007 Bogdan Drozdowski, bogdandr (at) op.pl
 * License: GNU General Public License, v3+
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
 */

#ifndef WFS_HEADER
# define WFS_HEADER 1

# undef WFS_ATTR
# ifdef __GNUC__
#  define WFS_ATTR(x)	__attribute__(x)
/*#  pragma GCC poison strcpy strcat*/
# else
#  define WFS_ATTR(x)
# endif

# define 	ERR_MSG_FORMATL			"(%s %ld) %s '%s'"
# define 	ERR_MSG_FORMAT			"(%s %d) %s '%s'"

enum patterns
{
	NPAT = 22
};

enum errcode_enum
{
	WFS_SUCCESS		= 0,
	WFS_NOTHING		= 1,
	WFS_BAD_CMDLN		= -1,
	WFS_MNTCHK		= -2,
	WFS_MNTRW		= -3,
	WFS_OPENFS		= -4,
	WFS_BLBITMAPREAD	= -5,
	WFS_MALLOC		= -6,
	WFS_FSHASERROR		= -7,
	WFS_FSCLOSE		= -8,
	WFS_INOSCAN		= -9,
	WFS_BLKITER		= -10,
	WFS_INOREAD		= -11,
	WFS_DIRITER		= -12,
	WFS_SUID		= -13,
	WFS_FLUSHFS		= -14,
	WFS_BLKWR		= -15,
	WFS_ATTROPEN		= -16,
	WFS_NTFSRUNLIST		= -17,
	WFS_GETNAME		= -18,
	WFS_CTXERROR		= -19,
	WFS_BADPARAM		= -20,
	WFS_PIPEERR		= -21,
	WFS_FORKERR		= -22,
	WFS_EXECERR		= -23,
	WFS_SIGNAL		= -100
};

typedef enum errcode_enum errcode_enum;

enum CURR_FS
{
	CURR_NONE	= 0,
	CURR_EXT2FS,
	CURR_NTFS,
	CURR_XFS
};

typedef enum CURR_FS CURR_FS;

# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# endif
# ifndef HAVE_SSIZE_T
typedef int ssize_t;
# endif
# ifndef HAVE_OFF64_T
#  ifdef HAVE_LONG_LONG
typedef long long off64_t;
#  else
typedef long off64_t;
#  endif
# endif

# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
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

# if (defined HAVE_NTFS_NTFS_VOLUME_H) && (defined HAVE_LIBNTFS)
#  include <ntfs/ntfs_volume.h>
#  include <ntfs/ntfs_version.h>
#  define	WFS_NTFS	1
# elif (defined HAVE_NTFS_VOLUME_H) && (defined HAVE_LIBNTFS)
#  include <ntfs/volume.h>
#  include <ntfs/version.h>
#  define	WFS_NTFS	1
# elif (defined HAVE_VOLUME_H) && (defined HAVE_LIBNTFS)
#  include <volume.h>
#  include <version.h>
#  define	WFS_NTFS	1
# else
#  undef	WFS_NTFS
# endif

# if (defined HAVE_LONG_LONG) && (defined HAVE_UNISTD_H)	\
	&& (defined HAVE_FORK) && (defined HAVE_EXECVP)		\
	&& (defined HAVE_DUP2) && (defined HAVE_PIPE)		\
	&& (defined HAVE_CLOSE) && (defined HAVE_FCNTL_H)	\
	&& (							\
	      (defined HAVE_WAITPID)				\
	   || (defined HAVE_WAIT)				\
	   || (defined HAVE_KILL)				\
	)

#  define	WFS_XFS		1
# endif

# ifdef HAVE_GETTEXT
#  ifndef _
#   define 	_(String)		gettext (String)
#  endif
# else
#  define 	_(String)		String
# endif

# define	gettext_noop(String)	String
# define	N_(String)		String

# ifdef HAVE_SIGNAL_H
#  include <signal.h>
# endif
# ifndef HAVE_SIG_ATOMIC_T
typedef int sig_atomic_t;
# endif

struct error_type {

	CURR_FS whichfs;

	union {
		/* general error, if more specific type unavailable */
		errcode_enum	gerror;
# ifdef 	WFS_EXT2
		errcode_t	e2error;
# endif
	/* TODO: to be expanded, when other FS come into the program */
	} errcode;

};

typedef struct error_type error_type;

union wfs_fsid_t {

# ifdef 	WFS_EXT2
	ext2_filsys	e2fs;
# endif
# ifdef		WFS_NTFS
	ntfs_volume	ntfs;
# endif
# ifdef		WFS_XFS
	struct wfs_xfs {
		unsigned long wfs_xfs_blocksize;
		unsigned long long wfs_xfs_agblocks;
		char * dev_name;
		char * mnt_point;
	} xxfs;
# endif
	/* TODO: to be expanded, when other FS come into the program */

};

typedef union wfs_fsid_t wfs_fsid_t;

struct wipedata {

	unsigned long int	passno;
	wfs_fsid_t		filesys;
};

typedef struct wipedata wipedata;

union fselem_t {

# ifdef 	WFS_EXT2
	ext2_ino_t	e2elem;
# endif
# ifdef		WFS_NTFS
	ntfs_inode 	*ntfselem;
# endif
# ifdef		WFS_XFS
	/* Nothing. XFS has no undelete capability. */
# endif
	/* TODO: to be expanded, when other FS come into the program */

};

typedef union fselem_t fselem_t;

union fsdata {

	struct wipe_e2data {
		int super_off;
		unsigned int blocksize;
	} e2fs;

	/* TODO: to be expanded, when other FS come into the program */

};

typedef union fsdata fsdata;

/* ========================= Common to all ================================ */
extern void WFS_ATTR ((nonnull)) 	show_error ( const error_type err, const char*const msg,
							const char*const extra );

extern void WFS_ATTR ((nonnull)) 	show_msg ( const int type, const char*const msg,
							const char*const extra );

extern void WFS_ATTR ((nonnull)) 	fill_buffer ( 	unsigned long int 		pat_no,
							unsigned char* const 		buffer,
							const size_t 			buflen,
							int * const			selected );

extern const char * const err_msg;
extern const char * const err_msg_open;
extern const char * const err_msg_flush;
extern const char * const err_msg_close;
extern const char * const err_msg_malloc;
extern const char * const err_msg_checkmt;
extern const char * const err_msg_mtrw;
extern const char * const err_msg_rdblbm;
extern const char * const err_msg_wrtblk;
extern const char * const err_msg_rdblk;
extern const char * const err_msg_rdino;
extern const char * const err_msg_signal;
extern const char * const err_msg_fserr;
extern const char * const err_msg_openscan;
extern const char * const err_msg_blkiter;
extern const char * const err_msg_diriter;
extern const char * const err_msg_nowork;
extern const char * const err_msg_suid;

extern const char * fsname;
extern const char * const sig_unk;

extern unsigned long int npasses;


#endif	/* WFS_HEADER */
