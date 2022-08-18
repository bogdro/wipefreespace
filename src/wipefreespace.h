/*
 * A program for secure cleaning of free space on filesystems.
 *	-- header file.
 *
 * Copyright (C) 2007-2008 Bogdan Drozdowski, bogdandr (at) op.pl
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
# define WFS_HEADER 1

# ifdef STAT_MACROS_BROKEN
#  if STAT_MACROS_BROKEN
#   error Stat macros broken. Change your C library.
#  endif
# endif

# undef WFS_ATTR
# ifdef __GNUC__
#  define WFS_ATTR(x)	__attribute__(x)
/*#  pragma GCC poison strcpy strcat*/
# else
#  define WFS_ATTR(x)
# endif

# undef		ERR_MSG_FORMATL
# define 	ERR_MSG_FORMATL			"(%s %ld) %s '%s', FS='%s'"
# undef		ERR_MSG_FORMAT
# define 	ERR_MSG_FORMAT			"(%s %d) %s '%s', FS='%s'"

# undef		NPAT
# undef		PASSES

# ifdef	LSR_WANT_RANDOM
	/* shred-like method: 22 patterns and 3 random passes */
#  define NPAT 22
#  define PASSES (NPAT+3)
# else
	/* Gutmann method: 5 more patterns and 9 random passes */
#  define NPAT (22+5)
#  define PASSES (NPAT+9)
# endif

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
	WFS_SEEKERR		= -24,
	WFS_SIGNAL		= -100
};

typedef enum errcode_enum errcode_enum;

enum CURR_FS
{
	CURR_NONE	= 0,
	CURR_EXT2FS,
	CURR_NTFS,
	CURR_XFS,
	CURR_REISERFS,
	CURR_REISER4
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

/* fix e2fsprogs inline functions - some linkers saw double definitions and
   failed with an error message */
# if (defined HAVE_LIBEXT2FS) && ((defined HAVE_EXT2FS_EXT2FS_H) || (defined HAVE_EXT2FS_H))
#  define _EXT2_USE_C_VERSIONS_	1
#  define NO_INLINE_FUNCS	1
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
# else
#  undef	WFS_XFS
# endif

# if (defined HAVE_REISERFS_LIB_H) && (defined HAVE_LIBCORE)	\
	&& (defined HAVE_UNISTD_H) && (defined HAVE_FORK)	\
	&& (							\
	      (defined HAVE_WAITPID)				\
	   || (defined HAVE_WAIT)				\
	)
#  ifdef HAVE_ASM_TYPES_H
#   include <asm/types.h>
#  else
typedef unsigned int __u32;
typedef unsigned short int __u16;
#  endif

#  include <reiserfs_lib.h>
#  define	WFS_REISER	1
# else
#  undef	WFS_REISER
# endif

/* fix conflict between libext2fs and reiser4. This gets #undef'd in the source files. */
# define blk_t reiser4_blk_t

# if (defined HAVE_REISER4_LIBREISER4_H) && (defined HAVE_LIBREISER4)	\
	&& (defined HAVE_LIBREISER4MISC) && (defined HAVE_LIBAAL)
#  include <reiser4/libreiser4.h>
#  define	WFS_REISER4	1
# else
#  undef	WFS_REISER4
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

struct error_type
{
	CURR_FS whichfs;

	union errcode {
		/* general error, if more specific type unavailable */
		errcode_enum	gerror;
# ifdef 	WFS_EXT2
		errcode_t	e2error;
# endif
# ifdef		WFS_REISER4
		errno_t		r4error;
# endif
	/* TODO: to be expanded, when other FS come into the program */
	} errcode;

};

typedef struct error_type error_type;

struct wfs_fsid_t
{
	const char * fsname;

# ifdef 	WFS_EXT2
	ext2_filsys	e2fs;
# endif
# ifdef		WFS_NTFS
	ntfs_volume	ntfs;
# endif
# ifdef		WFS_XFS
	struct wfs_xfs
	{
		/* size of 1 block is from sector size to 65536. Max is system page size */
		size_t wfs_xfs_blocksize;
		unsigned long long int wfs_xfs_agblocks;
		char * dev_name;
		char * mnt_point;
	} xxfs;
# endif
# ifdef		WFS_REISER
	reiserfs_filsys_t * rfs;
# endif
# ifdef		WFS_REISER4
	reiser4_fs_t * r4;
# endif

	/* TODO: to be expanded, when other FS come into the program */


};

typedef struct wfs_fsid_t wfs_fsid_t;

struct wipedata
{
	unsigned long int	passno;
	wfs_fsid_t		filesys;
};

typedef struct wipedata wipedata;

union fselem_t
{
# ifdef 	WFS_EXT2
	ext2_ino_t	e2elem;
# endif
# ifdef		WFS_NTFS
	ntfs_inode 	* ntfselem;
# endif
# ifdef		WFS_XFS
	/* Nothing. XFS has no undelete capability. */
# endif
# ifdef		WFS_REISER
	struct key	rfs_elem;
# endif
# ifdef		WFS_REISER4
	reiser4_node_t * r4node;
# endif

	/* TODO: to be expanded, when other FS come into the program */




# if (!defined WFS_EXT2) && (!defined WFS_NTFS) && (!defined WFS_REISER) && (!defined WFS_REISER4)
	char dummy;	/* Make this union non-empty */
# endif
};

typedef union fselem_t fselem_t;

union fsdata
{
	struct wipe_e2data
	{
		unsigned long int super_off;
		unsigned int blocksize;
	} e2fs;

	/* TODO: to be expanded, when other FS come into the program */

};

typedef union fsdata fsdata;

/* ========================= Common to all ================================ */
/* PARAMS is a macro used to wrap function prototypes, so that
        compilers that don't understand ANSI C prototypes still work,
        and ANSI C compilers can issue warnings about type mismatches. */
# undef PARAMS
# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
#  define PARAMS(protos) protos
# else
#  define PARAMS(protos) ()
# endif

extern void WFS_ATTR ((nonnull))
	show_error PARAMS((const error_type err, const char * const msg,
		const char * const extra, const wfs_fsid_t FS ));

extern void WFS_ATTR ((nonnull))
	show_msg PARAMS((const int type, const char * const msg,
		const char * const extra, const wfs_fsid_t FS ));

extern void WFS_ATTR ((nonnull))
	fill_buffer PARAMS((unsigned long int pat_no, unsigned char * const buffer,
		const size_t buflen, int * const selected, const wfs_fsid_t FS ));

extern unsigned long int npasses;

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
extern const char * const err_msg_fork;
extern const char * const err_msg_nocache;
extern const char * const err_msg_cacheon;

extern const char * const sig_unk;


#endif	/* WFS_HEADER */
