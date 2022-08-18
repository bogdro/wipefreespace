/*
 * A program for secure cleaning of free space on filesystems.
 *	-- header file.
 *
 * Copyright (C) 2007-2012 Bogdan Drozdowski, bogdandr (at) op.pl
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

# undef		WFS_WFS_ERR_MSG_FORMATL
# define 	WFS_WFS_ERR_MSG_FORMATL		"(%s %ld) %s '%s', FS='%s'"
# undef		WFS_ERR_MSG_FORMAT
# define 	WFS_ERR_MSG_FORMAT		"(%s %d) %s '%s', FS='%s'"

# undef		WFS_PASSES
# define	WFS_PASSES 35 /* default Gutmann */
# undef		WFS_NPAT
# define	WFS_NPAT 50 /* anything more than the maximum number of patterns in all wiping methods. */

# define	WFS_MNTBUFLEN 4096

enum wfs_errcode_t
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
	WFS_BLKRD		= -25,
	WFS_SIGNAL		= -100
};

typedef enum wfs_errcode_t wfs_errcode_t;

enum wfs_curr_fs_t
{
	CURR_NONE	= 0,
	CURR_EXT234FS,
	CURR_NTFS,
	CURR_XFS,
	CURR_REISERFS,
	CURR_REISER4,
	CURR_FATFS,
	CURR_MINIXFS,
	CURR_JFS,
	CURR_HFSP,
	CURR_OCFS
};

typedef enum wfs_curr_fs_t wfs_curr_fs_t;

# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# endif
# ifndef HAVE_SSIZE_T
typedef int ssize_t;
# endif
# ifndef HAVE_OFF64_T
#  ifdef HAVE_LONG_LONG
typedef long long int off64_t;
#  else
typedef long int off64_t;
#  endif
# endif

# if defined HAVE_SYS_STAT_H
#  include <sys/stat.h>
# elif (!defined HAVE_DEV_T) && ((defined HAVE_EXT2FS_EXT2FS_H) || (defined HAVE_EXT2FS_H))
/* can't proceed with ext2/3/4 without the 'dev_t' type */
#  undef HAVE_EXT2FS_EXT2FS_H
#  undef HAVE_EXT2FS_H
#  undef HAVE_LIBEXT2FS
# endif

/* ================ Beginning of filesystem includes ================ */

/* fix e2fsprogs inline functions - some linkers saw double definitions and
   failed with an error message */
# if (defined HAVE_LIBEXT2FS) && ((defined HAVE_EXT2FS_EXT2FS_H) || (defined HAVE_EXT2FS_H))
#  ifndef _EXT2_USE_C_VERSIONS_
#   define _EXT2_USE_C_VERSIONS_	1
#  endif
#  ifndef NO_INLINE_FUNCS
#   define NO_INLINE_FUNCS	1
#  endif
# endif

# if (defined HAVE_EXT2FS_EXT2FS_H) && (defined HAVE_LIBEXT2FS) && (defined HAVE_DEV_T)
#  include <ext2fs/ext2fs.h>
#  define	WFS_EXT234	1
# elif (defined HAVE_EXT2FS_H) && (defined HAVE_LIBEXT2FS) && (defined HAVE_DEV_T)
#  include <ext2fs.h>
#  define	WFS_EXT234	1
# else
#  undef	WFS_EXT234
# endif

/* fix symbol collision with ReiserFSv3 header files: */
# define ROUND_UP NTFS_ROUND_UP

# if ((defined HAVE_NTFS_NTFS_VOLUME_H) || (defined HAVE_NTFS_3G_NTFS_VOLUME_H)) \
	&& ((defined HAVE_LIBNTFS) || (defined HAVE_LIBNTFS_3G))
#  ifdef HAVE_NTFS_NTFS_VOLUME_H
#   include <ntfs/ntfs_volume.h>
#   include <ntfs/ntfs_version.h>
#   define	WFS_NTFS	1
#  else
#   include <ntfs-3g/ntfs_volume.h>
/*#   include <ntfs-3g/ntfs_version.h> missing */
#   define	WFS_NTFS	1
#   if (defined HAVE_MINIX_FS_H) && (defined HAVE_LIBMINIXFS)
/* fix compatibility with MinixFS: */
#    define u8 u8_minix
#    define u16 u16_minix
#    define u32 u32_minix
#   endif
#  endif
# else
#  if ((defined HAVE_NTFS_VOLUME_H) || (defined HAVE_NTFS_3G_VOLUME_H)) \
	&& ((defined HAVE_LIBNTFS) || (defined HAVE_LIBNTFS_3G))
#   ifdef HAVE_NTFS_VOLUME_H
#    include <ntfs/volume.h>
#    include <ntfs/version.h>
#    define	WFS_NTFS	1
#   else
#    include <ntfs-3g/volume.h>
/*#    include <ntfs-3g/version.h> missing */
#    define	WFS_NTFS	1
#    if (defined HAVE_MINIX_FS_H) && (defined HAVE_LIBMINIXFS)
/* fix compatibility with MinixFS: */
#     define u8 u8_minix
#     define u16 u16_minix
#     define u32 u32_minix
#    endif
#   endif
#  else
#   if (defined HAVE_VOLUME_H) && ((defined HAVE_LIBNTFS) || (defined HAVE_LIBNTFS_3G))
#    include <volume.h>
#    ifndef HAVE_LIBNTFS_3G
#     include <version.h>
#    else
#     if (defined HAVE_MINIX_FS_H) && (defined HAVE_LIBMINIXFS)
/* fix compatibility with MinixFS: */
#      define u8 u8_minix
#      define u16 u16_minix
#      define u32 u32_minix
#     endif
#    endif
#    define	WFS_NTFS	1
#   else
#    undef	WFS_NTFS
#   endif
#  endif
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
	&& (defined HAVE_FORK) && (defined HAVE_UNISTD_H)	\
	&& ((defined HAVE_WAITPID) || (defined HAVE_WAIT))

#  ifdef HAVE_ASM_TYPES_H
#   include <asm/types.h>
#  else
typedef unsigned int __u32;
typedef unsigned short int __u16;
#  endif

/* fix symbol collision with NTFS header files: */
/*# define ROUND_UP REISER_ROUND_UP*/
# undef ROUND_UP

/* Avoid some Reiser3 header files' name conflicts:
 reiserfs_lib.h uses the same name for a function and a variable,
 so let's redefine one to avoid name conflicts */
#  define div reiser_div
#  define index reiser_index
#  define key_format(x) key_format0 (x)
#  include <stdio.h>	/* FILE for reiserfs_fs.h */
#  include <reiserfs_lib.h>
#  undef div
#  undef index
#  undef key_format
#  define	WFS_REISER	1
# else
#  undef	WFS_REISER
# endif

# if (defined HAVE_REISER4_LIBREISER4_H) && (defined HAVE_LIBREISER4)	\
	&& (defined HAVE_LIBREISER4MISC) && (defined HAVE_LIBAAL)
#  undef get_unaligned
#  undef put_unaligned
/* Avoid some Reiser4 header files' name conflicts: */
#  define div reiser4_div
#  define index reiser4_index

/* fix conflict between libext2fs and reiser4. This gets #undef'd in the source files. */
#  define blk_t reiser4_blk_t
/* we're not using these headers, so let's pretend they're already included,
   to avoid warnings caused by them. */
#  define AAL_EXCEPTION_H 1
#  define AAL_DEBUG_H 1
#  define AAL_BITOPS_H 1
#  define REISER4_FAKE_H 1

#  include <reiser4/libreiser4.h>
#  define	WFS_REISER4	1
# else
#  undef	WFS_REISER4
# endif

# undef div
# undef index

# if (defined HAVE_TFFS_H) && (defined HAVE_LIBTFFS)
#  include <tffs.h>
#  define	WFS_FATFS	1
# else
#  undef	WFS_FATFS
# endif

# if (defined HAVE_MINIX_FS_H) && (defined HAVE_LIBMINIXFS)
#  include <stdio.h>	/* FILE for minix_fs.h */
#  undef BLOCK_SIZE	/* fix conflict with NTFS. Unused in NTFS anyway. */
#  include <minix_fs.h>
#  define	WFS_MINIXFS	1
# else
#  undef	WFS_MINIXFS
# endif

# if (defined HAVE_JFS_JFS_SUPERBLOCK_H) && (defined HAVE_LIBFS)
#  include <stdio.h>	/* FILE */
#  ifndef HAVE_SYS_BYTEORDER_H
#   define WFS_ADDED_HAVE_SYS_BYTEORDER_H
#   define HAVE_SYS_BYTEORDER_H 0
#  endif
#  ifndef HAVE_MACHINE_ENDIAN_H
#   define WFS_ADDED_HAVE_MACHINE_ENDIAN_H
#   define HAVE_MACHINE_ENDIAN_H 0
#  endif
#  ifndef HAVE_ENDIAN_H
#   define WFS_ADDED_HAVE_ENDIAN_H
#   define HAVE_ENDIAN_H 0
#  endif
#  include <jfs/jfs_types.h>
#  include <jfs/jfs_superblock.h>
#  ifdef WFS_ADDED_HAVE_SYS_BYTEORDER_H
#   undef HAVE_SYS_BYTEORDER_H
#  endif
#  ifdef WFS_ADDED_HAVE_MACHINE_ENDIAN_H
#   undef HAVE_MACHINE_ENDIAN_H
#  endif
#  ifdef WFS_ADDED_HAVE_ENDIAN_H
#   undef HAVE_ENDIAN_H
#  endif
#  define	WFS_JFS		1
# else
#  if (defined HAVE_JFS_SUPERBLOCK_H) && (defined HAVE_LIBFS)
#   include <stdio.h>	/* FILE  */
#   ifndef HAVE_SYS_BYTEORDER_H
#    define WFS_ADDED_
#    define HAVE_SYS_BYTEORDER_H 0
#   endif
#   ifndef HAVE_MACHINE_ENDIAN_H
#    define WFS_ADDED_
#    define HAVE_MACHINE_ENDIAN_H 0
#   endif
#   ifndef HAVE_ENDIAN_H
#    define WFS_ADDED_HAVE_ENDIAN_H
#    define HAVE_ENDIAN_H 0
#   endif
#   include <jfs_types.h>
#   include <jfs_superblock.h>
#   ifdef WFS_ADDED_HAVE_SYS_BYTEORDER_H
#    undef HAVE_SYS_BYTEORDER_H
#   endif
#   ifdef WFS_ADDED_HAVE_MACHINE_ENDIAN_H
#    undef HAVE_MACHINE_ENDIAN_H
#   endif
#   ifdef WFS_ADDED_HAVE_ENDIAN_H
#    undef HAVE_ENDIAN_H
#   endif
#   define	WFS_JFS		1
#  else
#   undef	WFS_JFS
#  endif
# endif

# if (defined HAVE_HFSPLUS_LIBHFSP_H) && (defined HAVE_LIBHFSP)
#  include <hfsplus/libhfsp.h>
#  include <hfsplus/record.h>
#  define	WFS_HFSP	1
# else
#  if (defined HAVE_LIBHFSP_H) && (defined HAVE_LIBHFSP)
#   include <libhfsp.h>
#   include <record.h>
#   define	WFS_HFSP	1
#  else
#   undef	WFS_HFSP
#  endif
# endif

# if (defined HAVE_OCFS2_OCFS2_H) && (defined HAVE_LIBOCFS2)
/* fix incompatibility with NTFS: */
#  define list_head ocfs_list_head
#  define __list_add __ocfs_list_add
#  define list_add ocfs_list_add
#  define list_add_tail ocfs_list_add_tail
#  define __list_del __ocfs_list_del
#  define list_del ocfs_list_del
#  define list_empty ocfs_list_empty
#  define list_splice ocfs_list_splice
/*
#  define LIST_HEAD_INIT OCFS_LIST_HEAD_INIT
#  define LIST_HEAD OCFS_LIST_HEAD
#  define INIT_LIST_HEAD OCFS_INIT_LIST_HEAD
#  define list_entry ocfs_list_entry
#  define list_for_each ocfs_list_for_each
#  define list_for_each_safe ocfs_list_for_each_safe
*/
/* fix incomaptibility with ext2_fs.h: */
#  undef i_reserved2
/* fix incomaptibility with ext2_io.h: */
#  define io_channel ocfs_io_channel
#  include <ocfs2/ocfs2.h>
#  define	WFS_OCFS	1
# else
#  if (defined HAVE_OCFS2_H) && (defined HAVE_LIBOCFS2)
/* fix incompatibility with NTFS: */
#   define list_head ocfs_list_head
#   define __list_add __ocfs_list_add
#   define list_add ocfs_list_add
#   define list_add_tail ocfs_list_add_tail
#   define __list_del __ocfs_list_del
#   define list_del ocfs_list_del
#   define list_empty ocfs_list_empty
#   define list_splice ocfs_list_splice
/*
#   define LIST_HEAD_INIT OCFS_LIST_HEAD_INIT
#   define LIST_HEAD OCFS_LIST_HEAD
#   define INIT_LIST_HEAD OCFS_INIT_LIST_HEAD
#   define list_entry ocfs_list_entry
#   define list_for_each ocfs_list_for_each
#   define list_for_each_safe ocfs_list_for_each_safe
*/
/* fix incomaptibility with ext2_fs.h: */
#   undef i_reserved2
/* fix incomaptibility with ext2_io.h: */
#   define io_channel ocfs_io_channel
#   include <ocfs2.h>
#   define	WFS_OCFS	1
#  else
#   undef	WFS_OCFS
#  endif
# endif

# if (defined HAVE_LIBHIDEIP) && (defined HAVE_LIBHIDEIP_H)
#  define WFS_HAVE_LIBHIDEIP	1
# else
#  undef WFS_HAVE_LIBHIDEIP
# endif

# if (defined HAVE_LIBNETBLOCK) && (defined HAVE_LIBNETBLOCK_H)
#  define WFS_HAVE_LIBNETBLOCK	1
# else
#  undef WFS_HAVE_LIBNETBLOCK
# endif

/* ================ End of filesystem includes ================ */

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

struct wfs_error_type_t
{
	wfs_curr_fs_t whichfs;

	union wfs_errcode_union
	{
		/* general error, if more specific type unavailable */
		wfs_errcode_t	gerror;
# if (defined WFS_EXT234) || (defined WFS_OCFS)
		errcode_t	e2error;
# endif
# ifdef		WFS_REISER4
		errno_t		r4error;
# endif
	/* TODO: to be expanded, when other FS come into the program */
	} errcode;
};

typedef struct wfs_error_type_t wfs_error_type_t;

struct wfs_fsid_t
{
	const char * fsname;	/* filesystem name, for informational purposes */
	unsigned long int npasses;
	int zero_pass;	/* whether to perform an additional wiping with zeros on this filesystem */

# ifdef 	WFS_EXT234
	ext2_filsys e2fs;
# endif
# ifdef		WFS_NTFS
	ntfs_volume * ntfs;
# endif
# ifdef		WFS_XFS
	struct wfs_xfs
	{
		/* size of 1 block is from sector size to 65536. Max is system page size */
		size_t wfs_xfs_blocksize;
		unsigned long long int wfs_xfs_agblocks;
		char * dev_name;
		char * mnt_point;
		unsigned long long int inodes_used;
		unsigned long long int free_blocks;
	} xxfs;
# endif
# ifdef		WFS_REISER
	reiserfs_filsys_t * rfs;
# endif
# ifdef		WFS_REISER4
	reiser4_fs_t * r4;
# endif
# ifdef		WFS_FATFS
	tffs_handle_t fat;
# endif
# ifdef		WFS_MINIXFS
	struct minix_fs_dat * minix;
# endif
# ifdef		WFS_JFS
	struct wfs_jfs
	{
		FILE * fs;
		struct superblock super;
	} jfs;
# endif
# ifdef		WFS_HFSP
	struct volume	hfsp_volume;
# endif
# ifdef		WFS_OCFS
	ocfs2_filesys * ocfs2;
# endif

	/* TODO: to be expanded, when other FS come into the program */
};

typedef struct wfs_fsid_t wfs_fsid_t;

/* Additional data that may be useful when wiping a filesystem, for functions that
   have a strict interface that disallows passing these elements separately. */
struct wfs_wipedata_t
{
	unsigned long int	passno;		/* current pass' number */
	wfs_fsid_t		filesys;	/* filesystem being wiped */
	int			total_fs;	/* total number of filesystems, for ioctl() */
	int			ret_val;	/* return value, for threads */
	unsigned char *		buf;		/* current buffer */
	int			isjournal;	/* is the journal being wiped currently */
};

typedef struct wfs_wipedata_t wfs_wipedata_t;

union wfs_fselem_t
{
# ifdef 	WFS_EXT234
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
	reiser4_node_t	* r4node;
# endif
# ifdef		WFS_FATFS
	tdir_handle_t	fatdir;
# endif
# ifdef		WFS_MINIXFS
	int 		minix_ino;
# endif
# ifdef		WFS_JFS
	/* Nothing. Undelete on JFS not supported. */
# endif
# ifdef		WFS_HFSP
	record		hfsp_dirent;
# endif
# ifdef		WFS_OCFS
	struct ocfs2_dir_entry * ocfs2dir;
# endif

	/* TODO: to be expanded, when other FS come into the program */




# if (!defined WFS_EXT234) && (!defined WFS_NTFS) && (!defined WFS_REISER) \
	&& (!defined WFS_REISER4) && (!defined WFS_FATFS) && (!defined WFS_MINIXFS) \
	&& (!defined WFS_HFSP) && (!defined WFS_OCFS)
	char dummy;	/* Make this union non-empty */
# endif
};

typedef union wfs_fselem_t wfs_fselem_t;

/* Additional data that may be useful when opening a filesystem */
union wfs_fsdata_t
{
	struct wfs_e2data
	{
		unsigned long int super_off;
		unsigned int blocksize;
	} e2fs;

	/* TODO: to be expanded, when other FS come into the program */

};

typedef union wfs_fsdata_t wfs_fsdata_t;

/* ========================= Common to all ================================ */
/* autoconf: WFS_PARAMS is a macro used to wrap function prototypes, so that
        compilers that don't understand ANSI C prototypes still work,
        and ANSI C compilers can issue warnings about type mismatches. */
# undef WFS_PARAMS
# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
#  define WFS_PARAMS(protos) protos
#  define WFS_ANSIC
# else
#  define WFS_PARAMS(protos) ()
#  undef WFS_ANSIC
# endif

extern void WFS_ATTR ((nonnull))
	show_error WFS_PARAMS((const wfs_error_type_t err, const char * const msg,
		const char * const extra, const wfs_fsid_t FS ));

extern void WFS_ATTR ((nonnull))
	show_msg WFS_PARAMS((const int type, const char * const msg,
		const char * const extra, const wfs_fsid_t FS ));

# define WFS_PROGRESS_WFS	0
# define WFS_PROGRESS_PART	1
# define WFS_PROGRESS_UNRM	2
extern WFS_ATTR ((nonnull)) void
	show_progress WFS_PARAMS((const unsigned int type, const unsigned int percent,
		unsigned int * const prev_percent));

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
