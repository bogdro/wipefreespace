/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- header file.
 *
 * Copyright (C) 2007-2024 Bogdan Drozdowski, bogdro (at) users.sourceforge.net
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef WFS_HEADER
# define WFS_HEADER 1

# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# endif
# ifndef HAVE_OFF64_T
#  if (defined HAVE_LONG_LONG) || (defined HAVE_LONG_LONG_INT)
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

# ifdef HAVE_SIGNAL_H
#  include <signal.h>
# endif
# ifndef HAVE_SIG_ATOMIC_T
typedef int sig_atomic_t;
# endif

# ifdef STAT_MACROS_BROKEN
#  if STAT_MACROS_BROKEN
#   error Stat macros broken. Change your C library.
/* make a syntax error, because not all compilers treat #error as an error */
Stat macros broken. Change your C library.
#  endif
# endif

# ifdef WFS_ATTR
#  undef WFS_ATTR
# endif

# ifdef __GNUC__
#  define WFS_ATTR(x)	__attribute__(x)
/*#  pragma GCC poison strcpy strcat*/
# endif

# ifndef GCC_WARN_UNUSED_RESULT
/*
 if the compiler doesn't support this, define this to an empty value,
 so that everything compiles (just in case)
 */
#  define GCC_WARN_UNUSED_RESULT /*WFS_ATTR((warn_unused_result))*/
# endif

# ifdef WFS_ERR_MSG_FORMATL
#  undef WFS_ERR_MSG_FORMATL
# endif

# define 	WFS_ERR_MSG_FORMATL		"(%s %ld) %s '%s', FS='%s'"

# ifdef WFS_ERR_MSG_FORMAT
#  undef WFS_ERR_MSG_FORMAT
# endif

# define 	WFS_ERR_MSG_FORMAT		"(%s %d) %s '%s', FS='%s'"

# ifdef WFS_PASSES
#  undef WFS_PASSES
# endif

# define	WFS_PASSES 35 /* default Gutmann */

# ifdef WFS_NPAT
#  undef WFS_NPAT
# endif

# define	WFS_NPAT 50 /* anything more than the maximum number of patterns in all wiping methods. */

# ifdef WFS_MNTBUFLEN
#  undef WFS_MNTBUFLEN
# endif

# define	WFS_MNTBUFLEN 4096

# ifdef WFS_IS_SYNC_NEEDED
#  undef WFS_IS_SYNC_NEEDED
# endif

# define	WFS_IS_SYNC_NEEDED(fs) ( ((((fs).npasses > 1) || ((fs).zero_pass != 0)) && ((fs).wipe_mode != WFS_WIPE_MODE_PATTERN)) && (sig_recvd == 0))

# ifdef WFS_IS_SYNC_NEEDED_PAT
#  undef WFS_IS_SYNC_NEEDED_PAT
# endif

# define	WFS_IS_SYNC_NEEDED_PAT(fs) ( (((fs).npasses > 1) && ((fs).wipe_mode == WFS_WIPE_MODE_PATTERN)) && (sig_recvd == 0))

# ifdef WFS_IS_NAME_CURRENT_DIR
#  undef WFS_IS_NAME_CURRENT_DIR
# endif

# define	WFS_IS_NAME_CURRENT_DIR(x) (((x)[0]) == '.' && ((x)[1]) == '\0')

# ifdef WFS_IS_NAME_PARENT_DIR
#  undef WFS_IS_NAME_PARENT_DIR
# endif

# define	WFS_IS_NAME_PARENT_DIR(x) (((x)[0]) == '.' && ((x)[1]) == '.' && ((x)[2]) == '\0')

enum wfs_errcode
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
	WFS_IOCTL		= -26,
	WFS_SIGNAL		= -100
};

typedef enum wfs_errcode wfs_errcode_t;

enum wfs_curr_fs
{
	WFS_CURR_FS_NONE	= 0,
	WFS_CURR_FS_EXT234FS,
	WFS_CURR_FS_NTFS,
	WFS_CURR_FS_XFS,
	WFS_CURR_FS_REISERFS,
	WFS_CURR_FS_REISER4,
	WFS_CURR_FS_FATFS,
	WFS_CURR_FS_MINIXFS,
	WFS_CURR_FS_JFS,
	WFS_CURR_FS_HFSP,
	WFS_CURR_FS_OCFS
};

typedef enum wfs_curr_fs wfs_curr_fs_t;

enum wfs_wipe_mode
{
	WFS_WIPE_MODE_PATTERN	= 0,
	WFS_WIPE_MODE_BLOCK
};

typedef enum wfs_wipe_mode wfs_wipe_mode_t;

/* ================ Beginning of filesystem includes ================ */

# ifdef WFS_EXT234
#  undef WFS_EXT234
# endif

# if (defined HAVE_EXT2FS_EXT2FS_H) && (defined HAVE_LIBEXT2FS) && (defined HAVE_DEV_T)
#  define	WFS_EXT234	1
# elif (defined HAVE_EXT2FS_H) && (defined HAVE_LIBEXT2FS) && (defined HAVE_DEV_T)
#  define	WFS_EXT234	1
# endif

# ifdef WFS_NTFS
#  undef WFS_NTFS
# endif

# if ((defined HAVE_NTFS_NTFS_VOLUME_H) || (defined HAVE_NTFS_3G_NTFS_VOLUME_H)) \
	&& ((defined HAVE_LIBNTFS) || (defined HAVE_LIBNTFS_3G))
#  define	WFS_NTFS	1
# else
#  if ((defined HAVE_NTFS_VOLUME_H) || (defined HAVE_NTFS_3G_VOLUME_H)) \
	&& ((defined HAVE_LIBNTFS) || (defined HAVE_LIBNTFS_3G))
#   define	WFS_NTFS	1
#  endif
# endif

# ifdef WFS_XFS
#  undef WFS_XFS
# endif

# if ((defined HAVE_LONG_LONG) || (defined HAVE_LONG_LONG_INT))	\
	&& (defined HAVE_UNISTD_H)				\
	&& (defined HAVE_WORKING_FORK /* HAVE_FORK */) && (	\
		(defined HAVE_EXECVP)				\
		|| (defined HAVE_EXECVPE)			\
	)							\
	&& (defined HAVE_DUP2) && (defined HAVE_PIPE)		\
	&& (defined HAVE_CLOSE) && (defined HAVE_FCNTL_H)	\
	&& (							\
	      (defined HAVE_WAITPID)				\
	   || (defined HAVE_WAIT)				\
	   || (defined HAVE_KILL)				\
	)							\
	&& (defined HAVE_XFS_DB)
#  define	WFS_XFS		1
# endif

# ifdef WFS_REISER
#  undef WFS_REISER
# endif

# if (defined HAVE_REISERFS_LIB_H) && (defined HAVE_LIBCORE)	\
	&& (defined HAVE_WORKING_FORK /* HAVE_FORK */)		\
	&& (defined HAVE_UNISTD_H)	\
	&& ((defined HAVE_WAITPID) || (defined HAVE_WAIT))

#  ifdef HAVE_ASM_TYPES_H
#   include <asm/types.h>
#  else
typedef unsigned int __u32;
typedef unsigned short int __u16;
#  endif

#  define	WFS_REISER	1
# endif

# ifdef WFS_REISER4
#  undef WFS_REISER4
# endif

# if (defined HAVE_REISER4_LIBREISER4_H) && (defined HAVE_LIBREISER4)	\
	/*&& (defined HAVE_LIBREISER4MISC)*/ && (defined HAVE_LIBAAL)
#  define	WFS_REISER4	1
# endif

# ifdef div
#  undef div
# endif

# ifdef index
#  undef index
# endif

# ifdef WFS_FATFS
#  undef WFS_FATFS
# endif

# if (defined HAVE_TFFS_H) && (defined HAVE_LIBTFFS)
#  define	WFS_FATFS	1
# endif

# ifdef WFS_MINIXFS
#  undef WFS_MINIXFS
# endif

# if (defined HAVE_MINIX_FS_H) && (defined HAVE_LIBMINIXFS)
#  define	WFS_MINIXFS	1
# endif

# ifdef WFS_JFS
#  undef WFS_JFS
# endif

# if (defined HAVE_JFS_JFS_SUPERBLOCK_H) && (defined HAVE_LIBFS)
#  define	WFS_JFS		1
# else
#  if (defined HAVE_JFS_SUPERBLOCK_H) && (defined HAVE_LIBFS)
#   define	WFS_JFS		1
#  endif
# endif

# ifdef WFS_HFSP
#  undef WFS_HFSP
# endif

# if (defined HAVE_HFSPLUS_LIBHFSP_H) && (defined HAVE_LIBHFSP)
#  define	WFS_HFSP	1
# else
#  if (defined HAVE_LIBHFSP_H) && (defined HAVE_LIBHFSP)
#   define	WFS_HFSP	1
#  endif
# endif

# ifdef WFS_OCFS
#  undef WFS_OCFS
# endif

# if (defined HAVE_OCFS2_OCFS2_H) && (defined HAVE_LIBOCFS2)
#  define	WFS_OCFS	1
# else
#  if (defined HAVE_OCFS2_H) && (defined HAVE_LIBOCFS2)
#   define	WFS_OCFS	1
#  endif
# endif

# ifdef WFS_HAVE_LIBHIDEIP
#  undef WFS_HAVE_LIBHIDEIP
# endif

# if (defined HAVE_LIBHIDEIP) && (defined HAVE_LIBHIDEIP_H)
#  define WFS_HAVE_LIBHIDEIP	1
# endif

# ifdef WFS_HAVE_LIBNETBLOCK
#  undef WFS_HAVE_LIBNETBLOCK
# endif

# if (defined HAVE_LIBNETBLOCK) && (defined HAVE_LIBNETBLOCK_H)
#  define WFS_HAVE_LIBNETBLOCK	1
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

struct wfs_fsid
{
		/* filesystem name, for informational purposes: */
	const char * fsname;
		/* the number of wiping passes: */
	unsigned long int npasses;
		/* whether to perform an additional wiping with
		zeros on this filesystem: */
	int zero_pass;
		/* the filesystem backend: */
	void * fs_backend;
		/* holder for filesystem errors: */
	void * fs_error;
		/* the type of the current filesystem: */
	wfs_curr_fs_t whichfs;
		/* whether not to wipe all-zero blocks on
		on this filesystem: */
	int no_wipe_zero_blocks;
		/* whether not to use the dedicated wiping tool: */
	int use_dedicated;
		/* the wiping mode - block-order or pattern-order: */
	wfs_wipe_mode_t wipe_mode;
};

typedef struct wfs_fsid wfs_fsid_t;

/* Additional data that may be useful when wiping a filesystem, for functions that
   have a strict interface that disallows passing these elements separately. */
struct wfs_wipedata
{
	unsigned long int	passno;		/* current pass' number */
	wfs_fsid_t		filesys;	/* filesystem being wiped */
	int			total_fs;	/* total number of filesystems, for ioctl() */
	int			ret_val;	/* return value, for threads */
	unsigned char *		buf;		/* current buffer */
	int			isjournal;	/* is the journal being wiped currently */
	int			is_zero_pass;	/* is the current pass the zero pass */
};

typedef struct wfs_wipedata wfs_wipedata_t;

/* Additional data that may be useful when opening a filesystem */
union wfs_fsdata
{
	struct wfs_e2data
	{
		unsigned long int super_off;
		unsigned int blocksize;
	} e2fs;

	/* to be expanded, when other filesystems come into the program */
};

typedef union wfs_fsdata wfs_fsdata_t;

/* ========================= Common to all ================================ */
/* autoconf: WFS_PARAMS is a macro used to wrap function prototypes, so that
        compilers that don't understand ANSI C prototypes still work,
        and ANSI C compilers can issue warnings about type mismatches. */
# ifdef WFS_PARAMS
#  undef WFS_PARAMS
# endif

# ifdef WFS_ANSIC
#  undef WFS_ANSIC
# endif

# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined (WIN32) || defined (__cplusplus)
#  define WFS_PARAMS(protos) protos
#  define WFS_ANSIC
# else
#  define WFS_PARAMS(protos) ()
# endif

# ifdef WFS_ANSIC
#  define WFS_VOID void
# else
#  define WFS_VOID
# endif

# ifdef HAVE_ERRNO_H
#  define WFS_GET_ERRNO_OR_DEFAULT(val) (errno)
#  define WFS_SET_ERRNO(value) do { errno = (value); } while (0)
# else
#  define WFS_GET_ERRNO_OR_DEFAULT(val) (val)
#  define WFS_SET_ERRNO(value)
# endif
# ifndef EPERM
#  define EPERM 1
# endif
# ifndef EBADF
#  define EBADF 9
# endif
# ifndef ENOMEM
#  define ENOMEM 12
# endif

extern int GCC_WARN_UNUSED_RESULT
	wfs_is_stdout_open WFS_PARAMS ((void));

extern int GCC_WARN_UNUSED_RESULT
	wfs_is_stderr_open WFS_PARAMS ((void));

extern const char * GCC_WARN_UNUSED_RESULT
	wfs_get_program_name WFS_PARAMS ((void));

extern void WFS_ATTR ((nonnull))
	wfs_show_msg WFS_PARAMS ((const int type, const char * const msg,
		const char * const extra, const wfs_fsid_t wfs_fs));

enum wfs_progress_type
{
	WFS_PROGRESS_WFS,
	WFS_PROGRESS_PART,
	WFS_PROGRESS_UNRM
};

typedef enum wfs_progress_type wfs_progress_type_t;

extern WFS_ATTR ((nonnull)) void
	wfs_show_progress WFS_PARAMS ((const wfs_progress_type_t type,
		unsigned int percent,
		unsigned int * const prev_percent));

extern const char * const wfs_err_msg;
extern const char * const wfs_err_msg_open;
extern const char * const wfs_err_msg_flush;
extern const char * const wfs_err_msg_close;
extern const char * const wfs_err_msg_malloc;
extern const char * const wfs_err_msg_checkmt;
extern const char * const wfs_err_msg_mtrw;
extern const char * const wfs_err_msg_rdblbm;
extern const char * const wfs_err_msg_wrtblk;
extern const char * const wfs_err_msg_rdblk;
extern const char * const wfs_err_msg_rdino;
extern const char * const wfs_err_msg_signal;
extern const char * const wfs_err_msg_fserr;
extern const char * const wfs_err_msg_openscan;
extern const char * const wfs_err_msg_blkiter;
extern const char * const wfs_err_msg_diriter;
extern const char * const wfs_err_msg_nowork;
extern const char * const wfs_err_msg_suid;
extern const char * const wfs_err_msg_capset;
extern const char * const wfs_err_msg_fork;
extern const char * const wfs_err_msg_nocache;
extern const char * const wfs_err_msg_cacheon;
extern const char * const wfs_err_msg_attopen;
extern const char * const wfs_err_msg_runlist;
extern const char * const wfs_err_msg_srchctx;
extern const char * const wfs_err_msg_param;
extern const char * const wfs_err_msg_pipe;
extern const char * const wfs_err_msg_exec;
extern const char * const wfs_err_msg_seek;
extern const char * const wfs_err_msg_ioctl;

extern const char * const wfs_sig_unk;


#endif	/* WFS_HEADER */
