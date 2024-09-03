/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- utility functions, header file.
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

#ifndef WFS_UTIL_H
# define WFS_UTIL_H 1

# include "wipefreespace.h"

/* This structure helps to run ioctl()s once per device */
struct fs_ioctl
{
	int how_many;		/* how many ioctl tries were on this device. Incremented
				   on begin, decremented on fs close. When reaches zero,
				   caching is brought back to its previous state. */
	int was_enabled;
	char fs_name[WFS_MNTBUFLEN];	/* space for "/dev/hda" etc. */
};

typedef struct fs_ioctl fs_ioctl_t;


extern wfs_errcode_t GCC_WARN_UNUSED_RESULT
	wfs_check_mounted WFS_PARAMS ((const wfs_fsid_t wfs_fs));

extern wfs_errcode_t GCC_WARN_UNUSED_RESULT WFS_ATTR ((nonnull))
	wfs_get_mnt_point WFS_PARAMS ((const char * const dev_name,
		wfs_errcode_t * const error,
		char * const mnt_point,
		const size_t mnt_point_len,
		int * const is_rw));

extern const char *
	wfs_convert_fs_to_name WFS_PARAMS ((const wfs_curr_fs_t fs));

extern wfs_errcode_t WFS_ATTR ((nonnull))
	wfs_enable_drive_cache WFS_PARAMS ((wfs_fsid_t wfs_fs,
		const int total_fs, fs_ioctl_t ioctls[]));

extern wfs_errcode_t WFS_ATTR ((nonnull))
	wfs_disable_drive_cache WFS_PARAMS ((wfs_fsid_t wfs_fs,
		const int total_fs, fs_ioctl_t ioctls[]));

extern void WFS_ATTR ((nonnull))
	wfs_show_fs_error_gen WFS_PARAMS ((
		const char * const	msg,
		const char * const	extra,
		const wfs_fsid_t	wfs_fs));

extern int GCC_WARN_UNUSED_RESULT WFS_ATTR ((nonnull))
	wfs_check_loop_mounted WFS_PARAMS ((
		const char * const dev_name));

extern int GCC_WARN_UNUSED_RESULT WFS_ATTR ((nonnull))
	wfs_is_block_zero WFS_PARAMS ((
		const unsigned char * const buf,
		const size_t len));

extern void
	wfs_flush_pipe_input WFS_PARAMS ((const int fd));

extern char **
	wfs_deep_copy_array WFS_PARAMS ((const char * const * const array,
		const unsigned int len));

extern void
	wfs_free_array_deep_copy WFS_PARAMS ((char * array[],
		const unsigned int len));

# ifdef HAVE_MEMCPY
#  define WFS_MEMCOPY memcpy
# else
extern void wfs_memcopy WFS_PARAMS ((void * const dest,
	const void * const src, const size_t len));
#  define WFS_MEMCOPY wfs_memcopy
# endif

# ifdef HAVE_MEMSET
#  define WFS_MEMSET memset
# else
extern void wfs_mem_set WFS_PARAMS ((void * const dest,
	const char value, const size_t len));
#  define WFS_MEMSET wfs_mem_set
# endif

# ifdef HAVE_STRDUP
#  define WFS_STRDUP strdup
# else
extern char * wfs_duplicate_string WFS_PARAMS ((const char src[]));
#  define WFS_STRDUP wfs_duplicate_string
# endif

#endif	/* WFS_UTIL_H */
