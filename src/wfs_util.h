/*
 * A program for secure cleaning of free space on filesystems.
 *	-- utility functions, header file.
 *
 * Copyright (C) 2007-2018 Bogdan Drozdowski, bogdandr (at) op.pl
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

#ifndef WFS_UTIL_H
# define WFS_UTIL_H 1

# include "wipefreespace.h"

enum child_type
{
	CHILD_FORK,
};

struct child_id
{
	enum child_type type;
	union id
	{
#ifdef HAVE_FORK
		pid_t chld_pid;
#endif
		char * dummy;
	} chld_id;
	const char * program_name;
	char ** args;
	char * const * child_env;
	int stdin_fd;
	int stdout_fd;
	int stderr_fd;
};

typedef struct child_id child_id_t;

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

extern wfs_errcode_t GCC_WARN_UNUSED_RESULT WFS_ATTR ((nonnull))
	wfs_create_child WFS_PARAMS ((child_id_t * const id));

extern void WFS_ATTR ((nonnull))
	wfs_wait_for_child WFS_PARAMS ((const child_id_t * const id));

extern int WFS_ATTR ((nonnull))
	wfs_has_child_exited WFS_PARAMS ((const child_id_t * const id));

extern const char *
	convert_fs_to_name WFS_PARAMS ((const wfs_curr_fs_t fs));

extern wfs_errcode_t WFS_ATTR ((nonnull))
	enable_drive_cache WFS_PARAMS ((wfs_fsid_t wfs_fs,
		const int total_fs, fs_ioctl_t ioctls[]));

extern wfs_errcode_t WFS_ATTR ((nonnull))
	disable_drive_cache WFS_PARAMS ((wfs_fsid_t wfs_fs,
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
	flush_pipe_input WFS_PARAMS ((const int fd));

#endif	/* WFS_UTIL_H */
