/*
 * A program for secure cleaning of free space on filesystems.
 *	-- ReiserFSv4 file system-specific functions, header file.
 *
 * Copyright (C) 2007-2019 Bogdan Drozdowski, bogdandr (at) op.pl
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

#ifndef WFS_HEADER_REISER4
# define WFS_HEADER_REISER4 1

# include "wipefreespace.h"

extern wfs_errcode_t GCC_WARN_UNUSED_RESULT
	wfs_r4_wipe_unrm WFS_PARAMS ((wfs_fsid_t wfs_fs));

extern wfs_errcode_t GCC_WARN_UNUSED_RESULT
	wfs_r4_wipe_fs WFS_PARAMS ((wfs_fsid_t wfs_fs));

extern wfs_errcode_t GCC_WARN_UNUSED_RESULT
	wfs_r4_wipe_part WFS_PARAMS ((const wfs_fsid_t wfs_fs));

extern int GCC_WARN_UNUSED_RESULT
	wfs_r4_check_err WFS_PARAMS ((wfs_fsid_t wfs_fs));

extern int GCC_WARN_UNUSED_RESULT
	wfs_r4_is_dirty WFS_PARAMS ((wfs_fsid_t wfs_fs));

extern wfs_errcode_t GCC_WARN_UNUSED_RESULT
	wfs_r4_chk_mount WFS_PARAMS ((const wfs_fsid_t wfs_fs));

extern wfs_errcode_t GCC_WARN_UNUSED_RESULT WFS_ATTR ((nonnull))
	wfs_r4_open_fs WFS_PARAMS ((wfs_fsid_t * const wfs_fs,
		const wfs_fsdata_t * const data));

extern wfs_errcode_t
	wfs_r4_close_fs WFS_PARAMS ((const wfs_fsid_t wfs_fs));

extern wfs_errcode_t
	wfs_r4_flush_fs WFS_PARAMS ((wfs_fsid_t wfs_fs));

extern void
	wfs_r4_print_version WFS_PARAMS ((void));

extern size_t GCC_WARN_UNUSED_RESULT
	wfs_r4_get_err_size WFS_PARAMS ((void));

extern void
	wfs_r4_init WFS_PARAMS ((void));

extern void
	wfs_r4_deinit WFS_PARAMS ((void));

extern void WFS_ATTR ((nonnull))
	wfs_r4_show_error WFS_PARAMS ((
		const char * const	msg,
		const char * const	extra,
		const wfs_fsid_t	wfs_fs));

#endif	/* WFS_HEADER_REISER4 */
