/*
 * A program for secure cleaning of free space on filesystems.
 *	-- NTFS file system-specific functions, header file.
 *
 * Copyright (C) 2007-2021 Bogdan Drozdowski, bogdro (at) users.sourceforge.net
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

#ifndef WFS_HEADER_NTFS
# define WFS_HEADER_NTFS 1

# include "wipefreespace.h"

extern wfs_errcode_t GCC_WARN_UNUSED_RESULT
	wfs_ntfs_wipe_part WFS_PARAMS ((const wfs_fsid_t wfs_fs));

extern wfs_errcode_t GCC_WARN_UNUSED_RESULT
	wfs_ntfs_wipe_fs WFS_PARAMS ((const wfs_fsid_t wfs_fs));

extern wfs_errcode_t GCC_WARN_UNUSED_RESULT
	wfs_ntfs_wipe_unrm WFS_PARAMS ((const wfs_fsid_t wfs_fs));

extern int GCC_WARN_UNUSED_RESULT
	wfs_ntfs_check_err WFS_PARAMS ((const wfs_fsid_t wfs_fs));

extern int GCC_WARN_UNUSED_RESULT
	wfs_ntfs_is_dirty WFS_PARAMS ((const wfs_fsid_t wfs_fs));

extern wfs_errcode_t GCC_WARN_UNUSED_RESULT
	wfs_ntfs_chk_mount WFS_PARAMS ((const wfs_fsid_t wfs_fs));

extern wfs_errcode_t GCC_WARN_UNUSED_RESULT WFS_ATTR ((nonnull))
	wfs_ntfs_open_fs WFS_PARAMS ((wfs_fsid_t* const wfs_fs,
		const wfs_fsdata_t * const data));

extern wfs_errcode_t
	wfs_ntfs_close_fs WFS_PARAMS ((const wfs_fsid_t wfs_fs));

extern wfs_errcode_t
	wfs_ntfs_flush_fs WFS_PARAMS ((const wfs_fsid_t wfs_fs));

extern void
	wfs_ntfs_print_version WFS_PARAMS ((void));

extern size_t GCC_WARN_UNUSED_RESULT
	wfs_ntfs_get_err_size WFS_PARAMS ((void));

extern void
	wfs_ntfs_init WFS_PARAMS ((void));

extern void
	wfs_ntfs_deinit WFS_PARAMS ((void));

extern void WFS_ATTR ((nonnull))
	wfs_ntfs_show_error WFS_PARAMS ((
		const char * const	msg,
		const char * const	extra,
		const wfs_fsid_t	wfs_fs));

#endif	/* WFS_HEADER_NTFS */
