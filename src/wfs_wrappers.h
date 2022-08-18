/*
 * A program for secure cleaning of free space on filesystems.
 *	-- wrapper functions, header file.
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

#ifndef WFS_HEADER_WRAP
# define WFS_HEADER_WRAP 1

# include "wipefreespace.h"

extern wfs_errcode_t WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
	wfs_open_fs WFS_PARAMS((   const char * const dev_name, wfs_fsid_t * const FS,
		wfs_curr_fs_t * const which_fs, const wfs_fsdata_t * const data, wfs_error_type_t * const error ));

extern wfs_errcode_t WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
	wfs_chk_mount WFS_PARAMS(( const char * const dev_name, wfs_error_type_t * const error ));

extern wfs_errcode_t WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
	wipe_unrm WFS_PARAMS(( wfs_fsid_t FS, const wfs_curr_fs_t which_fs, wfs_error_type_t * const error ));

extern wfs_errcode_t WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
	wipe_fs	WFS_PARAMS(( wfs_fsid_t FS, const wfs_curr_fs_t which_fs, wfs_error_type_t * const error ));

extern wfs_errcode_t WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
	wipe_part WFS_PARAMS(( const wfs_fsid_t FS, const wfs_curr_fs_t which_fs, wfs_error_type_t * const error ));

extern wfs_errcode_t WFS_ATTR ((nonnull))
	wfs_close_fs WFS_PARAMS(( const wfs_fsid_t FS, const wfs_curr_fs_t which_fs, wfs_error_type_t * const error ));

extern wfs_errcode_t WFS_ATTR ((nonnull))
	wfs_flush_fs WFS_PARAMS(( wfs_fsid_t FS, const wfs_curr_fs_t which_fs, wfs_error_type_t * const error ));

extern int WFS_ATTR ((warn_unused_result))
	wfs_check_err WFS_PARAMS(( wfs_fsid_t FS, const wfs_curr_fs_t which_fs, wfs_error_type_t * const error ));

extern int WFS_ATTR ((warn_unused_result))
	wfs_is_dirty WFS_PARAMS(( wfs_fsid_t FS, const wfs_curr_fs_t which_fs, wfs_error_type_t * const error ));

#endif	/* WFS_HEADER_WRAP */
