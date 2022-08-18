/*
 * A program for secure cleaning of free space on filesystems.
 *	-- JFS file system-specific functions, header file.
 *
 * Copyright (C) 2010 Bogdan Drozdowski, bogdandr (at) op.pl
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

#ifndef WFS_HEADER_JFS
# define WFS_HEADER_JFS 1

# include "wipefreespace.h"

extern errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
	wfs_jfs_wipe_unrm PARAMS(( wfs_fsid_t FS, const fselem_t node, error_type * const error ));

extern errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
	wfs_jfs_wipe_fs PARAMS(( wfs_fsid_t FS, error_type * const error ));

extern errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
	wfs_jfs_wipe_part PARAMS(( const wfs_fsid_t FS, error_type * const error ));

extern int WFS_ATTR ((warn_unused_result))
	wfs_jfs_check_err PARAMS(( wfs_fsid_t FS ));

extern int WFS_ATTR ((warn_unused_result))
	wfs_jfs_is_dirty PARAMS(( wfs_fsid_t FS ));

extern errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
	wfs_jfs_chk_mount PARAMS(( const char * const dev_name, error_type * const error ));

extern errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
	wfs_jfs_open_fs PARAMS(( const char * const dev_name, wfs_fsid_t* const FS,
		CURR_FS * const whichfs, const fsdata * const data, error_type * const error ));

extern errcode_enum WFS_ATTR ((nonnull))
	wfs_jfs_close_fs PARAMS(( const wfs_fsid_t FS, error_type *const error ));

extern errcode_enum WFS_ATTR ((nonnull))
	wfs_jfs_flush_fs PARAMS(( wfs_fsid_t FS, error_type * const error ));

#endif	/* WFS_HEADER_JFS */
