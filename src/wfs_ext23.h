/*
 * A program for secure cleaning of free space on filesystems.
 *	-- ext2 and ext3 file system-specific functions, header file.
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

#ifndef WFS_HEADER_EXT23
# define WFS_HEADER_EXT23 1

# include "wipefreespace.h"

extern errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
	wfs_e2_wipe_unrm ( const wfs_fsid_t FS, const fselem_t node, error_type * const error );

extern errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
	wfs_e2_wipe_fs ( const wfs_fsid_t FS, error_type * const error );

extern errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
	wfs_e2_wipe_part ( const wfs_fsid_t FS,	error_type * const error );

extern int WFS_ATTR ((warn_unused_result)) 	wfs_e2_check_err	( const wfs_fsid_t FS );

extern int WFS_ATTR ((warn_unused_result))	wfs_e2_is_dirty		( const wfs_fsid_t FS );

extern errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
	wfs_e2_chk_mount ( const char * const dev_name, error_type * const error );

extern errcode_enum WFS_ATTR ((warn_unused_result)) WFS_ATTR ((nonnull))
	wfs_e2_open_fs ( const char * const dev_name, wfs_fsid_t* const FS, CURR_FS * const whichfs,
	const fsdata * const data, error_type * const error );

extern errcode_enum WFS_ATTR ((nonnull)) wfs_e2_close_fs ( const wfs_fsid_t FS, error_type *const error );

extern errcode_enum WFS_ATTR ((nonnull)) wfs_e2_flush_fs ( const wfs_fsid_t FS, error_type *const error );

#endif	/* WFS_HEADER_EXT23 */
