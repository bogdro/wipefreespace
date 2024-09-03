/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- mount-checking functions, header file.
 *
 * Copyright (C) 2024 Bogdan Drozdowski, bogdro (at) users.sourceforge.net
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

#ifndef WFS_MOUNT_CHECK_H
# define WFS_MOUNT_CHECK_H 1

# include "wipefreespace.h"

extern wfs_errcode_t GCC_WARN_UNUSED_RESULT
	wfs_check_mounted WFS_PARAMS ((const wfs_fsid_t wfs_fs));

extern wfs_errcode_t GCC_WARN_UNUSED_RESULT WFS_ATTR ((nonnull))
	wfs_get_mnt_point WFS_PARAMS ((const char * const dev_name,
		wfs_errcode_t * const error,
		char * const mnt_point,
		const size_t mnt_point_len,
		int * const is_rw));

extern int GCC_WARN_UNUSED_RESULT WFS_ATTR ((nonnull))
	wfs_check_loop_mounted WFS_PARAMS ((
		const char * const dev_name));

#endif	/* WFS_MOUNT_CHECK_H */
