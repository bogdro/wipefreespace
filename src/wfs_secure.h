/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- security-related procedures, header file.
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

#ifndef WFS_HEADER_SEC
# define WFS_HEADER_SEC 1

# include "wipefreespace.h"

extern int GCC_WARN_UNUSED_RESULT
	wfs_clear_cap WFS_PARAMS ((void));

extern wfs_errcode_t GCC_WARN_UNUSED_RESULT
	wfs_check_suid WFS_PARAMS ((void));

extern void WFS_ATTR ((nonnull))
	wfs_check_stds WFS_PARAMS ((int * const stdout_open, int * const stderr_open));

extern void
	wfs_clear_env WFS_PARAMS ((void));

#endif /* WFS_HEADER_SEC */

