/*
 * A program for secure cleaning of free space on filesystems.
 *	-- security-related procedures, header file.
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

#ifndef WFS_HEADER_SEC
# define WFS_HEADER_SEC 1

# include "wipefreespace.h"

extern WFS_ATTR ((nonnull)) WFS_ATTR ((warn_unused_result))
	int wfs_clear_cap (error_type * const error);
extern WFS_ATTR ((warn_unused_result))	int wfs_check_suid (void);
extern WFS_ATTR ((nonnull))		void wfs_check_stds (int *stdout_open, int *stderr_open);
extern void wfs_clear_env (void);

#endif /* WFS_HEADER_SEC */

