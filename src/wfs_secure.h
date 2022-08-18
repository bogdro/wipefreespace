/*
 * A program for secure cleaning of free space on filesystems.
 *	-- security-related procedures, header file.
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

#ifndef WFS_HEADER_SEC
# define WFS_HEADER_SEC 1

# include "wipefreespace.h"

extern int WFS_ATTR ((nonnull)) WFS_ATTR ((warn_unused_result))
	wfs_clear_cap WFS_PARAMS((wfs_error_type_t * const error));
extern int WFS_ATTR ((warn_unused_result))
	wfs_check_suid WFS_PARAMS((void));
extern void WFS_ATTR ((nonnull))
	wfs_check_stds WFS_PARAMS((int *stdout_open, int *stderr_open));
extern void
	wfs_clear_env WFS_PARAMS((void));

#endif /* WFS_HEADER_SEC */

