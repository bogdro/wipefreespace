/*
 * A program for secure cleaning of free space on filesystems.
 *	-- wiping functions, header file.
 *
 * Copyright (C) 2011-2017 Bogdan Drozdowski, bogdandr (at) op.pl
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

#ifndef WFS_WIPING_H
# define WFS_WIPING_H 1

# include "wipefreespace.h"

extern unsigned long int init_wiping WFS_PARAMS ((
	unsigned long int number_of_passes,
	const int verbose, const int allzero,
	const char * const method));

extern void WFS_ATTR ((nonnull))
	fill_buffer WFS_PARAMS ((unsigned long int pat_no,
		unsigned char * const buffer,
		const size_t buflen,
		int * const selected,
		const wfs_fsid_t wfs_fs));

#endif /* WFS_WIPING_H */
