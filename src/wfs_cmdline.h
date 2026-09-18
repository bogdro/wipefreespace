/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- command line parsing, header file.
 *
 * Copyright (C) 2026 Bogdan Drozdowski, bogdro (at) users.sourceforge.net
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

#ifndef WFS_CMDLINE_H
# define WFS_CMDLINE_H 1

# include "wipefreespace.h"

extern int GCC_WARN_UNUSED_RESULT
	wfs_parse_cmdline WFS_PARAMS ((int argc, char* argv[]));

extern int GCC_WARN_UNUSED_RESULT
	wfs_is_verbose WFS_PARAMS ((void));

#endif	/* WFS_CMDLINE_H */
