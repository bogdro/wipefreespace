/*
 * A program for secure cleaning of free space on ext2/3 partitions.
 *	-- wrapper functions, header file.
 *
 * Copyright (C) 2007 Bogdan Drozdowski, bogdandr (at) op.pl
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
# define WFS_HEADER_WRAP

# include "e2wipefreespace.h"

extern int ATTR((warn_unused_result)) ATTR((nonnull))
	wfs_openfs ( const char*const devname, fsid *FS, int *whichfs, fsdata *data );

extern int ATTR((warn_unused_result)) ATTR((nonnull))
	wfs_chkmount ( const char*const devname );

extern int ATTR((warn_unused_result))	wipe_unrm		( fsid FS, int whichfs );
extern int ATTR((warn_unused_result))	wipe_fs			( fsid FS, int whichfs );
extern int ATTR((warn_unused_result))	wipe_part		( fsid FS, int whichfs );
extern int 				wfs_closefs		( fsid FS, int whichfs );
extern int ATTR((warn_unused_result))	wfs_checkerr		( fsid FS, int whichfs );
extern int ATTR((warn_unused_result))	wfs_isdirty		( fsid FS, int whichfs );
extern int 				wfs_flushfs		( fsid FS, int whichfs );
extern int ATTR((warn_unused_result))	wfs_getblocksize	( fsid FS, int whichfs );

#endif	/* WFS_HEADER_WRAP */
