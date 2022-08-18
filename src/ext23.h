/*
 * A program for secure cleaning of free space on filesystems.
 *	-- ext2 and ext3 file system-specific functions, header file.
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

#ifndef WFS_HEADER_EXT23
# define WFS_HEADER_EXT23

# ifndef ATTR
#  define ATTR(x)
# endif

extern int ATTR((warn_unused_result))	wfs_e2wipe_unrm	( wfs_fsid_t FS, fselem_t node );
extern int ATTR((warn_unused_result))	wfs_e2wipe_fs	( wfs_fsid_t FS );
extern int ATTR((warn_unused_result))	wfs_e2wipe_part	( wfs_fsid_t FS );
extern int ATTR((warn_unused_result))	wfs_e2checkerr	( wfs_fsid_t FS );
extern int ATTR((warn_unused_result))	wfs_e2isdirty	( wfs_fsid_t FS );
extern int ATTR((warn_unused_result))	wfs_e2getblocksize ( wfs_fsid_t FS );
extern int ATTR((warn_unused_result)) ATTR((nonnull)) wfs_e2chkmount ( const char*const devname );
extern int ATTR((warn_unused_result)) ATTR((nonnull))
	wfs_e2openfs ( const char*const devname, wfs_fsid_t *FS, int *whichfs, fsdata* data );
extern int wfs_e2closefs ( wfs_fsid_t FS );
extern int wfs_e2flushfs ( wfs_fsid_t FS );

#endif	/* WFS_HEADER_EXT23 */
