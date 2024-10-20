/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- stubs for unit tests.
 *
 * Copyright (C) 2024 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "wfs_test_common.h"
#include "src/wfs_mount_check.h"

int sig_recvd = 0;
const char * const wfs_err_msg = "error";

void
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_show_msg (
#ifdef WFS_ANSIC
	const int		type WFS_ATTR ((unused)),
	const char * const	msg WFS_ATTR ((unused)),
	const char * const	extra WFS_ATTR ((unused)),
	const wfs_fsid_t	wfs_fs WFS_ATTR ((unused)) )
#else
	type, msg, extra, wfs_fs )
	const int		type WFS_ATTR ((unused));
	const char * const	msg WFS_ATTR ((unused));
	const char * const	extra WFS_ATTR ((unused));
	const wfs_fsid_t	wfs_fs WFS_ATTR ((unused));
#endif
{
}

void
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_show_progress (
#ifdef WFS_ANSIC
	const wfs_progress_type_t	type,
	unsigned int			percent,
	unsigned int * const		prev_percent
	)
#else
	type, percent, prev_percent )
	const wfs_progress_type_t	type;
	unsigned int			percent;
	unsigned int * const		prev_percent;
#endif
{
}

const char *
wfs_get_program_name (WFS_VOID)
{
	return "WipeFreeSpace";
}

int
wfs_is_stderr_open (WFS_VOID)
{
	return 1;
}

wfs_errcode_t
wfs_check_mounted (
#ifdef WFS_ANSIC
	const wfs_fsid_t wfs_fs)
#else
	wfs_fs)
	const wfs_fsid_t wfs_fs;
#endif
{
	return 0;
}
