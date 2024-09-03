/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- subprocess functions, header file.
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

#ifndef WFS_SUBPROCESS_H
# define WFS_SUBPROCESS_H 1

enum child_type
{
	CHILD_FORK,
};

struct child_id
{
	enum child_type type;
	union id
	{
#ifdef HAVE_WORKING_FORK /* HAVE_FORK */
		pid_t chld_pid;
#endif
		char * dummy;
	} chld_id;
	const char * program_name;
	char ** args;
	char * const * child_env;
	int stdin_fd;
	int stdout_fd;
	int stderr_fd;
};

typedef struct child_id child_id_t;

extern wfs_errcode_t GCC_WARN_UNUSED_RESULT WFS_ATTR ((nonnull))
	wfs_create_child WFS_PARAMS ((child_id_t * const id));

extern void WFS_ATTR ((nonnull))
	wfs_wait_for_child WFS_PARAMS ((const child_id_t * const id));

extern int WFS_ATTR ((nonnull))
	wfs_has_child_exited WFS_PARAMS ((const child_id_t * const id));

#endif	/* WFS_SUBPROCESS_H */
