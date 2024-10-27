/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- tests, common header file.
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

#ifndef WFS_TEST_COMMON
# define WFS_TEST_COMMON 1

# define _POSIX_C_SOURCE 200112L
# define _XOPEN_SOURCE 600
# define _LARGEFILE64_SOURCE 1
# define _GNU_SOURCE	1
# define _ATFILE_SOURCE 1
# define __USE_GNU

# ifdef HAVE_CONFIG_H
#  include <config.h>
# endif

# include "wipefreespace.h"

# include <check.h>

/* compatibility with older check versions */
# ifndef ck_abort
#  define ck_abort() ck_abort_msg(NULL)
#  define ck_abort_msg fail
#  define ck_assert(C) ck_assert_msg(C, NULL)
#  define ck_assert_msg fail_unless
# endif

# ifndef _ck_assert_int
#  define _ck_assert_int(X, O, Y) ck_assert_msg((X) O (Y), "Assertion '"#X#O#Y"' failed: "#X"==%d, "#Y"==%d", X, Y)
#  define ck_assert_int_eq(X, Y) _ck_assert_int(X, ==, Y)
#  define ck_assert_int_ne(X, Y) _ck_assert_int(X, !=, Y)
# endif

# ifndef _ck_assert_str
#  define _ck_assert_str(C, X, O, Y) ck_assert_msg(C, "Assertion '"#X#O#Y"' failed: "#X"==\"%s\", "#Y"==\"%s\"", X, Y)
#  define ck_assert_str_eq(X, Y) _ck_assert_str(!strcmp(X, Y), X, ==, Y)
#  define ck_assert_str_ne(X, Y) _ck_assert_str(strcmp(X, Y), X, !=, Y)
# endif

# ifndef ck_assert_uint_gt
#  define _ck_assert_uint(X, OP, Y) do { \
      uintmax_t _ck_x = (X); \
      uintmax_t _ck_y = (Y); \
      ck_assert_msg(_ck_x OP _ck_y, "Assertion '%s' failed: %s == %ju, %s == %ju", #X" "#OP" "#Y, #X, _ck_x, #Y, _ck_y); \
    } while (0)
#  define ck_assert_uint_gt(X, Y) _ck_assert_uint(X, >, Y)
# endif

# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# endif

# ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
# endif

# ifdef HAVE_UNISTD_H
#  include <unistd.h>
# endif

# define WFS_AUTOMAKE_TEST_SKIP 77

#endif /* WFS_TEST_COMMON */
