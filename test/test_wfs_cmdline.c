/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- unit test for the wfs_cmdline.c file.
 *
 * Copyright (C) 2026 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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
#include "src/wfs_cmdline.h"

/* =================== stubs =================================== */

int
wfs_is_stdout_open (WFS_VOID)
{
	return 1;
}

void
wfs_set_stdout_open (
#ifdef WFS_ANSIC
	int value)
#else
	value)
	int value;
#endif
{
}

void
wfs_set_stderr_open (
#ifdef WFS_ANSIC
	int value)
#else
	value)
	int value;
#endif
{
}

const char *
wfs_get_err_msg (
#ifdef WFS_ANSIC
	const wfs_errcode_t wfs_err)
#else
	wfs_err)
	const wfs_errcode_t wfs_err;
#endif
{
	return "TEST-ERROR";
}

void wfs_set_sigh (
#ifdef WFS_ANSIC
	const int opt_verbose)
#else
	opt_verbose)
	const int opt_verbose;
#endif
{
}

void
wfs_clear_env (WFS_VOID)
{
}

const char * const wfs_err_msg         = ("error");
const char * const wfs_err_msg_open    = ("during opening");
const char * const wfs_err_msg_flush   = ("while flushing");
const char * const wfs_err_msg_close   = ("during closing");
const char * const wfs_err_msg_malloc  = ("during malloc while working on");
const char * const wfs_err_msg_checkmt = ("during checking if the file system is mounted");
const char * const wfs_err_msg_mtrw    = ("- Device is mounted in read-write mode");
const char * const wfs_err_msg_rdblbm  = ("during reading block bitmap from");
const char * const wfs_err_msg_wrtblk  = ("during writing of a block on");
const char * const wfs_err_msg_rdblk   = ("during reading of a block on");
const char * const wfs_err_msg_rdino   = ("during reading of an inode on");
const char * const wfs_err_msg_signal  = ("while trying to set a signal handler for");
const char * const wfs_err_msg_fserr   = ("Filesystem has errors");
const char * const wfs_err_msg_openscan= ("during opening a scan of");
const char * const wfs_err_msg_blkiter = ("during iterating over blocks on");
const char * const wfs_err_msg_diriter = ("during iterating over a directory on");
const char * const wfs_err_msg_nowork  = ("Nothing selected for wiping.");
const char * const wfs_err_msg_suid    = ("PLEASE do NOT set this program's suid bit. Use sgid instead.");
const char * const wfs_err_msg_capset  = ("during setting capabilities");
const char * const wfs_err_msg_fork    = ("during creation of child process");
const char * const wfs_err_msg_nocache = ("during disabling device cache");
const char * const wfs_err_msg_cacheon = ("during enabling device cache");
const char * const wfs_err_msg_attopen = ("during opening an attribute");
const char * const wfs_err_msg_runlist = ("during mapping a runlist");
const char * const wfs_err_msg_srchctx = ("during creating a search context");
const char * const wfs_err_msg_param   = ("during checking parameters");
const char * const wfs_err_msg_pipe    = ("during creating a pipe");
const char * const wfs_err_msg_exec    = ("during starting a sub-process");
const char * const wfs_err_msg_seek    = ("during seeking to position");
const char * const wfs_err_msg_ioctl   = ("during performing a control operation on");


/* ============================================================= */

START_TEST(test_wfs_cmdline_help)
{
	char * argv[] = {"wipefreespace", "-h", NULL};

	ck_assert_int_eq(WFS_NOTHING, wfs_parse_cmdline(2, argv));
	argv[1] = "--help";
	ck_assert_int_eq(WFS_NOTHING, wfs_parse_cmdline(2, argv));
}
END_TEST

START_TEST(test_wfs_cmdline_version)
{
	char * argv[] = {"wipefreespace", "-V", NULL};

	ck_assert_int_eq(WFS_NOTHING, wfs_parse_cmdline(2, argv));
	argv[1] = "--version";
	ck_assert_int_eq(WFS_NOTHING, wfs_parse_cmdline(2, argv));
}
END_TEST

START_TEST(test_wfs_cmdline_license)
{
	char * argv[] = {"wipefreespace", "-l", NULL};

	ck_assert_int_eq(WFS_NOTHING, wfs_parse_cmdline(2, argv));
	argv[1] = "--license";
	ck_assert_int_eq(WFS_NOTHING, wfs_parse_cmdline(2, argv));
	argv[1] = "--licence";
	ck_assert_int_eq(WFS_NOTHING, wfs_parse_cmdline(2, argv));
}
END_TEST

START_TEST(test_wfs_cmdline_full)
{
	char * argv[] = {
		"wipefreespace", "-v", "-f",
		"-n", "1",
		"--order", "block",
		"--first-block", "1",
		"--last-block", "1000000",
		WFS_TEST_FILESYSTEM,
		NULL
	};

	ck_assert_int_eq(WFS_SUCCESS, wfs_parse_cmdline(sizeof(argv) / sizeof(argv[0]) - 1, argv));
}
END_TEST

START_TEST(test_wfs_cmdline_invalid)
{
	char * argv[] = {"wipefreespace", "--garbage-option", NULL};

	ck_assert_int_eq(WFS_BAD_CMDLN, wfs_parse_cmdline(2, argv));
}
END_TEST

static Suite * wfs_create_suite(void)
{
	Suite * s = suite_create("wfs_cmdline");

	TCase * tests_cmdline = tcase_create("cmdline");

	tcase_add_test(tests_cmdline, test_wfs_cmdline_help);
	tcase_add_test(tests_cmdline, test_wfs_cmdline_version);
	tcase_add_test(tests_cmdline, test_wfs_cmdline_license);
	tcase_add_test(tests_cmdline, test_wfs_cmdline_full);
	tcase_add_test(tests_cmdline, test_wfs_cmdline_invalid);

	/*tcase_add_checked_fixture(tests_cmdline, &setup_test, &teardown_test);*/
	/*tcase_add_unchecked_fixture(tests_cmdline, &setup_global, &teardown_global);*/

	suite_add_tcase(s, tests_cmdline);

	return s;
}

int main(void)
{
	int failed = 0;
#ifdef HAVE_STAT64
	struct stat64 fs_stat64;
#else
	struct stat fs_stat;
#endif
	Suite * s;
	SRunner * sr;

#ifdef HAVE_STAT64
	if (stat64(WFS_TEST_FILESYSTEM, &fs_stat64) != 0)
	{
		return WFS_AUTOMAKE_TEST_SKIP;
	}
#else
	if (stat(WFS_TEST_FILESYSTEM, &fs_stat) != 0)
	{
		return WFS_AUTOMAKE_TEST_SKIP;
	}
#endif

	s = wfs_create_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);

	failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return failed;
}
