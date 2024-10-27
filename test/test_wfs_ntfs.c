/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- unit test for the wfs_ntfs.c file.
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
#include "src/wfs_ntfs.h"
#include "src/wfs_mount_check.h"

#define FS_NAME_NTFS "test-fs-ntfs"

/* =================== stubs =================================== */

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

/* ============================================================= */

static wfs_fsid_t wfs_fs = {FS_NAME_NTFS, 1, 0, NULL, NULL, WFS_CURR_FS_NONE, 0, 0, WFS_WIPE_MODE_PATTERN};
static wfs_fsdata_t data = {{0, 0}};

START_TEST(test_wfs_ntfs_chk_mount)
{
	ck_assert_int_eq(WFS_SUCCESS, wfs_ntfs_chk_mount(wfs_fs));
}
END_TEST

START_TEST(test_wfs_ntfs_wipe_fs)
{
	wfs_errcode_t ret_wfs = wfs_ntfs_open_fs(&wfs_fs, &data);
	ck_assert_int_eq(WFS_SUCCESS, ret_wfs);
	ret_wfs = wfs_ntfs_wipe_fs(wfs_fs);
	ck_assert_int_eq(WFS_SUCCESS, ret_wfs);
	wfs_ntfs_close_fs(wfs_fs);
}
END_TEST

START_TEST(test_wfs_ntfs_wipe_unrm)
{
	wfs_errcode_t ret_wfs = wfs_ntfs_open_fs(&wfs_fs, &data);
	ck_assert_int_eq(WFS_SUCCESS, ret_wfs);
	ret_wfs = wfs_ntfs_wipe_unrm(wfs_fs);
	ck_assert_int_eq(WFS_SUCCESS, ret_wfs);
	wfs_ntfs_close_fs(wfs_fs);
}
END_TEST

START_TEST(test_wfs_ntfs_wipe_part)
{
	wfs_errcode_t ret_wfs = wfs_ntfs_open_fs(&wfs_fs, &data);
	ck_assert_int_eq(WFS_SUCCESS, ret_wfs);
	ret_wfs = wfs_ntfs_wipe_part(wfs_fs);
	/* allow for empty files */
	ck_assert(ret_wfs == WFS_SUCCESS || ret_wfs == WFS_ATTROPEN);
	wfs_ntfs_close_fs(wfs_fs);
}
END_TEST

START_TEST(test_wfs_ntfs_check_err)
{
	wfs_errcode_t ret_wfs = wfs_ntfs_open_fs(&wfs_fs, &data);
	ck_assert_int_eq(WFS_SUCCESS, ret_wfs);
	ck_assert_int_eq(0, wfs_ntfs_check_err(wfs_fs));
	wfs_ntfs_close_fs(wfs_fs);
}
END_TEST

START_TEST(test_wfs_ntfs_is_dirty)
{
	wfs_errcode_t ret_wfs = wfs_ntfs_open_fs(&wfs_fs, &data);
	ck_assert_int_eq(WFS_SUCCESS, ret_wfs);
	ck_assert_int_eq(0, wfs_ntfs_is_dirty(wfs_fs));
	wfs_ntfs_close_fs(wfs_fs);
}
END_TEST

START_TEST(test_wfs_ntfs_flush_fs)
{
	wfs_errcode_t ret_wfs = wfs_ntfs_open_fs(&wfs_fs, &data);
	ck_assert_int_eq(WFS_SUCCESS, ret_wfs);
	ck_assert_int_eq(0, wfs_ntfs_flush_fs(wfs_fs));
	wfs_ntfs_close_fs(wfs_fs);
}
END_TEST

START_TEST(test_wfs_ntfs_print_version)
{
	wfs_ntfs_print_version();
}
END_TEST

START_TEST(test_wfs_ntfs_get_err_size)
{
	ck_assert_uint_gt(wfs_ntfs_get_err_size(), 0);
}
END_TEST

START_TEST(test_wfs_ntfs_lib_init)
{
	wfs_ntfs_init();
}
END_TEST

START_TEST(test_wfs_ntfs_lib_deinit)
{
	wfs_ntfs_deinit();
}
END_TEST

START_TEST(test_wfs_ntfs_show_error)
{
	long int e = 0;
	wfs_fs.fs_error = &e;
	wfs_ntfs_show_error("err", "extra", wfs_fs);
}
END_TEST

static Suite * wfs_create_suite(void)
{
	Suite * s = suite_create("wfs_ntfs");

	TCase * tests_ntfs = tcase_create("ntfs");

	tcase_add_test(tests_ntfs, test_wfs_ntfs_chk_mount);
	tcase_add_test(tests_ntfs, test_wfs_ntfs_wipe_fs);
	tcase_add_test(tests_ntfs, test_wfs_ntfs_wipe_unrm);
	tcase_add_test(tests_ntfs, test_wfs_ntfs_wipe_part);
	tcase_add_test(tests_ntfs, test_wfs_ntfs_check_err);
	tcase_add_test(tests_ntfs, test_wfs_ntfs_is_dirty);
	tcase_add_test(tests_ntfs, test_wfs_ntfs_flush_fs);
	tcase_add_test(tests_ntfs, test_wfs_ntfs_print_version);
	tcase_add_test(tests_ntfs, test_wfs_ntfs_get_err_size);
	tcase_add_test(tests_ntfs, test_wfs_ntfs_lib_init);
	tcase_add_test(tests_ntfs, test_wfs_ntfs_lib_deinit);
	tcase_add_test(tests_ntfs, test_wfs_ntfs_show_error);

	/*tcase_add_checked_fixture(tests_ntfs, &setup_test, &teardown_test);*/
	/*tcase_add_unchecked_fixture(tests_ntfs, &setup_global, &teardown_global);*/

	/* set 30-second timeouts */
	tcase_set_timeout(tests_ntfs, 30);

	suite_add_tcase(s, tests_ntfs);

	return s;
}

int main(void)
{
	int failed = 0;
	struct stat fs_stat;
	Suite * s;
	SRunner * sr;

	if (stat(FS_NAME_NTFS, &fs_stat) != 0)
	{
		return WFS_AUTOMAKE_TEST_SKIP;
	}

	s = wfs_create_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);

	failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return failed;
}
