/*
 * WipeFreeSpace - A program for secure cleaning of free space on filesystems.
 *	-- unit test for the wfs_wiping.c file.
 *
 * Copyright (C) 2021-2024 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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
#include "src/wfs_wiping.h"

#include <stdio.h>

/* ============================================================= */

START_TEST(test_fill_buffer)
{
#define OFFSET 20
	unsigned char buffer[100];
	size_t i, j;
	int selected[WFS_NPAT] = {0};
#ifdef ALL_PASSES_ZERO
	unsigned char marker = '\x55';
#else
	unsigned char marker = '\0';
#endif
	wfs_fsid_t wf_gen;
	wfs_errcode_t err;

	wf_gen.fsname = "";
	wf_gen.fs_error = &err;
	wf_gen.whichfs = WFS_CURR_FS_NONE;
	wf_gen.npasses = WFS_NPAT;
	wf_gen.zero_pass = 0;
	wf_gen.fs_backend = NULL;
	wf_gen.no_wipe_zero_blocks = 0;

	puts ("test_fill_buffer");

	for ( i = 0; i < 20; i++ )
	{
		for ( j = 0; j < sizeof (buffer); j++ )
		{
			buffer[j] = marker;
		}
		wfs_fill_buffer (0, &buffer[OFFSET], i, selected, wf_gen);
		for ( j = 0; j < OFFSET; j++ )
		{
			if ( buffer[j] != marker )
			{
				fail("test_fill_buffer: iteration %ld: buffer[%ld] != %c (0x%x), but should be\n", i, j, marker, marker);
			}
		}
		for ( j = 0; j < i; j++ )
		{
			if ( buffer[OFFSET + j] == marker )
			{
				fail("test_fill_buffer: iteration %ld: buffer[%ld] == %c (0x%x), but shouldn't be\n", i, j, marker, marker);
			}
		}
		for ( j = i + OFFSET; j < sizeof (buffer); j++ )
		{
			if ( buffer[j] != marker )
			{
				fail("test_fill_buffer: iteration %ld: buffer[%ld] != %c (0x%x), but should be\n", i, j, marker, marker);
			}
		}
	}
}
END_TEST

START_TEST(test_init_wiping)
{
	/* no name provided = default Gutmann */
	ck_assert_uint_eq (wfs_init_wiping (10, 1, 1, NULL), 27 + 9);
	ck_assert_uint_eq (wfs_init_wiping (1, 1, 1, NULL), 27 + 9);
	ck_assert_uint_eq (wfs_init_wiping (0, 1, 1, NULL), 27 + 9);

	/* the default number of patterns in the Gutmann method: */
	ck_assert_uint_eq (wfs_init_wiping (10, 1, 1, "gutmann"), 27 + 9 );
	ck_assert_uint_eq (wfs_init_wiping (1, 1, 1, "gutmann"), 27 + 9);
	ck_assert_uint_eq (wfs_init_wiping (0, 1, 1, "gutmann"), 27 + 9);

	/* the default number of patterns in the random method: */
	ck_assert_uint_eq (wfs_init_wiping (10, 1, 1, "random"), 22 + 3);
	ck_assert_uint_eq (wfs_init_wiping (1, 1, 1, "random"), 22 + 3);
	ck_assert_uint_eq (wfs_init_wiping (0, 1, 1, "random"), 22 + 3);

	/* the default number of patterns in the Shneier method: */
	ck_assert_uint_eq (wfs_init_wiping (10, 1, 1, "schneier"), 2 + 5);
	ck_assert_uint_eq (wfs_init_wiping (1, 1, 1, "schneier"), 2 + 5);
	ck_assert_uint_eq (wfs_init_wiping (0, 1, 1, "schneier"), 2 + 5);

	/* the default number of patterns in the DoD method: */
	ck_assert_uint_eq (wfs_init_wiping (10, 1, 1, "dod"), 2 + 1);
	ck_assert_uint_eq (wfs_init_wiping (1, 1, 1, "dod"), 2 + 1);
	ck_assert_uint_eq (wfs_init_wiping (0, 1, 1, "dod"), 2 + 1);

	ck_assert_uint_eq (wfs_init_wiping (10, 1, 1, "blah"), 10);
	ck_assert_uint_eq (wfs_init_wiping (1, 1, 1, "blah"), 1);
	ck_assert_uint_eq (wfs_init_wiping (0, 1, 1, "blah"), WFS_PASSES /* the default number of patterns in the Gutmann method */);
}

static Suite * wfs_create_suite(void)
{
	Suite * s = suite_create("wfs_wiping");

	TCase * tests_wiping = tcase_create("wiping");

	tcase_add_test(tests_wiping, test_fill_buffer);
	tcase_add_test(tests_wiping, test_init_wiping);

	/*tcase_add_checked_fixture(tests_wiping, &setup_test, &teardown_test);*/
	/*tcase_add_unchecked_fixture(tests_wiping, &setup_global, &teardown_global);*/

	/* set 30-second timeouts */
	tcase_set_timeout(tests_wiping, 30);

	suite_add_tcase(s, tests_wiping);

	return s;
}

int main(void)
{
	int failed = 0;

	Suite * s = wfs_create_suite();
	SRunner * sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);

	failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return failed;
}
