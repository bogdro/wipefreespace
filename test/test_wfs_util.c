/*
 * A program for secure cleaning of free space on filesystems.
 *	-- unit test for the wfs_util.c file.
 *
 * Copyright (C) 2015-2022 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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

#define _POSIX_C_SOURCE 200112L
#define _XOPEN_SOURCE 600
#define _LARGEFILE64_SOURCE 1
#define _GNU_SOURCE	1
#define _ATFILE_SOURCE 1
#define __USE_GNU

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "src/wipefreespace.h"
#include "src/wfs_util.h"
#include "src/wfs_wiping.h"

#ifdef WFS_EXT234
# include "wfs_ext234.h"
#endif

#ifdef WFS_NTFS
# include "wfs_ntfs.h"
#endif

#ifdef WFS_XFS
# include "wfs_xfs.h"
#endif

#ifdef WFS_REISER
# include "wfs_reiser.h"
#endif

#ifdef WFS_REISER4
# include "wfs_reiser4.h"
#endif

#ifdef WFS_FATFS
# include "wfs_fat.h"
#endif

#ifdef WFS_MINIXFS
# include "wfs_minixfs.h"
#endif

#ifdef WFS_JFS
# include "wfs_jfs.h"
#endif

#ifdef WFS_HFSP
# include "wfs_hfsp.h"
#endif

#ifdef WFS_OCFS
# include "wfs_ocfs.h"
#endif

#include <check.h>

/* compatibility with older check versions */
#ifndef ck_abort
# define ck_abort() ck_abort_msg(NULL)
# define ck_abort_msg fail
# define ck_assert(C) ck_assert_msg(C, NULL)
# define ck_assert_msg fail_unless
#endif

#ifndef _ck_assert_int
# define _ck_assert_int(X, O, Y) ck_assert_msg((X) O (Y), "Assertion '"#X#O#Y"' failed: "#X"==%d, "#Y"==%d", X, Y)
# define ck_assert_int_eq(X, Y) _ck_assert_int(X, ==, Y)
# define ck_assert_int_ne(X, Y) _ck_assert_int(X, !=, Y)
#endif

#ifndef _ck_assert_str
# define _ck_assert_str(C, X, O, Y) ck_assert_msg(C, "Assertion '"#X#O#Y"' failed: "#X"==\"%s\", "#Y"==\"%s\"", X, Y)
# define ck_assert_str_eq(X, Y) _ck_assert_str(!strcmp(X, Y), X, ==, Y)
# define ck_assert_str_ne(X, Y) _ck_assert_str(strcmp(X, Y), X, !=, Y)
#endif


#ifdef HAVE_ERRNO_H
# include <errno.h>
#else
static int errno = -1;
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <stdio.h>

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#else
# define O_RDONLY	0
# define O_WRONLY	1
# define O_RDWR		2
# define O_TRUNC	01000
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#else
# define S_IRUSR 0600
# define S_IWUSR 0400
#endif

#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif

#ifdef HAVE_SYS_MOUNT_H
# include <sys/mount.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#ifdef HAVE_LINUX_LOOP_H
# include <linux/loop.h>
#endif

#if (defined HAVE_FCNTL_H) && (defined HAVE_SYS_IOCTL_H) \
	&& (defined HAVE_SYS_MOUNT_H) && (defined HAVE_MOUNT) \
	&& (defined HAVE_OPEN) && (defined HAVE_UMOUNT) \
	&& ((defined HAVE_LINUX_LOOP_H) || (defined HAVE_LOOP_H))

# define WFS_TEST_CAN_MOUNT 1
#else
# undef WFS_TEST_CAN_MOUNT
#endif

/* ============ stubs: */

const char * const wfs_err_msg = "ERROR";
int sig_recvd = 0;
int sigchld_recvd = 0;

int
wfs_is_stderr_open (
#ifdef WFS_ANSIC
	void
#endif
)
{
	return 0;
}

const char *
wfs_get_program_name (
#ifdef WFS_ANSIC
	void
#endif
)
{
	return "test_wfs_util";
}

void
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
wfs_show_progress (
#ifdef WFS_ANSIC
	const wfs_progress_type_t	type WFS_ATTR ((unused)),
	const unsigned int		percent WFS_ATTR ((unused)),
	unsigned int * const		prev_percent WFS_ATTR ((unused))
	)
#else
	type, percent, prev_percent )
	const wfs_progress_type_t	type;
	const unsigned int		percent;
	unsigned int * const		prev_percent;
#endif
{
}

void
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
fill_buffer (
#ifdef WFS_ANSIC
	unsigned long int 		pat_no WFS_ATTR ((unused)),
	unsigned char * const 		buffer WFS_ATTR ((unused)),
	const size_t 			buflen WFS_ATTR ((unused)),
	int * const			selected WFS_ATTR ((unused)),
	const wfs_fsid_t		wfs_fs WFS_ATTR ((unused)) )
#else
	pat_no,	buffer,	buflen,	selected, wfs_fs )
	unsigned long int 		pat_no WFS_ATTR ((unused));
	unsigned char * const 		buffer WFS_ATTR ((unused));
	const size_t 			buflen WFS_ATTR ((unused));
	int * const			selected WFS_ATTR ((unused));
	const wfs_fsid_t		wfs_fs WFS_ATTR ((unused));
#endif
{
}

/* ============================================================= */

#define WFS_TEST_FILESYSTEM "test-fs"
#define WFS_TEST_MOUNT_POINT "testdir"
#define WFS_TEST_LOOP_DEVICE "/dev/loop3"	/* chosen arbitrarily */

START_TEST(test_wfs_check_mounted)
{
	wfs_fsid_t wfs_fs;
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted\n");
	wfs_fs.fs_error = malloc (sizeof(wfs_errcode_t));
	if ( wfs_fs.fs_error != NULL )
	{
		wfs_fs.fsname = "/dev/sda2";
		ret = wfs_check_mounted (wfs_fs);
		free (wfs_fs.fs_error);
		ck_assert_int_eq (ret, WFS_MNTRW);
	}
	else
	{
		fail ("test_wfs_check_mounted: can't allocate memory of size %ld\n",
			sizeof(wfs_errcode_t));
	}
}
END_TEST

#ifdef WFS_TEST_CAN_MOUNT
/* Use "losetup" to detach any incorrectly attached devices */

# define WFS_TEST_ERR_SIZE 16 /*sizeof(wfs_errcode_t)*/
typedef wfs_errcode_t (*mount_check_function) (const wfs_fsid_t wfs_fs);

static wfs_errcode_t mount_and_get_result (const char * const test_name,
	int open_flags, unsigned int mount_flags, const mount_check_function mcf)
{
	wfs_fsid_t wfs_fs;
	wfs_errcode_t ret = WFS_NOTHING;
	wfs_errcode_t ret2 = WFS_NOTHING;
	int res;
	int fd_fs;
	int fd_loop;

	if ( (test_name == NULL) || (mcf == NULL) )
	{
		return WFS_BADPARAM;
	}

	sleep (1);
	fd_fs = open (WFS_TEST_FILESYSTEM, open_flags);
	if ( fd_fs < 0 )
	{
		fail ("%s: can't open test filesystem '%s': errno=%d\n",
			test_name, WFS_TEST_FILESYSTEM, errno);
	}

	fd_loop = open (WFS_TEST_LOOP_DEVICE, open_flags);
	if ( fd_loop < 0 )
	{
		close (fd_fs);
		fail ("%s: can't open loop device '%s': errno=%d\n",
			test_name, WFS_TEST_LOOP_DEVICE, errno);
	}

	/* ioctl(4, 0x4c00, 0x3) = 0
	   mount("/dev/loop1", "/mount_path", "ext2", MS_MGC_VAL|MS_RDONLY, NULL) = 0
	*/
	res = ioctl (fd_loop, LOOP_SET_FD, fd_fs);
	if ( res < 0 )
	{
		close (fd_fs);
		close (fd_loop);
		fail ("%s: can't connect test filesystem to loop device: errno=%d\n",
			test_name, errno);
	}

	res = mount (WFS_TEST_LOOP_DEVICE, WFS_TEST_MOUNT_POINT,
		"ext2", MS_MGC_VAL | mount_flags, NULL);
	if ( res == 0 )
	{
		wfs_fs.fs_error = malloc (WFS_TEST_ERR_SIZE);
		if ( wfs_fs.fs_error != NULL )
		{
			wfs_fs.fsname = WFS_TEST_LOOP_DEVICE;
			ret = (*mcf) (wfs_fs);
			wfs_fs.fsname = WFS_TEST_FILESYSTEM;
			ret2 = (*mcf) (wfs_fs);
			free (wfs_fs.fs_error);

			fsync(fd_fs);
			fsync(fd_loop);
			sync();
			res = umount (WFS_TEST_MOUNT_POINT);
			if ( res != 0 )
			{
				printf("umount(WFS_TEST_MOUNT_POINT) failed 1, errno=%d\n", errno);
			}
			close (fd_fs);
			ioctl (fd_loop, LOOP_CLR_FD, 0);
			close (fd_loop);
		}
		else
		{
			fsync(fd_fs);
			fsync(fd_loop);
			sync();
			res = umount (WFS_TEST_MOUNT_POINT);
			if ( res != 0 )
			{
				printf("umount(WFS_TEST_MOUNT_POINT) failed 2, errno=%d\n", errno);
			}
			close (fd_fs);
			ioctl (fd_loop, LOOP_CLR_FD, 0);
			close (fd_loop);
			fail ("%s: can't allocate memory of size %d\n",
				test_name, WFS_TEST_ERR_SIZE);
		}
	}
	else
	{
		close (fd_fs);
		ioctl (fd_loop, LOOP_CLR_FD, 0);
		close (fd_loop);
		fail ("%s: can't mount test filesystem: errno=%d\n",
			test_name, errno);
	}

	if ( ret != WFS_SUCCESS )
	{
		return ret;
	}
	return ret2;
}

START_TEST(test_wfs_check_mounted_ro)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_ro\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_ro", O_RDONLY,
		MS_RDONLY, &wfs_check_mounted);
	ck_assert_int_eq (ret, WFS_SUCCESS);
}
END_TEST

START_TEST(test_wfs_check_mounted_rw)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_rw\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_rw", O_RDWR,
		0, &wfs_check_mounted);
	ck_assert_int_eq (ret, WFS_MNTRW);
}
END_TEST

# ifdef WFS_EXT234
START_TEST(test_wfs_check_mounted_e2_ro)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_e2_ro\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_e2_ro", O_RDONLY,
		MS_RDONLY, &wfs_e234_chk_mount);
	ck_assert_int_eq (ret, WFS_SUCCESS);
}
END_TEST

START_TEST(test_wfs_check_mounted_e2_rw)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_e2_rw\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_e2_rw", O_RDWR,
		0, &wfs_e234_chk_mount);
	ck_assert_int_eq (ret, WFS_MNTRW);
}
END_TEST
# endif /* WFS_EXT234 */

# if (defined WFS_NTFS)
START_TEST(test_wfs_check_mounted_ntfs_ro)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_ntfs_ro\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_ntfs_ro", O_RDONLY,
		MS_RDONLY, &wfs_ntfs_chk_mount);
	ck_assert_int_eq (ret, WFS_SUCCESS);
}
END_TEST

START_TEST(test_wfs_check_mounted_ntfs_rw)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_ntfs_rw\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_ntfs_rw", O_RDWR,
		0, &wfs_ntfs_chk_mount);
	ck_assert_int_eq (ret, WFS_MNTRW);
}
END_TEST
# endif /* WFS_NTFS */

# if (defined WFS_XFS)
START_TEST(test_wfs_check_mounted_xfs_ro)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_xfs_ro\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_xfs_ro", O_RDONLY,
		MS_RDONLY, &wfs_xfs_chk_mount);
	ck_assert_int_eq (ret, WFS_SUCCESS);
}
END_TEST

START_TEST(test_wfs_check_mounted_xfs_rw)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_xfs_rw\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_xfs_rw", O_RDWR,
		0, &wfs_xfs_chk_mount);
	ck_assert_int_eq (ret, WFS_MNTRW);
}
END_TEST
# endif /* WFS_XFS */

# if (defined WFS_REISER)
START_TEST(test_wfs_check_mounted_r3_ro)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_r3_ro\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_r3_ro", O_RDONLY,
		MS_RDONLY, &wfs_reiser_chk_mount);
	ck_assert_int_eq (ret, WFS_SUCCESS);
}
END_TEST

START_TEST(test_wfs_check_mounted_r3_rw)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_r3_rw\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_r3_rw", O_RDWR,
		0, &wfs_reiser_chk_mount);
	ck_assert_int_eq (ret, WFS_MNTRW);
}
END_TEST
# endif /* WFS_REISER */

# if (defined WFS_REISER4)
START_TEST(test_wfs_check_mounted_r4_ro)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_r4_ro\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_r4_ro", O_RDONLY,
		MS_RDONLY, &wfs_r4_chk_mount);
	ck_assert_int_eq (ret, WFS_SUCCESS);
}
END_TEST

START_TEST(test_wfs_check_mounted_r4_rw)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_r4_rw\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_r4_rw", O_RDWR,
		0, &wfs_r4_chk_mount);
	ck_assert_int_eq (ret, WFS_MNTRW);
}
END_TEST
# endif /* WFS_REISER4 */

# if (defined WFS_FATFS)
START_TEST(test_wfs_check_mounted_fat_ro)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_fat_ro\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_fat_ro", O_RDONLY,
		MS_RDONLY, &wfs_fat_chk_mount);
	ck_assert_int_eq (ret, WFS_SUCCESS);
}
END_TEST

START_TEST(test_wfs_check_mounted_fat_rw)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_fat_rw\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_fat_rw", O_RDWR,
		0, &wfs_fat_chk_mount);
	ck_assert_int_eq (ret, WFS_MNTRW);
}
END_TEST
# endif /* WFS_FATFS */

# if (defined WFS_MINIXFS)
START_TEST(test_wfs_check_mounted_minix_ro)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_minix_ro\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_minix_ro", O_RDONLY,
		MS_RDONLY, &wfs_minixfs_chk_mount);
	ck_assert_int_eq (ret, WFS_SUCCESS);
}
END_TEST

START_TEST(test_wfs_check_mounted_minix_rw)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_minix_rw\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_minix_rw", O_RDWR,
		0, &wfs_minixfs_chk_mount);
	ck_assert_int_eq (ret, WFS_MNTRW);
}
END_TEST
# endif /* WFS_MINIXFS */

# if (defined WFS_JFS)
START_TEST(test_wfs_check_mounted_jfs_ro)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_jfs_ro\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_jfs_ro", O_RDONLY,
		MS_RDONLY, &wfs_jfs_chk_mount);
	ck_assert_int_eq (ret, WFS_SUCCESS);
}
END_TEST

START_TEST(test_wfs_check_mounted_jfs_rw)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_jfs_rw\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_jfs_rw", O_RDWR,
		0, &wfs_jfs_chk_mount);
	ck_assert_int_eq (ret, WFS_MNTRW);
}
END_TEST
# endif /* WFS_JFS */

# if (defined WFS_HFSP)
START_TEST(test_wfs_check_mounted_hfsp_ro)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_hfsp_ro\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_hfsp_ro", O_RDONLY,
		MS_RDONLY, &wfs_hfsp_chk_mount);
	ck_assert_int_eq (ret, WFS_SUCCESS);
}
END_TEST

START_TEST(test_wfs_check_mounted_hfsp_rw)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_hfsp_rw\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_hfsp_rw", O_RDWR,
		0, &wfs_hfsp_chk_mount);
	ck_assert_int_eq (ret, WFS_MNTRW);
}
END_TEST
# endif /* WFS_HFSP */

# if (defined WFS_OCFS)
START_TEST(test_wfs_check_mounted_ocfs_ro)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_ocfs_ro\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_ocfs_ro", O_RDONLY,
		MS_RDONLY, &wfs_ocfs_chk_mount);
	ck_assert_int_eq (ret, WFS_SUCCESS);
}
END_TEST

START_TEST(test_wfs_check_mounted_ocfs_rw)
{
	wfs_errcode_t ret;

	printf ("test_wfs_check_mounted_ocfs_rw\n");
	ret = mount_and_get_result ("test_wfs_check_mounted_ocfs_rw", O_RDWR,
		0, &wfs_ocfs_chk_mount);
	ck_assert_int_eq (ret, WFS_MNTRW);
}
END_TEST
# endif /* WFS_OCFS */

#endif /* WFS_TEST_CAN_MOUNT */

__attribute__ ((constructor))
static void setup_global(void) /* unchecked */
{
	mkdir (WFS_TEST_MOUNT_POINT, 0666);
}

/*__attribute__ ((destructor))*/
static void teardown_global(void)
{
	rmdir (WFS_TEST_MOUNT_POINT);
}

/* checked * /
static void setup_test(void)
{
}

static void teardown_test(void)
{
}
*/

static Suite * wfs_create_suite(void)
{
	Suite * s = suite_create("wfs_util");

	TCase * tests_mount = tcase_create("mount");

	tcase_add_test(tests_mount, test_wfs_check_mounted);
#ifdef WFS_TEST_CAN_MOUNT
	tcase_add_test(tests_mount, test_wfs_check_mounted_ro);
	tcase_add_test(tests_mount, test_wfs_check_mounted_rw);
# ifdef WFS_EXT234
	tcase_add_test(tests_mount, test_wfs_check_mounted_e2_ro);
	tcase_add_test(tests_mount, test_wfs_check_mounted_e2_rw);
# endif
# ifdef WFS_NTFS
	tcase_add_test(tests_mount, test_wfs_check_mounted_ntfs_ro);
	tcase_add_test(tests_mount, test_wfs_check_mounted_ntfs_rw);
# endif
# ifdef WFS_XFS
	tcase_add_test(tests_mount, test_wfs_check_mounted_xfs_ro);
	tcase_add_test(tests_mount, test_wfs_check_mounted_xfs_rw);
# endif
# ifdef WFS_REISER
	tcase_add_test(tests_mount, test_wfs_check_mounted_r3_ro);
	tcase_add_test(tests_mount, test_wfs_check_mounted_r3_rw);
# endif
# ifdef WFS_REISER4
	tcase_add_test(tests_mount, test_wfs_check_mounted_r4_ro);
	tcase_add_test(tests_mount, test_wfs_check_mounted_r4_rw);
# endif
# ifdef WFS_FATFS
	tcase_add_test(tests_mount, test_wfs_check_mounted_fat_ro);
	tcase_add_test(tests_mount, test_wfs_check_mounted_fat_rw);
# endif
# ifdef WFS_MINIXFS
	tcase_add_test(tests_mount, test_wfs_check_mounted_minix_ro);
	tcase_add_test(tests_mount, test_wfs_check_mounted_minix_rw);
# endif
# ifdef WFS_JFS
	tcase_add_test(tests_mount, test_wfs_check_mounted_jfs_ro);
	tcase_add_test(tests_mount, test_wfs_check_mounted_jfs_rw);
# endif
# ifdef WFS_HFSP
	tcase_add_test(tests_mount, test_wfs_check_mounted_hfsp_ro);
	tcase_add_test(tests_mount, test_wfs_check_mounted_hfsp_rw);
# endif
# ifdef WFS_OCFS
	tcase_add_test(tests_mount, test_wfs_check_mounted_ocfs_ro);
	tcase_add_test(tests_mount, test_wfs_check_mounted_ocfs_rw);
# endif
#endif

	/*tcase_add_checked_fixture(tests_mount, &setup_test, &teardown_test);*/
	tcase_add_unchecked_fixture(tests_mount, &setup_global, &teardown_global);

	/* set 30-second timeouts */
	tcase_set_timeout(tests_mount, 30);

	suite_add_tcase(s, tests_mount);

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
