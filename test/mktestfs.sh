#!/bin/sh

mktestfs()
{
	fsname=$1
	mkfscmd=$2
	size=$3
	[[ -z $size ]] && size=35
	echo "================= Creating $fsname"
	dd if=/dev/zero of=$fsname bs=1M count=$size
	$mkfscmd
}

mktestfs 'test-fs-extfs' 'mkfs.ext4 -F -j test-fs-extfs'
mktestfs 'test-fs-fat' 'mkfs.vfat -F 32 test-fs-fat'
mktestfs 'test-fs-hfsp' 'hformat -l "TEST" test-fs-hfsp'
mktestfs 'test-fs-jfs' 'mkfs.jfs -q test-fs-jfs'
mktestfs 'test-fs-minixfs' 'mkfs.minix -2 test-fs-minixfs'
mktestfs 'test-fs-ntfs' 'mkfs.ntfs -F test-fs-ntfs'
mktestfs 'test-fs-ocfs' 'mkfs.ocfs2 -M local test-fs-ocfs'
mktestfs 'test-fs-reiser' 'mkreiserfs -f -f -s 532 test-fs-reiser'
mktestfs 'test-fs-reiser4' 'mkfs.reiser4 -y -f test-fs-reiser4'
mktestfs 'test-fs-xfs' 'mkfs.xfs test-fs-xfs' 300

mktestfs 'test-fs' 'mkfs.ext2 -F test-fs'
