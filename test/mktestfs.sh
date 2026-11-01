#!/bin/sh

prefix=test-fs
mountdir=$prefix-mount

mktestfs()
{
	fsname=$1
	mkfscmd=$2
	mountcmd=$3
	size=$4
	if ( test -z $size ); then
		size=35
	fi

	echo "================= Creating $fsname"
	dd if=/dev/zero of=$fsname bs=1M count=$size
	$mkfscmd
	res=$?
	if test "x$res" = "x0"; then
		# skip HFS+, seems to hang sometimes
		if test "x$fsname" != "x$prefix-hfsp"; then
			mount -o loop $fsname $mountdir
			cp $prefix-1 $prefix-2 $prefix-3 $mountdir
			mkdir $mountdir/testdir
			cp $prefix-1 $prefix-2 $prefix-3 $mountdir/testdir
			rm -f $mountdir/testdir/$prefix-3
			sync
			sleep 1
			umount $mountdir
			echo "Waiting after releasing the loop device"
			sleep 5
		fi
	else
		rm -f $fsname
	fi
}

mkdir $mountdir
dd if=/dev/zero of=$prefix-1 bs=10 count=1
dd if=/dev/zero of=$prefix-2 bs=1024 count=1
dd if=/dev/zero of=$prefix-3 bs=4096 count=1

mktestfs "$prefix-extfs" "mkfs.ext4 -F -j $prefix-extfs" ""
mktestfs "$prefix-fat" "mkfs.vfat -F 32 $prefix-fat" ""
mktestfs "$prefix-hfsp" "hformat -l TEST $prefix-hfsp" ""
mktestfs "$prefix-jfs" "mkfs.jfs -q $prefix-jfs" ""
mktestfs "$prefix-minixfs" "mkfs.minix -2 $prefix-minixfs" ""
mktestfs "$prefix-ntfs" "mkfs.ntfs -F $prefix-ntfs" ""
mktestfs "$prefix-ocfs" "mkfs.ocfs2 -M local $prefix-ocfs" ""
mktestfs "$prefix-reiser" "mkreiserfs -f -f -s 532 $prefix-reiser" ""
mktestfs "$prefix-reiser4" "mkfs.reiser4 -y -f $prefix-reiser4" ""
mktestfs "$prefix-xfs" "mkfs.xfs $prefix-xfs" "" 300

mktestfs "$prefix" "mkfs.ext2 -F $prefix" ""

rm -fr $prefix-1 $prefix-2 $prefix-3 $mountdir
