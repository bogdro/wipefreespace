This is the README file for e2wipefreespace, a program for secure wiping
 of free space on ext2/3 file systems.

Author: Bogdan Drozdowski, bogdandr @ op . pl
License: GPLv2

Type 'info ./e2wipefreespace.info.gz' to get help.

Requirements for compiling:
- a gcc-compatible C compiler
- development package for the C library (like glibc-devel and glibc-headers)
- development package for the ext2 file system library, libext2fs (usually
  included in something like e2fsprogs-devel). If you don't have anything
  like this installed or available (check twice), then go to
  	http://e2fsprogs.sf.net/
  Then compile and install that package.
- the 'make' program (you may however compile it by hand, if you wish)

Type 'make' to compile the program. If you don't have or don't want to use
 'make', a simple

	cc -o e2wipefreespace e2wipefreespace.c -lext2fs -lcom_err

should do.

Type 'make doc' to compile the "info" documentation. This requires the
 'makeinfo' program (usually comes in a 'texinfo' package) and the texinfo.tex
 file (usually comes in a TeX package, like 'tetex'). The manual command is

	makeinfo e2wipefreespace.texi && gzip -f -9 e2wipefreespace.info

Type 'make static' to compile a static binary (this may be big). You can
 use the command

	cc -static -o e2wipefreespace e2wipefreespace.c -lext2fs -lcom_err

instead, if you wish.
