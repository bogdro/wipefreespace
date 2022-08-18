This is the README file for e2wipefreespace, a program for secure wiping
 of free space on ext2/3 file systems.

Author: Bogdan Drozdowski, bogdandr @ op . pl
License: GPLv2

Requirements:
- a gcc-compatible C compiler
- development package for the C library (like glibc-devel and glibc-headers)
- development package for the ext2 file system library, libext2fs (usually
  included in something like e2fsprogs-devel). If you don't have anything
  like this (check twice), then go to http://e2fsprogs.sf.net/ and compile
  and install that package.
- the 'make' program (you may however compile it by hand, if you wish)

Type 'make' to compile the program.

Type 'make doc' to compile the info documentation. This requires the
 'makeinfo' program (usually comes in a 'texinfo' package) and the texinfo.tex
 file (usually comes in a TeX package, like 'tetex').

