SUBDIRS = doc src po

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = config.rpath mkinstalldirs m4/ChangeLog wipefreespace.spec.in \
	m4/ax_c_check_flag.m4 wipefreespace.desktop THANKS

pack:
	echo '\input texinfo'			 > doc/wipefreespace.texi
	echo '@setfilename wipefreespace.info'	>> doc/wipefreespace.texi
	echo '@settitle wipefreespace manual'	>> doc/wipefreespace.texi
	echo '@bye'				>> doc/wipefreespace.texi
	make dist-gzip

