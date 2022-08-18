SUBDIRS = doc src po test

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = config.rpath mkinstalldirs m4/ChangeLog wipefreespace.spec.in \
	m4/ax_c_check_flag.m4 wipefreespace.desktop wipefreespace-kde4.desktop \
	THANKS patches INSTALL-WFS.txt m4/ax_check_link_flag.m4

pack:	doc/wipefreespace.info
	make dist-gzip
	tar zxf wipefreespace-@VERSION@.tar.gz
	echo '\input texinfo'			 > wipefreespace-@VERSION@/doc/wipefreespace.texi
	echo '@setfilename wipefreespace.info'	>> wipefreespace-@VERSION@/doc/wipefreespace.texi
	echo '@settitle wipefreespace manual'	>> wipefreespace-@VERSION@/doc/wipefreespace.texi
	echo '@bye'				>> wipefreespace-@VERSION@/doc/wipefreespace.texi
	tar zcf wipefreespace-@VERSION@.tar.gz wipefreespace-@VERSION@
	rm -fr wipefreespace-@VERSION@
