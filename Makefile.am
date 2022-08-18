SUBDIRS = doc src po

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = config.rpath mkinstalldirs m4/ChangeLog wipefreespace.spec.in \
	m4/ax_c_check_flag.m4 wipefreespace.desktop wipefreespace-kde4.desktop THANKS

pack:	doc/wipefreespace.info
	make dist-gzip
	mkdir -p wipefreespace-@VERSION@/doc
	echo '\input texinfo'			 > wipefreespace-@VERSION@/doc/wipefreespace.texi
	echo '@setfilename wipefreespace.info'	>> wipefreespace-@VERSION@/doc/wipefreespace.texi
	echo '@settitle wipefreespace manual'	>> wipefreespace-@VERSION@/doc/wipefreespace.texi
	echo '@bye'				>> wipefreespace-@VERSION@/doc/wipefreespace.texi
	gunzip -f wipefreespace-@VERSION@.tar.gz
	tar --delete -f wipefreespace-@VERSION@.tar wipefreespace-@VERSION@/doc/wipefreespace.texi
	tar -rf wipefreespace-@VERSION@.tar wipefreespace-@VERSION@/doc/wipefreespace.texi
	gzip -9 -f wipefreespace-@VERSION@.tar
	rm -fr wipefreespace-@VERSION@

