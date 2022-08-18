NAME	= e2wipefreespace
VER	= 0.5
INFO	= $(NAME).info

ifeq ($(RPMROOT),)
 RPMROOT= /usr/src/redhat
endif

ifeq ($(PREFIX),)
 PREFIX = /usr/local
endif

ifeq ($(LOCALEDIR),)
 LOCALEDIR=$(PREFIX)/share/locale
endif

CFLAGS	+=	-Wall -Wextra -Wfloat-equal -Wbad-function-cast		\
		-Wsign-compare -Wunreachable-code -Wpointer-arith	\
		-Wcast-qual -Wcast-align -Wstrict-prototypes 		\
		-Wformat-security -Wformat-nonliteral -Wnested-externs	\
		-Wshadow -Wconversion -Wdeclaration-after-statement	\
		-Wundef -Wpadded -Wredundant-decls			\
  		-pedantic -O2						\
		-DLOCALEDIR=\"$(LOCALEDIR)\" -DPACKAGE=\"$(NAME)\"	\
		#-ansi

STATICFL= -march=i386 -static

LIB	= -lext2fs -lcom_err
MKINFO	= makeinfo
RM	= rm
RMFL	= -fr
GZIP	= gzip
GZIPFL	= -f -9
LINT    = splint
LINTFL  = +posixlib #+gnuextensions
MKDIR	= mkdir
MKDIRFL	= -p
CP	= cp
CPFL	= -f
MV	= mv
INSTALLINFO	= /sbin/install-info
XGETTEXT=xgettext
XGETTEXTFL = -d $(NAME) --keyword=_ -o $(NAME).pot
MSGFMT	= msgfmt
MSGFMTFL= --check -o pl.mo
MSGINIT	= msginit
MSGINITFL = -i $(NAME).pot -o pl.po

ifeq ($(CC),)
 CC	=	gcc
endif

.SUFFIXES:
.PHONY: all clean doc lint static test rpms install translation translation2

all:	$(NAME)

$(NAME):	$(NAME).c $(NAME).h ext23.c ext23.h wrappers.c wrappers.h
	$(CC) $(CFLAGS) -o $(NAME) wrappers.c ext23.c $(NAME).c $(LIB)

doc:	$(INFO).gz $(NAME).1.gz

$(INFO).gz:	$(NAME).texi
	$(MKINFO) -o $(INFO) $(NAME).texi && $(GZIP) $(GZIPFL) $(INFO)

$(NAME).1.gz:	$(NAME).1
	$(GZIP) $(GZIPFL) -c $(NAME).1 > $(NAME).1.gz

static:		$(NAME).c
	$(RM) $(RMFL) $(NAME) $(NAME).o
	$(CC) $(CFLAGS) $(STATICFL) -o $(NAME) $(NAME).c $(LIB)

clean:
	$(RM) $(RMFL) $(NAME) $(NAME).o $(NAME).info*

lint:
	$(LINT) $(LINTFL) $(NAME).c > $(NAME).err

test:
	./$(NAME) -v -n 1 /dev/fd0 > $(NAME).log # --nowfs --nopart
	@echo Exit code: $$?

install:
	$(MKDIR) $(MKDIRFL) $(PREFIX)/bin
	$(MKDIR) $(MKDIRFL) $(PREFIX)/share/info
	$(MKDIR) $(MKDIRFL) $(PREFIX)/share/locale/pl
	$(CP) $(CPFL) $(NAME) $(PREFIX)/bin
	$(CP) $(CPFL) $(NAME).info* $(PREFIX)/share/info
	$(CP) $(CPFL) pl.mo $(PREFIX)/share/locale/pl/$(NAME).mo
	$(INSTALLINFO) $(NAME).info.gz $(PREFIX)/share/info/dir

rpms:
	$(MKDIR) $(MKDIRFL) $(RPMROOT)/BUILD
	$(MKDIR) $(MKDIRFL) $(RPMROOT)/RPMS
	$(MKDIR) $(MKDIRFL) $(RPMROOT)/SOURCES
	$(MKDIR) $(MKDIRFL) $(RPMROOT)/SPECS
	$(MKDIR) $(MKDIRFL) $(RPMROOT)/SRPMS
	$(RM) $(RMFL) $(RPMROOT)/SPECS/$(NAME).spec
	$(CP) $(CPFL) $(NAME).spec $(RPMROOT)/SPECS
	$(RM) $(RMFL) $(RPMROOT)/SOURCES/$(NAME)-$(VER).tar.gz
	$(CP) $(CPFL) $(NAME)-$(VER).tar.gz $(RPMROOT)/SOURCES
	rpmbuild -ba $(RPMROOT)/SPECS/$(NAME).spec
	$(MV) $(CPFL) $(RPMROOT)/RPMS/i386/$(NAME)*rpm .
	$(MV) $(CPFL) $(RPMROOT)/SRPMS/$(NAME)*rpm .
	$(RM) $(RMFL) $(RPMROOT)/SPECS/$(NAME).spec
	$(RM) $(RMFL) $(RPMROOT)/SOURCES/$(NAME)-$(VER).tar.gz

translation:	$(NAME).c
	$(RM) $(RMFL) pl.po $(NAME).pot
	$(XGETTEXT) $(XGETTEXTFL) $(NAME).c
	$(MSGINIT) $(MSGINITFL)

translation2:
	$(MSGFMT) $(MSGFMTFL) pl.po
