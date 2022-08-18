NAME	= e2wipefreespace
VER	= 0.4
INFO	= $(NAME).info

CFLAGS	+=	-Wall -Wextra -Wfloat-equal -Wbad-function-cast		\
		-Wsign-compare -Wunreachable-code -Wpointer-arith	\
		-Wcast-qual -Wcast-align -Wstrict-prototypes 		\
		-Wformat-security -Wformat-nonliteral -Wnested-externs	\
		-Wshadow -Wconversion -Wdeclaration-after-statement	\
		-Wundef -Wpadded -Wredundant-decls			\
  		-pedantic -O2 -s #-ansi

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

ifeq ($(RPMROOT),)
 RPMROOT= /usr/src/redhat
endif

ifeq ($(PREFIX),)
 PREFIX = /usr/local
endif

ifeq ($(CC),)
 CC	=	gcc
endif

.SUFFIXES:
.PHONY: all clean doc lint static test rpms install

all:	$(NAME)

$(NAME):	$(NAME).c
	$(CC) $(CFLAGS) -o $(NAME) $(NAME).c $(LIB)

doc:	$(INFO).gz

$(INFO).gz:	$(NAME).texi
	$(MKINFO) -o $(INFO) $(NAME).texi && $(GZIP) $(GZIPFL) $(INFO)

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
	@$(MKDIR) $(MKDIRFL) $(PREFIX)/bin
	@$(MKDIR) $(MKDIRFL) $(PREFIX)/share/info
	@$(CP) $(CPFL) $(NAME) $(PREFIX)/bin
	@$(CP) $(CPFL) $(NAME).info* $(PREFIX)/share/info

rpms:
	@$(MKDIR) $(MKDIRFL) $(RPMROOT)/BUILD
	@$(MKDIR) $(MKDIRFL) $(RPMROOT)/RPMS
	@$(MKDIR) $(MKDIRFL) $(RPMROOT)/SOURCES
	@$(MKDIR) $(MKDIRFL) $(RPMROOT)/SPECS
	@$(MKDIR) $(MKDIRFL) $(RPMROOT)/SRPMS
	@$(RM) $(RMFL) $(RPMROOT)/SPECS/$(NAME).spec
	@$(CP) $(CPFL) $(NAME).spec $(RPMROOT)/SPECS
	@$(RM) $(RMFL) $(RPMROOT)/SOURCES/$(NAME)-$(VER).tar.gz
	@$(CP) $(CPFL) $(NAME)-$(VER).tar.gz $(RPMROOT)/SOURCES
	rpmbuild -ba $(RPMROOT)/SPECS/$(NAME).spec
	@$(MV) $(CPFL) $(RPMROOT)/RPMS/i386/$(NAME)*rpm .
	@$(MV) $(CPFL) $(RPMROOT)/SRPMS/$(NAME)*rpm .

