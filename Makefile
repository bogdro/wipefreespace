NAME	= e2wipefreespace
INFO	= $(NAME).info

GCC_FL	=	-Wall -Wextra -Wfloat-equal -Wbad-function-cast		\
		-Wsign-compare -Wunreachable-code -Wpointer-arith	\
		-Wcast-qual -Wcast-align -Wstrict-prototypes 		\
		-Wformat-security -Wformat-nonliteral -Wnested-externs	\
		-Wshadow -Wconversion -Wdeclaration-after-statement	\
		-Wundef -Wpadded -Wredundant-decls			\
  		-pedantic -O2 -s #-ansi

LIB	= -lext2fs -lcom_err
MKINFO	= makeinfo
RM	= rm
RMFL	= -f
GZIP	= gzip
GZIPFL	= -f -9
LINT    = splint
LINTFL  = +posixlib #+gnuextensions

ifeq ($(CC),)
 CC	=	gcc
endif

.SUFFIXES:
.PHONY: all clean doc lint static

all:	$(NAME)

$(NAME):	$(NAME).c
	$(CC) $(GCC_FL) -o $(NAME) $(NAME).c $(LIB)

doc:	$(INFO).gz

$(INFO).gz:	$(NAME).texi
	$(MKINFO) -o $(INFO) $(NAME).texi && $(GZIP) $(GZIPFL) $(INFO)

clean:
	$(RM) $(RMFL) $(NAME) $(NAME).o $(NAME).info*

lint:
	$(LINT) $(LINTFL) $(NAME).c > $(NAME).err

static:		$(NAME).c
	$(RM) $(RMFL) $(NAME) $(NAME).o
	$(CC) $(GCC_FL) -static -o $(NAME) $(NAME).c $(LIB)

