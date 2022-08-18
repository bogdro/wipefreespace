NAME	= e2wipefreespace
INFO	= $(NAME).info

GCC_FL	=	-Wall -Wextra -Wfloat-equal -Wbad-function-cast -Wsign-compare	\
  		-Wunreachable-code -Wpointer-arith -Wcast-qual -Wcast-align	\
  		-Wstrict-prototypes -Wformat-security -Wformat-nonliteral	\
  		-Wnested-externs -Wshadow -pedantic -O2 -Wconversion #-ansi

LIB	= -lext2fs -lcom_err
MKINFO	= makeinfo
RM	= rm
RMFL	= -f
GZIP	= gzip
GZIPFL	= -f -9

ifeq ($(CC),)
 CC	=	gcc
endif

.SUFFIXES:
.PHONY: all clean doc

all:	$(NAME)

$(NAME):	$(NAME).c
	$(CC) $(GCC_FL) -o $(NAME) $(NAME).c $(LIB)

doc:	$(INFO).gz

$(INFO).gz:	$(NAME).texi
	$(MKINFO) -o $(INFO) $(NAME).texi && $(GZIP) $(GZIPFL) $(INFO)

clean:
	$(RM) $(RMFL) $(NAME) $(NAME).o $(NAME).info*

