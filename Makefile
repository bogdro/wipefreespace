NAME	= e2wipefreespace
INFO	= $(NAME).info

GCC_FL	=	-Wall -Wextra -Wfloat-equal -Wbad-function-cast -Wsign-compare\
  		-Wunreachable-code -pedantic -O2 -march=pentium3 \
		-Wconversion #-ansi

LIB	= -lext2fs -lcom_err
MKINFO	= makeinfo
RM	= rm
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
	$(RM) -f $(NAME) $(NAME).o $(NAME).info*

