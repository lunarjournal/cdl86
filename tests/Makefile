IDIR=../
CC=gcc
CFLAGS=-I$(IDIR)
CFILES_CDL=../cdl.c

all: basic_jmp basic_swbp

basic_jmp: basic_jmp.c
	$(CC) $(CFLAGS) basic_jmp.c $(CFILES_CDL) -o basic_jmp
basic_swbp: basic_swbp.c
	$(CC) $(CFLAGS) basic_swbp.c $(CFILES_CDL) -o basic_swbp

.PHONY: clean
clean:
	rm -f basic_jmp
	rm -f basic_swbp
