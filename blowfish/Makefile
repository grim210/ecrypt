TARGET=blowfish
TEST=bf_test
CC=gcc
CCFLAGS=-c -std=c99 -Wall -Werror
LD=gcc
LDFLAGS=-lm
RM=rm -rf
OBJS=	blowfish.o

all: $(TEST)

$(TEST): $(OBJS) blowfish_test.o
	$(LD) $(OBJS) blowfish_test.o -o $(TEST) $(LDFLAGS)

blowfish.o: blowfish.c blowfish.h
	$(CC) $(CCFLAGS) blowfish.c -o blowfish.o

blowfish_test.o: blowfish_test.c
	$(CC) $(CCFLAGS) blowfish_test.c -o blowfish_test.o

clean:
	$(RM) $(OBJS) *o

distclean:
	$(RM) $(OBJS) *o $(TARGET) $(TEST)

