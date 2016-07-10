TARGET=pbkdf2_test
CC=gcc
CCFLAGS=-c -std=c99 -Wall -Werror
LD=gcc
LDFLAGS=-lm
RM=rm -rf
OBJS=	pbkdf2.o \
	pbkdf2_test.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(LD) $(OBJS) -o $(TARGET) $(LDFLAGS)

pbkdf2.o: pbkdf2.c pbkdf2.h
	$(CC) $(CCFLAGS) pbkdf2.c -o pbkdf2.o

pbkdf2_test.o: pbkdf2_test.c
	$(CC) $(CCFLAGS) pbkdf2_test.c -o pbkdf2_test.o

clean:
	$(RM) $(OBJS)

distclean:
	$(RM) $(OBJS) $(TARGET)
