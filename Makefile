CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -g
LDLIBS = -lm

SRCS = src/main.c src/entropy.c src/filetype.c src/strings.c src/ioc.c

fileinspect: $(SRCS)
	$(CC) $(CFLAGS) -o fileinspect $(SRCS) $(LDLIBS)

clean:
	rm -f fileinspect src/*.o

.PHONY: clean
