CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -g
LDLIBS = -lm

SRCS = src/main.c src/entropy.c

fileinspect: $(SRCS)
	$(CC) $(CFLAGS) -o fileinspect $(SRCS) $(LDLIBS)

clean:
	rm -f fileinspect src/*.o

.PHONY: clean
