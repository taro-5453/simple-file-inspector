CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -g

fileinspect: src/main.c
	$(CC) $(CFLAGS) -o fileinspect src/main.c

clean:
	rm -f fileinspect src/*.o

.PHONY: clean
