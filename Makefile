CC = gcc
CFLAGS_ = -std=gnu11 -Wall -Wextra

all: main

main: main.c malloc.o
	$(CC) $(CFLAGS) -g main.c malloc.o -o main

malloc.o: malloc.c malloc.h
	$(CC) $(CFLAGS) -g -c malloc.c -o malloc.o 

clean:
	rm -f main *.o *~ *.so
