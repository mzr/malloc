CC = gcc
CFLAGS_ = -std=gnu11 -Wall -Wextra

all: main

main: main.c malloc.o

malloc.o: malloc.c malloc.h
	$(CC) $(CFLAGS) -pthread -c malloc.c -o malloc.o 

clean:
	rm -f main *.o *~ 
