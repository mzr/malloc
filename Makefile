CC = gcc
CFLAGS_ = -std=gnu11 -Wall -Wextra

all: main

main: main.c malloc.so

malloc.so: malloc.c malloc.h
	$(CC) $(CFLAGS) -fPIC -shared -pthread -c malloc.c -o malloc.so 

clean:
	rm -f main *.o *~ *.so
