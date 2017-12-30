CC = gcc
CFLAGS_ = -std=gnu11 -Wall -Wextra

all: main

run-tests: tests
	./tests/tests

run-wojtek: testy-wojtka
	./tests/testy-wojtka

tests: tests/tests.c malloc.o malloc.h
	$(CC) $(CFLAGS) -g tests/tests.c malloc.o -o ./tests/tests

testy-wojtka: tests/testy_wojtka.c malloc.o malloc.h
	$(CC) $(CFLAGS) -g tests/testy_wojtka.c malloc.o -o ./tests/testy-wojtka

main: main.c malloc.o
	$(CC) $(CFLAGS) -g main.c malloc.o -o main

malloc.o: malloc.c malloc.h
	$(CC) $(CFLAGS) -g -c malloc.c -o malloc.o 

clean:
	rm -f main *.o *~ *.so ./tests/tests ./tests/testy-wojtka
