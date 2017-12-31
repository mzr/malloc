CC = gcc
CFLAGS_ = -std=gnu11 -Wall -Wextra -g

all: main

run-tests: tests
	./tests/tests

run-wojtek: testy-wojtka
	./tests/testy-wojtka

run-cases: test-cases
	./tests/test-cases

tests: tests/tests.c malloc.o malloc.h
	$(CC) $(CFLAGS) -g -fno-omit-frame-pointer tests/tests.c malloc.o -o ./tests/tests

test-cases: tests/test_cases.c malloc.o malloc.h
	$(CC) $(CFLAGS) -g -fno-omit-frame-pointer tests/test_cases.c malloc.o -o ./tests/test-cases

testy-wojtka: tests/testy_wojtka.c malloc.o malloc.h
	$(CC) $(CFLAGS) -g -fno-omit-frame-pointer tests/testy_wojtka.c malloc.o -o ./tests/testy-wojtka

main: main.c malloc.o
	$(CC) $(CFLAGS) -g -fno-omit-frame-pointer main.c malloc.o -o main

malloc.o: malloc.c malloc.h
	$(CC) $(CFLAGS) -g -fno-omit-frame-pointer -c malloc.c -o malloc.o 

clean:
	rm -f main *.o *~ *.so ./tests/tests ./tests/testy-wojtka ./tests/test-cases
