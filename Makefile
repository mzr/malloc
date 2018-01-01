CC = gcc
CFLAGS_ = -std=gnu11 -Wall -Wextra -g

all: main

run-tests: tests
	./tests/tests

run-test-functional: test-functional
	./tests/functional-test

run-cases: test-cases
	./tests/test-cases

tests: tests/tests.c malloc.o malloc.h
	$(CC) $(CFLAGS) -g -fno-omit-frame-pointer tests/tests.c malloc.o -o ./tests/tests

test-cases: tests/test_cases.c malloc.o malloc.h
	$(CC) $(CFLAGS) -g -fno-omit-frame-pointer tests/test_cases.c malloc.o -o ./tests/test-cases

test-functional: tests/functional_test.c malloc.o integrity-check.o malloc.h
	$(CC) $(CFLAGS) -g -fno-omit-frame-pointer tests/functional_test.c malloc.o integrity-check.o -o ./tests/functional-test

integrity-check.o: malloc_integrity_check.c  malloc_integrity_check.h
	$(CC) $(CFLAGS) -g -c malloc_integrity_check.c -o integrity-check.o

main: main.c malloc.o
	$(CC) $(CFLAGS) -g -fno-omit-frame-pointer main.c malloc.o -o main

malloc.o: malloc.c malloc.h
	$(CC) $(CFLAGS) -g -fno-omit-frame-pointer -c malloc.c -o malloc.o 

clean:
	rm -f main *.o *~ *.so ./tests/tests ./tests/functional-test ./tests/test-cases
