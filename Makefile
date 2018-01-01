CC = gcc
CFLAGS = -std=gnu11 -Wall -Wextra -O3

all: malloc.o test-functional test-cases test-spec

run-all-tests: run-test-functional run-test-cases run-test-spec

run-test-functional: test-functional
	./tests/functional-test $(SEED) # might want to pass seed to randomize tests

run-test-cases: test-cases
	./tests/test-cases

run-test-spec: test-spec
	./tests/test-spec

test-spec: tests/spec_tests.c malloc.o malloc.h
	$(CC) $(CFLAGS) tests/spec_tests.c malloc.o -o ./tests/test-spec

test-cases: tests/test_cases.c malloc.o malloc.h
	$(CC) $(CFLAGS) tests/test_cases.c malloc.o -o ./tests/test-cases

test-functional: tests/functional_test.c malloc.o integrity-check.o malloc.h
	$(CC) -std=gnu11 tests/functional_test.c malloc.o integrity-check.o -o ./tests/functional-test

integrity-check.o: malloc_integrity_check.c  malloc_integrity_check.h
	$(CC) $(CFLAGS) -c malloc_integrity_check.c -o integrity-check.o

malloc.o: malloc.c malloc.h
	$(CC) $(CFLAGS) -c malloc.c -o malloc.o 

clean:
	rm -f *.o *~ *.so ./tests/test-spec ./tests/functional-test ./tests/test-cases
