CC = gcc
CFLAGS = -std=gnu11 -Wall -Wextra -O3

all: malloc.so test-functional test-spec sha-verify

malloc: malloc.so 

run-all-tests: run-test-functional run-test-spec

run-test-functional: test-functional
	./tests/functional-test $(SEED) # might want to pass seed to randomize tests

run-test-spec: test-spec
	./tests/test-spec

test-spec: tests/spec_tests.c malloc.o malloc.h
	$(CC) -std=gnu11 -g tests/spec_tests.c malloc.o -o ./tests/test-spec

test-functional: tests/functional_tests.c malloc.o integrity-check.o malloc.h
	$(CC) -std=gnu11 -g tests/functional_tests.c malloc.o integrity-check.o -o ./tests/functional-test

integrity-check.o: malloc_integrity_check.c  malloc_integrity_check.h
	$(CC) -std=gnu11 -g -c malloc_integrity_check.c -o integrity-check.o

malloc.o: malloc.c malloc.h
	$(CC) $(CFLAGS) -c -fPIC malloc.c -o malloc.o 

malloc.so: malloc.o
	$(CC) $(CFLAGS) -shared malloc.o -o malloc.so -pthread 

# requires libssl-dev
sha-verify: malloc.o malloc.h integrity-check.o
	-$(CC) -std=gnu11 -g tests/sha_verify.c malloc.o integrity-check.o -o ./tests/sha-verify -lssl -lcrypto

run-sha-verify: 
	./tests/sha-verify $(SEED) # might want to pass seed to randomize tests

clean:
	rm -f *.o *~ *.so ./tests/test-spec ./tests/functional-test ./tests/sha-verify
