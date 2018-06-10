CC = gcc
CFLAGS = -std=gnu11 -Wall -Wextra -O3

all: malloc.so test-spec sha-verify

malloc: malloc.so 

run-all-tests: run-test-spec run-sha-verify

run-test-spec: test-spec
	./tests/test-spec

run-sha-verify: 
	./tests/sha-verify $(SEED) # might want to pass seed to randomize tests

test-spec: tests/spec_tests.c malloc.o malloc.h
	$(CC) -std=gnu11 -g tests/spec_tests.c malloc.o -o ./tests/test-spec

integrity-check.o: malloc_integrity_check.c  malloc_integrity_check.h
	$(CC) -std=gnu11 -g -c malloc_integrity_check.c -o integrity-check.o

malloc.o: malloc.c malloc.h
	$(CC) $(CFLAGS) -c -fPIC malloc.c -o malloc.o 

malloc.so: malloc.o
	$(CC) $(CFLAGS) -shared malloc.o -o malloc.so -pthread 

# requires libssl-dev when using SHA256 for data verification
sha-verify: integrity-check.o malloc.o malloc.h
	-$(CC) -std=gnu11 -g tests/sha_verify.c -o ./tests/sha-verify -lssl -lcrypto malloc.o integrity-check.o
	# $(CC) -std=gnu11 -g tests/sha_verify.c -o ./tests/sha-verify malloc.o integrity-check.o
	
clean:
	rm -f *.o *~ *.so ./tests/test-spec ./tests/sha-verify
