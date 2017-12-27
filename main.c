#include <stdlib.h>
#include <stdio.h>
#include "malloc.h"
#include "minunit.h"

int main()
{
	void* ptr;
	void* ptr2;

	printf("mem_chunk_t size: %lu\n", sizeof(mem_chunk_t));
	printf("mem_block_t size: %lu\n", sizeof(mem_block_t));
	printf("page size: %d\n", getpagesize());


	int result = foo_posix_memalign(&ptr, 16, 5);

	char* ptr_c = (char*) ptr;
	ptr_c = "1234";

	printf("result : %d\n", result);
	printf("returned pointer: %lx\n", (size_t)ptr);

	// foo_mdump();

	foo_posix_memalign(&ptr, 16, 5);

	char* ptr2_c = (char*) ptr2;
	ptr2_c = "abcd";

	return 0;
}
