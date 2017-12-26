#include <stdlib.h>
#include <stdio.h>
#include "malloc.h"
#include "minunit.h"

int main()
{
	void* ptr;

	printf("mem_chunk_t size: %lud\n", sizeof(mem_chunk_t));
	printf("mem_block_t size: %lud\n", sizeof(mem_block_t));
	printf("page size: %d\n", getpagesize());


	int result = foo_posix_memalign(&ptr, 16, 5);

	printf("result : %d\n", result);
	printf("returned pointer: %lux\n", (size_t)ptr);

	foo_mdump();

	return 0;
}
