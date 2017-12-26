#include <stdlib.h>
#include <stdio.h>
#include "malloc.h"
#include "minunit.h"

int main()
{
	void* ptr;

	printf("mem_chunk_t size: %d\n", sizeof(mem_chunk_t));
	printf("mem_block_t size: %d\n", sizeof(mem_block_t));
	printf("page size: %d\n", getpagesize());


	int result = foo_posix_memalign(&ptr, 16, 5);

	printf("result : %d\n", result);
	printf("returned pointer: %x\n", ptr);

	foo_mdump();

	return 0;
}
