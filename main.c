#include <stdlib.h>
#include <stdio.h>
#include "malloc.h"
#include "minunit.h"

int main()
{
	int result;

	printf("mem_chunk_t size: %lu\n", sizeof(mem_chunk_t));
	printf("mem_block_t size: %lu\n", sizeof(mem_block_t));
	printf("page size: %d\n", getpagesize());

	foo_free(foo_malloc(10));


	return 0;
}
