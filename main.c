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

	void* ptr1 = foo_malloc(10);
foo_mdump();
	void* ptr2 = foo_malloc(15);
foo_mdump();
	void* ptr3 = foo_malloc(2);
foo_mdump();
	foo_free(ptr1);
foo_mdump();

	return 0;
}
