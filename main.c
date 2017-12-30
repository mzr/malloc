#include <stdlib.h>
#include <stdio.h>
#include "malloc.h"
#include "minunit.h"

int main()
{
	void* ptr;
	void* ptr2;
	int result;

	printf("mem_chunk_t size: %lu\n", sizeof(mem_chunk_t));
	printf("mem_block_t size: %lu\n", sizeof(mem_block_t));
	printf("page size: %d\n", getpagesize());

// 	result = foo_posix_memalign(&ptr, 16, 4);
// 	printf("result : %d\n", result);
// 	printf("returned pointer: %lx\n", (size_t)ptr);

// 	int* ptr_d = (int*) ptr;
// 	*ptr_d = 1337;
// 	// char* ptr_c = (char*) ptr;
// 	// ptr_c = "\xde\xad\xc0\xde\xee";

// foo_mdump();

// 	result = foo_posix_memalign(&ptr2, 16, 5);
// 	printf("result : %d\n", result);
// 	printf("returned pointer: %lx\n", (size_t)ptr2);

// 	char* ptr2_c = (char*) ptr2;
// 	ptr2_c = "abcd";

// 	// --------------------
// 	// issue when freeing
// foo_mdump();
// 	foo_free(ptr);
// foo_mdump();
// 	foo_free(ptr2);
// foo_mdump();


// 	void* ptr3 = foo_malloc(10234);
// foo_mdump();
// 	// foo_free(ptr3);
// // foo_mdump();

// 	void* ptr4 = foo_realloc(ptr3, 3);
// foo_mdump();
// 	foo_free(ptr4);
// foo_mdump();

	void* ptr5;
	result = foo_posix_memalign(&ptr5, 32, 19);
	printf("result : %d\n", result);
	printf("pm returned pointer: %lx\n", (size_t)ptr5);
foo_mdump();
printf("-----------\n");

	void* ptr6 = foo_realloc(ptr5, 100);
	printf("ra returned pointer: %lx\n", (size_t)ptr6);
foo_mdump();
printf("----------------\n");
	foo_free(ptr6);
	// printf("dupa\n");
foo_mdump();

	return 0;
}
