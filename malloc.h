#ifndef __MALLOC_H_INCLUDED__
#define __MALLOC_H_INCLUDED__

#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>

#include <stdio.h>              // only for foo_mdump()
#include "queue.h"

#define ARCH_BIT sizeof(size_t)

void *foo_malloc(size_t size);
void *foo_calloc(size_t count, size_t size);
void *foo_realloc(void *ptr, size_t size);
int foo_posix_memalign(void **memptr, size_t alignment, size_t size);
void foo_free(void *ptr);

void foo_mdump();

typedef struct mem_block {
    int32_t mb_size;                    /* mb_size > 0 => free, mb_size < 0 => allocated */
    union {
        LIST_ENTRY(mem_block) mb_node;  /* node on free block list, valid if block is free */
        uint64_t mb_data[0];            /* user data pointer, valid if block is allocated */
    };
} mem_block_t;

typedef struct mem_chunk {
    LIST_ENTRY(mem_chunk) ma_node;      /* node on list of all chunks */
    LIST_HEAD(, mem_block) ma_freeblks; /* list of all free blocks in the chunk */
    int32_t size;                       /* chunk size minus sizeof(mem_chunk_t) */
    mem_block_t ma_first;               /* first block in the chunk */
} mem_chunk_t;

LIST_HEAD(, mem_chunk) chunk_list;      /* list of all chunks */

#endif