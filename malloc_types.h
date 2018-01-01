#ifndef __MALLOC_TYPES_H_INCLUDED__
#define __MALLOC_TYPES_H_INCLUDED__

#include "queue.h"
#include <stdint.h>

typedef struct mem_block {
    int32_t mb_size;                    /* mb_size > 0 => free, mb_size < 0 => allocated, w/o BT */
    union {
        LIST_ENTRY(mem_block) mb_node;  /* node on free block list, valid if block is free */
        uint64_t mb_data[0];            /* user data pointer, valid if block is allocated */
    };
} mem_block_t;                          /* mem_block_t* pointer to itself at the end of block data */

typedef struct mem_chunk {
    LIST_ENTRY(mem_chunk) ma_node;      /* node on list of all chunks */
    LIST_HEAD(, mem_block) ma_freeblks; /* list of all free blocks in the chunk */
    int32_t size;                       /* chunk size minus sizeof(mem_chunk_t) */
    mem_block_t ma_first;               /* first block in the chunk */
} mem_chunk_t;

#endif
