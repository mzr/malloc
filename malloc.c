#include "malloc.h"

void *foo_malloc(size_t size)
{

    if(!LIST_EMPTY(&chunk_list)){
        // search for a block in chunks
    } else {
        // need to allocate new chunk
        // allocate multiple of pagesize
        
    }

    return (void*) sizeof(mem_block_t);
}

void *foo_calloc(size_t count, size_t size)
{

}

void *foo_realloc(void *ptr, size_t size)
{

}

int foo_posix_memalign(void **memptr, size_t alignment, size_t size)
{

}

void foo_free(void *ptr)
{

}

void foo_mdump()
{
    int chunk_nr = 0;
    int block_nr = 0;
    mem_chunk_t* chunk;
    mem_block_t* block;
    LIST_FOREACH(chunk, &chunk_list, ma_node){
        // chunk_nr, address, size as whole size - sizeof(mem_chunk_t)
        printf("0x%016x\t0x%016x\t0x%016x\n", 
            chunk_nr++, (void*) chunk, chunk->size);

        LIST_FOREACH(block, &chunk->ma_freeblks, mb_node){
            // block_nr, address, size as mb_data size
            printf("\t0x%016x\t0x%016x\t0x%016x\n", 
                block_nr++, (void*) block, block->mb_size);
        }

        block_nr = 0;
    }
}