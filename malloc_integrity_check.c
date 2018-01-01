#include <stdlib.h>
#include <assert.h>
#include "malloc_integrity_check.h"

#define ABS(value)  ( ((value) >= 0) ? (value) : (-(value)) )

extern LIST_HEAD(, mem_chunk) chunk_list;
extern mem_block_t* get_back_boundary_tag_of_block(mem_block_t* block);
extern mem_block_t** get_back_boundary_tag_address(mem_block_t* block);
extern mem_block_t* get_right_block_addr(mem_block_t* block);

void walk_the_chunk(mem_chunk_t* chunk)
{
    mem_block_t* iter = &chunk->ma_first;
    int block_number = 0;

    assert(iter->mb_size == 0);
    assert((size_t)iter == (size_t)get_back_boundary_tag_of_block(iter));
    assert((size_t)iter->mb_data + ABS(iter->mb_size) == (size_t)get_back_boundary_tag_address(iter));

    iter = get_right_block_addr(iter);
    block_number++;
    do{
        assert(ABS(iter->mb_size) >= (int32_t)MIN_BLOCK_SIZE);
        assert(ABS(iter->mb_size) % 8 == 0);
        assert((size_t)iter == (size_t)get_back_boundary_tag_of_block(iter));
        assert((size_t)iter->mb_data + ABS(iter->mb_size) == (size_t)get_back_boundary_tag_address(iter));

        iter = get_right_block_addr(iter);
        block_number++;
    } while(iter->mb_size != 0);

    assert(iter->mb_size == 0);
    assert((size_t)iter == (size_t)get_back_boundary_tag_of_block(iter));
    assert((size_t)iter->mb_data + ABS(iter->mb_size) == (size_t)get_back_boundary_tag_address(iter));
    assert((size_t)iter + sizeof(void*) == (size_t)chunk + (size_t)chunk->size + sizeof(mem_chunk_t) - sizeof(void*));
}

void check_integrity(){
    mem_chunk_t* chunk;
    int i = 0;
    LIST_FOREACH(chunk, &chunk_list, ma_node){
        walk_the_chunk(chunk);
        i++;
    }
}