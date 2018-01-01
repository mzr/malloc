#include "malloc_types.h"
#include "block_utils.h"
#include <stdlib.h>
#include "queue.h"

int split_block_to_size(mem_block_t* block, size_t desired_size, mem_block_t** new_block)
{
    assert(desired_size % 8 == 0);

    if(ABS(block->mb_size) == desired_size)
        return 0;

    size_t available_space_for_new_block_with_its_header = ABS(block->mb_size) - ABS(desired_size) - BT_SIZE;
    
    // <= OR <. blocks of 0 size? NOPE
    // < doesnt generate blocks of 0 size. because the new block
    // looks like: SIZE,PREV,NEXT,BT. It's size is 16.
    // thats smallest possible block
    if(available_space_for_new_block_with_its_header < sizeof(mem_block_t)){
        return 0;
    }

    size_t new_block_size = available_space_for_new_block_with_its_header - sizeof(void*);

    *new_block = (mem_block_t*)((size_t)block->mb_data + desired_size + BT_SIZE);

    // update block
    block->mb_size = -ABS(desired_size);
    set_boundary_tag_of_block(block);

    // set new blocks data
    (*new_block)->mb_size = new_block_size;
    set_boundary_tag_of_block(*new_block);

    assert(new_block_size % 8 == 0);

    // add new block on list
    LIST_INSERT_AFTER(block, *new_block, mb_node);

    return 1;
}

void coalescence_blocks(mem_block_t* left, mem_block_t* right)
{
    set_block_size_and_bt(left, left->mb_size + right->mb_size + 2 * sizeof(void*));
}

mem_block_t* get_left_block_addr(mem_block_t* block)
{
    return *((mem_block_t**)((size_t)block - BT_SIZE));
}

mem_block_t* get_right_block_addr(mem_block_t* block)
{
    return (mem_block_t*)((size_t)get_back_boundary_tag_address(block) + BT_SIZE);
}

mem_block_t* get_block_address_from_aligned_data_pointer(void* aligned_data)
{
    // Bytes between mb_data and aligned_mb_data are 0.
    // Last (and first) non zero field in allocated block of mb_block_t structure
    // is block->mb_size. It is non-zero. We need to find it.

    aligned_data = (void*)((size_t)aligned_data - sizeof(void*));
    while(*(int64_t*)aligned_data == 0){
        aligned_data = (void*)((size_t)aligned_data - sizeof(void*));
    }
    return (mem_block_t*)aligned_data;
}

mem_block_t** get_back_boundary_tag_address(mem_block_t* block)
{
    return (mem_block_t**)((size_t)block->mb_data + (size_t)ABS(block->mb_size));
}

void set_boundary_tag_of_block(mem_block_t* block)
{
    mem_block_t** bt_address = get_back_boundary_tag_address(block);
    *bt_address = block;
}

void set_block_size_and_bt(mem_block_t* block, int32_t size)
{
    block->mb_size = size;
    set_boundary_tag_of_block(block);
}

mem_block_t* get_back_boundary_tag_of_block(mem_block_t* block)
{
    return *get_back_boundary_tag_address(block);
}

mem_chunk_t* get_chunk_address(mem_block_t* iter_block)
{
    if(iter_block->mb_size == 0)
        goto there;
    do{
        iter_block = get_left_block_addr(iter_block);
    }while(iter_block->mb_size != 0);
there:
    return (mem_chunk_t*)((size_t)iter_block - 4*sizeof(void*));
}

int expand_block(mem_block_t* block, size_t expand_bytes, void** new_data_pointer, size_t new_size, void* aligned_data)
{
    mem_block_t* right_block = get_right_block_addr(block);
    
    // right one is free
    if(right_block->mb_size > 0){
        // shrink right-one
        if(right_block->mb_size - (int32_t)expand_bytes >= (int32_t)sizeof(mem_block_t)){
            mem_block_t* new_right_block = (mem_block_t*)((size_t)right_block + expand_bytes);

            mem_block_t temp_block;
            memcpy(&temp_block, right_block, sizeof(mem_block_t));
            
            LIST_REPLACE(&temp_block, new_right_block, mb_node);

            new_right_block->mb_size = right_block->mb_size - expand_bytes; 
            set_boundary_tag_of_block(new_right_block);

            block->mb_size = -(ABS(block->mb_size) + expand_bytes);
            set_boundary_tag_of_block(block);

            goto shrinked_right_block_exit;
        } else{
            // check whether data fits in merged blocks
            if(ABS(block->mb_size) + expand_bytes <= ABS(block->mb_size) + ABS(right_block->mb_size) + 2 * sizeof(void*)){
                LIST_REMOVE(right_block, mb_node);
                block->mb_size = -(ABS(block->mb_size) + ABS(right_block->mb_size) + 2 * sizeof(void*));
                set_boundary_tag_of_block(block);

                goto merged_right_block_exit;
            } else {
                goto move_data;
            }
        }
    // right one is allocated
    } else {
        move_data:
        *new_data_pointer = foo_malloc(new_size);
        if(*new_data_pointer != NULL){
            mem_block_t* block_addr = get_block_address_from_aligned_data_pointer(aligned_data);
            size_t bytes_to_copy = ABS(block_addr->mb_size) - ((size_t)aligned_data - (size_t)block->mb_data);
            memcpy(*new_data_pointer, aligned_data, bytes_to_copy);
            foo_free(aligned_data);
            goto moved_data_exit;
        } else {
            goto error_exit;
        }

    }

    assert(1 == 0);
    shrinked_right_block_exit:      return SHRINKED_RIGHT_BLOCK;
    merged_right_block_exit:        return MERGED_RIGHT_BLOCK;
    moved_data_exit:                return MOVED_DATA;
    error_exit:                     return ECANTEXPAND;
}

int shrink_block(mem_block_t* block, size_t shrink_bytes)
{
    // block may be allocated
    assert(shrink_bytes % 8 == 0);
    assert(shrink_bytes >= sizeof(void*));

    mem_block_t* right_block;

    // avoid too much shrinking
    if(ABS(block->mb_size) - shrink_bytes < MIN_BLOCK_SIZE)
        shrink_bytes -= MIN_BLOCK_SIZE - (ABS(block->mb_size) - shrink_bytes);

    right_block = get_right_block_addr(block);

    // left-expand right_block by shrink_bytes
    if(right_block->mb_size > 0){
        block->mb_size =  -(ABS(block->mb_size) - shrink_bytes);
        set_boundary_tag_of_block(block);

        mem_block_t* new_right_block = (mem_block_t*)((size_t)right_block - shrink_bytes);
        new_right_block->mb_size = right_block->mb_size + shrink_bytes;
        set_boundary_tag_of_block(new_right_block);

        mem_block_t temp_block;
        memcpy(&temp_block, right_block, sizeof(mem_block_t));

        LIST_REPLACE(&temp_block, new_right_block, mb_node);

        goto expanded_right_block_exit;
    } else {
        //right_block is allocated
        // check if we can put a new free block between right_block and block
        if(shrink_bytes >= sizeof(mem_block_t) + BT_SIZE){
            block->mb_size = -(ABS(block->mb_size) - shrink_bytes);
            set_boundary_tag_of_block(block);

            void* bt_address = get_back_boundary_tag_address(block);
            mem_block_t* new_block = (mem_block_t*)((size_t)bt_address + sizeof(void*));
            new_block->mb_size = shrink_bytes - 2 * sizeof(void*);
            set_boundary_tag_of_block(new_block);

            mem_chunk_t* _chunk_addr = get_chunk_address(block);
            mem_block_t* _block_iter = NULL;
            LIST_FOREACH(_block_iter, &_chunk_addr->ma_freeblks, mb_node){
                if(_block_iter > new_block){
                    break;
                }
            }

            if(_block_iter != NULL){
                LIST_INSERT_BEFORE(_block_iter, new_block, mb_node);
            } else {
                LIST_INSERT_HEAD(&_chunk_addr->ma_freeblks, new_block, mb_node);
            } 

            goto fitted_new_block_exit;

        } else {
            goto did_nothing_exit;
        }
    }

    assert(1 == 0);
    did_nothing_exit:            return DID_NOTHING;
    fitted_new_block_exit:       return FITTED_NEW_BLOCK;
    expanded_right_block_exit:   return EXPANDED_RIGHT_BLOCK;
}
