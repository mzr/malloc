#include "malloc.h"

#define DID_NOTHING 0
#define FITTED_NEW_BLOCK 1
#define EXPANDED_RIGHT_BLOCK 2

#define SHRINKED_RIGHT_BLOCK 0
#define MERGED_RIGHT_BLOCK 1
#define MOVED_DATA 2
#define ECANTEXPAND 3

#define is_power_of_two(x)     ((((x) - 1) & (x)) == 0)
#define ABS(value)  ( ((value) >= 0) ? (value) : (-(value)) )
#define _round_up_to_multiply_of(x,r) ((x) + ((r) - ((x) % (r))))
#define _pages_needed(x,r) (((x) / (r)) + (((x) % (r)) ? 1 : 0))

mem_block_t* find_free_block(size_t size);
mem_chunk_t* get_new_chunk(size_t size);

mem_block_t** get_back_boundary_tag_address(mem_block_t* block);
void set_boundary_tag_of_block(mem_block_t* block);
mem_block_t* get_back_boundary_tag_of_block(mem_block_t* block);

mem_block_t* get_left_block_addr(mem_block_t* block);
mem_block_t* get_right_block_addr(mem_block_t* block);
mem_block_t* get_block_address_from_aligned_data_pointer(void* aligned_data);

void set_block_size_and_bt(mem_block_t* block, int32_t size);

void coalescence_blocks(mem_block_t* left, mem_block_t* right);
mem_chunk_t* get_chunk_address(mem_block_t* iter_block);
int split_block_to_size(mem_block_t* block, size_t desired_size, mem_block_t** new_block);

int shrink_block(mem_block_t* block, size_t shrink_bytes);
int expand_block(mem_block_t* block, size_t expand_bytes, void** new_data_pointer, size_t new_size, void* aligned_data);

static void* _posix_memalign(size_t alignment, size_t size);
static void *_foo_realloc(void *aligned_data, size_t size);

void *foo_malloc(size_t size)
{
    void* tmp;
    int rtn = foo_posix_memalign(&tmp, sizeof(void*), size);
    return (rtn == 0 ? tmp : NULL);
}

void* foo_realloc(void* ptr, size_t size)
{
    if(size == 0){
        foo_free(ptr);
        return NULL;
    }

    if(ptr == NULL)
        return foo_malloc(size);

    return _foo_realloc(ptr, size);
}

void *foo_calloc(size_t count, size_t size)
{
    if(count == 0 || size == 0)
        return NULL;

    size_t demanded_bytes = count * size;
    void* ptr; 
    int rtn = foo_posix_memalign(&ptr, sizeof(void*), demanded_bytes);

    if(rtn == EINVAL || rtn == ENOMEM || ptr == NULL)
        return NULL;
    
    memset(ptr, 0, demanded_bytes);

    return ptr;
}

int foo_posix_memalign(void **memptr, size_t alignment, size_t data_bytes)
{
    void* aligned_memory = NULL;

    if(alignment % sizeof(void *) != 0
        || !is_power_of_two(alignment / sizeof(void *))
        || alignment == 0)
        return EINVAL;
    
    // Disallow blocks of 0 size.
    if(data_bytes <= 0){
       *memptr = NULL;
        return 0;
    }
    
    aligned_memory = _posix_memalign(alignment, data_bytes);

    if(aligned_memory == NULL)
        return ENOMEM;

    *memptr = aligned_memory;

    return 0;    
}

static void* _foo_realloc(void* aligned_data, size_t size)
{
    mem_block_t* block = get_block_address_from_aligned_data_pointer(aligned_data);

    // we have to assume that user uses everything from aligned_data to BT.
    // he may have used much less than that but we really dont know.
    // all we know is, that user now wants to use size bytes from aligned_data.
    size_t block_new_size = _round_up_to_multiply_of((size_t)aligned_data - (size_t)block->mb_data + size, sizeof(void*));
    assert(block_new_size != 0);

    if(block_new_size == ABS(block->mb_size))
        return aligned_data;

    // shrinking block
    if(block_new_size < ABS(block->mb_size)){
        // cant shrink it bellow MIN_BLOCK_SIZE
        shrink_block(block, ABS(block->mb_size) - block_new_size);
        return aligned_data;
    }

    // expand block    
    if(block_new_size > ABS(block->mb_size)){
        void* new_data_pointer = NULL;
        int rtn = expand_block(block, block_new_size - ABS(block->mb_size), &new_data_pointer, size, aligned_data);
        switch(rtn){
        case SHRINKED_RIGHT_BLOCK:  return aligned_data;
        case MERGED_RIGHT_BLOCK:    return aligned_data;
        case MOVED_DATA:            return new_data_pointer;
        case ECANTEXPAND:           return aligned_data;    // dont modify anything on fail!!!
        }
    }

    return NULL; // dumy pointer. CHANGE IT!
}

static void* _posix_memalign(size_t alignment, size_t demanded_bytes)
{
    mem_block_t* found_block = NULL;
    mem_chunk_t* new_chunk = NULL;
    mem_block_t* right_side_split_block = NULL;
    void* aligned_memory = NULL;
    size_t user_align_bytes;
    size_t total_bytes;
    size_t eight_bytes_data;

    /* Overhead needed for user alignment. mb_data is aligned due to default struct alignment */
    user_align_bytes = alignment <= MB_DATA_ALIGNMENT ? 0 : alignment - MB_DATA_ALIGNMENT;
    total_bytes = demanded_bytes + user_align_bytes;
    /* round to align boundary tag, which at nearest, aligned to sizeof(void*) 
     * address, after aligned data */
    eight_bytes_data = _round_up_to_multiply_of(total_bytes, sizeof(void*));

    // UGLY TEMPORARY SOLUTION
    eight_bytes_data = eight_bytes_data < 2*sizeof(void*) ? 2*sizeof(void*) : eight_bytes_data;        

    found_block = find_free_block(eight_bytes_data);
    
        
    /* Need to allocate new chunk */
    if(found_block == NULL){
        new_chunk = get_new_chunk(eight_bytes_data);
        /* No memory available */
        if(new_chunk == NULL)
            return NULL;

        // we dont want first block cos it is a boundary block of size 0        
        found_block = (mem_block_t*)((size_t)new_chunk->ma_first.mb_data + BT_SIZE);
    }
    // need to set aligned_memory
    if(alignment <= MB_DATA_ALIGNMENT)
        aligned_memory = (void*)&found_block->mb_data;
    else
        aligned_memory = (void**)(((size_t)(&found_block->mb_data) + user_align_bytes) & ~(alignment - 1));
    assert(found_block->mb_size > 0);
    found_block->mb_size = -found_block->mb_size;
    set_boundary_tag_of_block(found_block);

    // now block is read but not splitted
    // split when needed
    split_block_to_size(found_block, eight_bytes_data, &right_side_split_block);

    // delete allocated block from list
    LIST_REMOVE(found_block, mb_node);

    // clear bytes between mb_data and aligned_memory
    bzero(found_block->mb_data, (size_t)aligned_memory - (size_t)(found_block->mb_data));

    return aligned_memory;
}

void foo_free(void *ptr)
{
    if(ptr == NULL)
        return;
    
    // wrong pointer
    if((size_t)ptr % sizeof(void*) != 0)
        return;

    mem_block_t* block = get_block_address_from_aligned_data_pointer(ptr);
    mem_block_t* left_block = get_left_block_addr(block);
    mem_block_t* right_block = get_right_block_addr(block);

    // free current block
    block->mb_size = ABS(block->mb_size);
    set_boundary_tag_of_block(block);

    /* check whether right or left are 0 size. Then it means that they
     * are edge blocks in the chunk. Do not coalescence them. 
     * They are not coalescenceable.
     */

    /* We need to coalescence free neighbours with size > 0.
     * When at least one is coalescenceable, we dont need to walk
     * the list of blocks
     */

    // first try to coalescence right one
    // then try to coalescence left one
    // depending on which were coalescenced update list
    int32_t left_block_size = left_block->mb_size;
    int32_t right_block_size = right_block->mb_size;


    if(left_block_size > 0){
        // LEFT IS ON FREE LIST
        coalescence_blocks(left_block, block);
        block = left_block;
    }

    if(right_block_size > 0){
        // RIGHT IS ON FREE_LIST
        coalescence_blocks(block, right_block);
    }
    mem_block_t* old_right = right_block;   // ugly fix
    // check for unmap
    left_block = get_left_block_addr(block);
    right_block = get_right_block_addr(block);
    // update left and right sizes
    if(left_block->mb_size == 0 && right_block->mb_size == 0){

        mem_chunk_t* chunk = (mem_chunk_t*)((size_t)left_block - 4 * sizeof(void*));
        LIST_REMOVE(chunk, ma_node);
        munmap(chunk, chunk->size + sizeof(mem_chunk_t));
        return;
    }

    // when at least left free, no need to update list
    if(left_block_size > 0 || right_block_size > 0){
        if(left_block_size < 0){
            // right one was free
            LIST_INSERT_BEFORE(old_right,block,mb_node);
        }
        if(right_block_size > 0){
            LIST_REMOVE(old_right, mb_node);
        }
    } else {
        // find good place in list for block
        // need to know chunk
        mem_chunk_t* chunk_iter = NULL;
        LIST_FOREACH(chunk_iter, &chunk_list, ma_node){
            if((size_t)chunk_iter <= (size_t)block && (size_t)block < (size_t)chunk_iter + sizeof(mem_chunk_t) + chunk_iter->size ){
                break;
            }
        }
        assert(chunk_iter != NULL);
        mem_block_t* block_iter = NULL;
        LIST_FOREACH(block_iter, &chunk_iter->ma_freeblks, mb_node){
            if(block_iter > block){
                break;
            }
        }

        if(block_iter != NULL){
            LIST_INSERT_BEFORE(block_iter, block, mb_node);
        } else {
            LIST_INSERT_HEAD(&chunk_iter->ma_freeblks, block, mb_node);
        } 
    }

    return;    

}

void foo_mdump()
{
    int chunk_nr = 0;
    int block_nr = 0;
    mem_chunk_t* chunk;
    mem_block_t* block;
    size_t bt_points_to; 
    printf("DYNAMICALLY ALLOCATED MEMORY DUMP (ONLY FREE BLOCKS):\n");
    LIST_FOREACH(chunk, &chunk_list, ma_node){
        printf("%d\t0x%016lx\t0x%016lx\t%d\n", 
            chunk_nr++, 
            (size_t) chunk, 
            (size_t) &chunk->ma_first, 
            chunk->size);
        LIST_FOREACH(block, &chunk->ma_freeblks, mb_node){
            bt_points_to = (size_t)get_back_boundary_tag_of_block(block);
            printf("\t%d\t0x%016lx\t0x%016lx\t%d\t0x%016lx\t0x%016lx\n", 
                block_nr++, 
                (size_t) block, 
                (size_t) block->mb_data, 
                block->mb_size, 
                (size_t)get_back_boundary_tag_address(block),
                bt_points_to);
            assert(block->mb_size > 0);
            assert((size_t)block == bt_points_to);
        }
        block_nr = 0;
    }
}

/*
 * Finds free block of size at least data_size.
 * When there is no block available, returns NULL
 */
mem_block_t* find_free_block(size_t size)
{
    assert(size >= MIN_BLOCK_SIZE );
    assert(size % 8 == 0);
    mem_block_t* iter_block;
    mem_chunk_t* iter_chunk;

    LIST_FOREACH(iter_chunk, &chunk_list, ma_node){
        LIST_FOREACH(iter_block, &iter_chunk->ma_freeblks, mb_node){
            if(iter_block->mb_size >= size){
                return iter_block;
            }
            assert(iter_block->mb_size >= MIN_BLOCK_SIZE);
        }
    }

    return NULL;
}

/*
 * Allocates new chunk which has a single free 
 * block of size at least min_block_data_bytes.
 * Returns NULL on fail (mmap error, propably no memory)
 */
mem_chunk_t* get_new_chunk(size_t min_block_data_bytes)
{
    size_t needed_bytes = sizeof(mem_chunk_t) + min_block_data_bytes + 4 * sizeof(void*);
    size_t page_bytes_needed = _pages_needed(needed_bytes, PAGESIZE) * PAGESIZE;
    mem_chunk_t* new_chunk;
    mem_block_t* middle_block;
    mem_block_t* right_boundary_block;

    new_chunk = (mem_chunk_t*) mmap(NULL, page_bytes_needed, 
        PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        
    if(new_chunk == MAP_FAILED)
        return NULL;

    // init chunk metadata
    new_chunk->size = page_bytes_needed - sizeof(mem_chunk_t);
    LIST_INSERT_HEAD(&chunk_list, new_chunk, ma_node);
    
    // Init left boundary block of size 0. It is always allocated.
    set_block_size_and_bt(&new_chunk->ma_first, 0);

    // Init middle free block.
    middle_block = (mem_block_t*)((size_t)(new_chunk->ma_first.mb_data)  + BT_SIZE);
    set_block_size_and_bt(middle_block, page_bytes_needed - sizeof(mem_chunk_t) - 3 * sizeof(void*));
    LIST_INSERT_HEAD(&new_chunk->ma_freeblks, middle_block, mb_node);
    assert(middle_block->mb_size >= MIN_BLOCK_SIZE && middle_block->mb_size % 8 == 0);

    // Init right boundary block of size 0. It is always allocated.
    right_boundary_block = (mem_block_t*)((size_t)get_back_boundary_tag_address(middle_block) + BT_SIZE);
    set_block_size_and_bt(right_boundary_block, 0);

    return new_chunk;
}

/////////////////////////////////////
// BLOCK & CHUNK UTILITY FUNCTIONS //
/////////////////////////////////////

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