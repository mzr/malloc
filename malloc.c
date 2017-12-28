#include "malloc.h"

#define is_power_of_two(x)     ((((x) - 1) & (x)) == 0)
#define MB_DATA_ALIGNMENT 8
#define WORD (sizeof(void*))
#define BT_SIZE (sizeof(void*))
#define PAGESIZE (getpagesize())
#define BT_ALLOCATED 1
#define BT_FREE 0
#define ABS(value)  ( (value) >=0 ? (value) : -(value) )

static mem_block_t* find_free_block(size_t size);
static mem_chunk_t* get_new_chunk(size_t size);
static void* _posix_memalign(size_t alignment, size_t size);
static size_t _pages_needed(size_t x, size_t r);
static int set_boundary_tag_of_block(mem_block_t* block, size_t is_allocated);
static size_t round_up_to_multiply_of(size_t x, size_t r);
static mem_block_t* get_back_boundary_tag_of_block(mem_block_t* block, size_t* is_allocated);
static int split_block_to_size(mem_block_t* block, size_t desired_size, mem_block_t** new_block);

static int set_boundary_tag_of_block(mem_block_t* block, size_t is_allocated)
{
    size_t bt_address = (size_t) block->mb_data + (size_t) ABS(block->mb_size);
    *((mem_block_t**) bt_address) = (mem_block_t*)(size_t)((size_t)block | is_allocated);
    return 0;
}

static mem_block_t* get_back_boundary_tag_of_block(mem_block_t* block, size_t* is_allocated)
{
    size_t bt_address = (size_t) ABS(block->mb_size) + (size_t) block->mb_data;
    if(is_allocated != NULL)
        *is_allocated = (size_t)(*((mem_block_t**)bt_address)) & BT_ALLOCATED;
    return (mem_block_t*)((size_t)(*((mem_block_t**)bt_address)) & 0xfffffffffffffffe);
} 

static size_t _pages_needed(size_t x, size_t r)
{
    return x / r + (x % r ? 1 : 0);
}

static size_t round_up_to_multiply_of(size_t x, size_t r)
{
    return x + (r - (x % r));
}

void *foo_malloc(size_t size)
{

}

void *foo_calloc(size_t count, size_t size)
{

}

void *foo_realloc(void *ptr, size_t size)
{

}
/*
 * Memory structures data dump. 
 * Format:
 * chunk_no   chunk_address   first_block_address   chunk_size
 *    block_no   block_address   mb_data_address   block_size   is_allocated
 *    block_no   block_address   mb_data_address   block_size   is_allocated
 *    block_no   block_address   mb_data_address   block_size   is_allocated
 * chunk_no   chunk_address   first_block_address   chunk_size
 *    block_no   block_address   mb_data_address   block_size   is_allocated
 *    block_no   block_address   mb_data_address   block_size   is_allocated
 */
void foo_mdump()
{
    int chunk_nr = 0;
    int block_nr = 0;
    mem_chunk_t* chunk;
    mem_block_t* block;
    size_t is_allocated;
    size_t bt_points_to; 
    printf("DYNAMICALLY ALLOCATED MEMORY DUMP (ONLY FREE BLOCKS):\n");
    LIST_FOREACH(chunk, &chunk_list, ma_node){
        printf("%d\t0x%016lx\t0x%016lx\t%d\n", 
            chunk_nr++, (size_t) chunk, (size_t) &chunk->ma_first, chunk->size);
        LIST_FOREACH(block, &chunk->ma_freeblks, mb_node){
            // LIST BT_POINTS_TO
            bt_points_to = (size_t)get_back_boundary_tag_of_block(block, &is_allocated);
            printf("\t%d\t0x%016lx\t0x%016lx\t%d\t%lu\n", 
                block_nr++, 
                (size_t) block, 
                (size_t) block->mb_data, 
                block->mb_size, 
                is_allocated);
        }
        block_nr = 0;
    }
}

/*
 * Finds free block of size at least data_size.
 * When there is no block available, returns NULL
 */
static mem_block_t* find_free_block(size_t data_size)
{
    mem_block_t* iter_block;
    mem_chunk_t* iter_chunk;

    LIST_FOREACH(iter_chunk, &chunk_list, ma_node){
        LIST_FOREACH(iter_block, &iter_chunk->ma_freeblks, mb_node){
            if(iter_block->mb_size >= data_size){
                return iter_block;
            }
        }
    }

    return NULL;
}

void foo_free(void *ptr)
{
    if(ptr == NULL)
        return;
    
    // wrong pointer
    if((size_t)ptr % sizeof(void*) != 0)
        return;
    void* iter_ptr = ptr;
    printf("iter_ptr: 0x%016lx, iter_ptr_val: %d\n", (size_t)iter_ptr, *((int32_t*)iter_ptr));
    iter_ptr = (void*)((size_t)ptr - sizeof(void*));
    printf("iter_ptr: 0x%016lx, iter_ptr_val: %d\n", (size_t)iter_ptr, *((int32_t*)iter_ptr));
    while(*(int32_t*)iter_ptr == 0){
        printf("loop. iter_ptr: 0x%016lx, iter_ptr_val: %d\n", (size_t)iter_ptr, *((int32_t*)iter_ptr));
        iter_ptr = (void*)((size_t)iter_ptr - sizeof(void*));
    }
printf("iter_ptr: 0x%016lx, iter_ptr_val: %d\n", (size_t)iter_ptr, *((int32_t*)iter_ptr));
    // now iter_ptr should point to block.
    mem_block_t* block = (mem_block_t*)iter_ptr;
    mem_block_t** bt_address = (mem_block_t**)((size_t)block - BT_SIZE);
printf("bt_address: 0x%016lx, bt_val: 0x%016lx\n", (size_t)(bt_address), (size_t)*bt_address);
    mem_block_t* left_block = (mem_block_t*)(((size_t)(*bt_address)) & 0xfffffffffffffffe);
    mem_block_t* right_block = (mem_block_t*)((size_t)block->mb_data + ABS(block->mb_size) + BT_SIZE);
printf("left_addr: 0x%016lx, middle_addr: 0x%016lx, right_addr: 0x%016lx\n", (size_t)left_block, (size_t)block, (size_t)right_block);
    // free current block
    block->mb_size = ABS(block->mb_size);
    set_boundary_tag_of_block(block, BT_FREE);
// foo_mdump();


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
    int is_left_free = left_block->mb_size > 0 ? 1 : 0;
    int is_right_free = right_block->mb_size > 0 ? 1 : 0;

    if(is_left_free){
        printf("block on left is free\n");
        // it is on FREE_LIST
        left_block->mb_size = left_block->mb_size + block->mb_size + 2 * sizeof(void*);
        set_boundary_tag_of_block(left_block, BT_FREE);
    }

    if(is_right_free){
        printf("block on right is free");
        // is on FREE_LIST
        left_block->mb_size = left_block->mb_size + right_block->mb_size + 2 * sizeof(void*);
        set_boundary_tag_of_block(left_block, BT_FREE);
    }

    // when at least left free, no need to update list
    if(is_left_free || is_right_free){
        if(!is_left_free){
            LIST_INSERT_BEFORE(right_block, block, mb_node);
        }
        if(is_right_free){
            LIST_REMOVE(right_block, mb_node);
        }
        // what if both free? -> unmap
        // even when one of them is free still we want to unmap because of 
        // boundary blocks
    } else {
        // find good place in list for block
        // need to know chunk
        mem_chunk_t* chunk_iter;
        LIST_FOREACH(chunk_iter, &chunk_list, ma_node){
            if(chunk_iter <= block && block < chunk_iter + sizeof(mem_chunk_t) + chunk_iter->size ){
                break;
            }
        }
        mem_block_t* block_iter = NULL;
        LIST_FOREACH(block_iter, &chunk_iter->ma_freeblks, mb_node){
            if(block_iter > block){
                break;
            }
        }

        if(block_iter != NULL){
            LIST_INSERT_BEFORE(block_iter, block, mb_node);
        } else {
            // need to unmap
            LIST_REMOVE(chunk_iter, ma_node);
            munmap(chunk_iter, chunk_iter->size + sizeof(mem_chunk_t));
        }
    }

    return;    
}

/*
 * Allocates new chunk which has a single free 
 * block of size at least min_block_data_bytes.
 * Returns NULL on fail (mmap error, propably no memory)
 */
static mem_chunk_t* get_new_chunk(size_t min_block_data_bytes)
{
    size_t needed_bytes = sizeof(mem_chunk_t) + min_block_data_bytes + BT_SIZE;
    size_t pages_needed = _pages_needed(needed_bytes, PAGESIZE);
    size_t page_bytes_needed = pages_needed * PAGESIZE;
    mem_chunk_t* new_chunk;

    new_chunk = (mem_chunk_t*) mmap(NULL, page_bytes_needed, 
        PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        
    if(new_chunk == MAP_FAILED)
        return NULL;

    // init chunk
    new_chunk->size = page_bytes_needed - sizeof(mem_chunk_t);
    LIST_INSERT_HEAD(&chunk_list, new_chunk, ma_node);
    
    // init first boundary block of 0 size. it is always allocated
    new_chunk->ma_first.mb_size = 0;
    set_boundary_tag_of_block(&new_chunk->ma_first, BT_ALLOCATED);

    // init middle free block
    mem_block_t* middle_block = NULL;
    middle_block = (mem_block_t*)((size_t)(new_chunk->ma_first.mb_data)  + BT_SIZE);
    middle_block->mb_size = page_bytes_needed - sizeof(mem_chunk_t) - 10 * sizeof(void*);
    assert(middle_block->mb_size > 0 && middle_block->mb_size % 8 == 0);
    set_boundary_tag_of_block(middle_block, BT_FREE);
    LIST_INSERT_HEAD(&new_chunk->ma_freeblks, middle_block, mb_node);

    // init last boundary block of 0 size. it is always allocated
    // potentially union problem?
    mem_block_t* right_boundary_block = (mem_block_t*)((size_t)(middle_block->mb_data) + (size_t)middle_block->mb_size + BT_SIZE);
    right_boundary_block->mb_size = 0;
    set_boundary_tag_of_block(right_boundary_block, BT_ALLOCATED);

// printf("chunk_addr: 0x%016lx, middle_data_addr: 0x%016lx, middle_bt_address: 0x%016lx\n", (size_t)new_chunk, (size_t)first_free_block->mb_data, (size_t)first_free_block->mb_data + first_free_block->mb_size);
// printf("first_0_addr: 0x%016lx, middle_free_addr: 0x%016lx, last_0_addr: 0x%016lx\n", (size_t)&new_chunk->ma_first, (size_t)first_free_block, (size_t)last_boundary_block);

    return new_chunk;
}

int foo_posix_memalign(void **memptr, size_t alignment, size_t data_bytes)
{
    void* aligned_memory = NULL;

    if(alignment % sizeof(void *) != 0
        || !is_power_of_two(alignment / sizeof(void *))
        || alignment == 0)
        return EINVAL;
    
    // Disallow blocks of 0 size.
    if(data_bytes == 0){
       *memptr = NULL;
        return 0;
    }
    
    aligned_memory = _posix_memalign(alignment, data_bytes);

    if(aligned_memory == NULL)
        return ENOMEM;

    *memptr = aligned_memory;

    return 0;    
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
    eight_bytes_data = round_up_to_multiply_of(total_bytes, sizeof(void*));

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

    found_block->mb_size = -found_block->mb_size;
    set_boundary_tag_of_block(found_block, BT_ALLOCATED);

    // now block is read but not splitted
    // split when needed
    split_block_to_size(found_block, eight_bytes_data, &right_side_split_block);

    // delete allocated block from list
    LIST_REMOVE(found_block, mb_node);

    // clear bytes between mb_data and aligned_memory
    // BE CAREFULL OF int argument of memset (4 bytes)
    // might want to set it to some magic number
    memset(&found_block->mb_data, 0, (size_t)aligned_memory - (size_t)(&found_block->mb_data));

    return aligned_memory;
}

static int split_block_to_size(mem_block_t* block, size_t desired_size, mem_block_t** new_block)
{
    assert(desired_size % 8 == 0);
    size_t available_space_for_new_block_with_its_header = ABS(block->mb_size) - ABS(desired_size) - BT_SIZE;
    
    // <= OR <. blocks of 0 size? NOPE
    if(available_space_for_new_block_with_its_header <= sizeof(mem_block_t)){
        return 0;
    }

    size_t new_block_size = available_space_for_new_block_with_its_header - sizeof(void*);

    *new_block = (mem_block_t*)((size_t)block->mb_data + desired_size + BT_SIZE);

    block->mb_size = -ABS(desired_size);
    set_boundary_tag_of_block(block, BT_ALLOCATED);
    (*new_block)->mb_size = new_block_size;
    assert(new_block_size % 8 == 0);
    set_boundary_tag_of_block(*new_block, BT_FREE);

    // add new block on list
    LIST_INSERT_AFTER(block, *new_block, mb_node);

    return 1;
}