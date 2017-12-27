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
    // *((void**) bt_address) = (mem_block_t*)(size_t)((size_t)block | is_allocated);
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

void foo_mdump()
{
    int chunk_nr = 0;
    int block_nr = 0;
    mem_chunk_t* chunk;
    mem_block_t* block;
    size_t is_allocated;
    size_t bt_points_to; 
    printf("DYNAMICALLY ALLOCATED MEMORY DUMP:\n");
    LIST_FOREACH(chunk, &chunk_list, ma_node){
        // chunk_nr, address, size as whole size - sizeof(mem_chunk_t)
        printf("%d\t0x%016lx\t0x%016lx\t%d\n", 
            chunk_nr++, (size_t) chunk, (size_t) &chunk->ma_first, chunk->size);

        LIST_FOREACH(block, &chunk->ma_freeblks, mb_node){
            // block_nr, address, size as mb_data size
            bt_points_to = (size_t)get_back_boundary_tag_of_block(block, &is_allocated);
            printf("\t%d\t0x%016lx\t0x%016lx\t%d\t0x%016lx\t%lu\n", 
                block_nr++, 
                (size_t) block, 
                (size_t) block->mb_data, 
                block->mb_size, 
                (size_t)block,
                is_allocated);
        }
        block_nr = 0;
    }
}

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

}

/*
 * Allocates new chunk which size is at least sizeof(block_data)
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
    
    // init first block
    LIST_INSERT_HEAD(&new_chunk->ma_freeblks, &new_chunk->ma_first, mb_node);
    new_chunk->ma_first.mb_size = page_bytes_needed - sizeof(mem_chunk_t) - BT_SIZE;

    assert(new_chunk->ma_first.mb_size >= 0);

    set_boundary_tag_of_block(&new_chunk->ma_first, 0);
// foo_mdump();
    return new_chunk;
}

int foo_posix_memalign(void **memptr, size_t alignment, size_t data_bytes)
{
    void* aligned_memory = NULL;

    if(data_bytes == 0){
       *memptr = NULL; // NULL or passable to free
        return 0;
    }

    if(alignment % sizeof(void *) != 0
        || !is_power_of_two(alignment / sizeof(void *))
        || alignment == 0)
        return EINVAL;
    
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
        
        found_block = &new_chunk->ma_first;
    }
    
    // need to set aligned_memory
    if(alignment <= MB_DATA_ALIGNMENT)
        aligned_memory = (void*)&found_block->mb_data;
    else
        aligned_memory = (void**)(((size_t)(&found_block->mb_data) + user_align_bytes) & ~(alignment - 1));

// printf("found_block_addr: 0x%016lx, aligned_memory: 0x%016lx\n", (size_t)found_block, (size_t)aligned_memory);

    // clear bytes between mb_data and aligned_memory
    memset(&found_block->mb_data, 0, (size_t)aligned_memory - (size_t)(&found_block->mb_data));
    found_block->mb_size = -found_block->mb_size;
    set_boundary_tag_of_block(found_block, BT_ALLOCATED);


    // now block is read but not splitted
    // split when needed
    split_block_to_size(found_block, eight_bytes_data, &right_side_split_block);

    return aligned_memory;
}

static int split_block_to_size(mem_block_t* block, size_t desired_size, mem_block_t** new_block)
{
    size_t available_space_for_new_block_with_its_header = 
        ABS(block->mb_size) - ABS(desired_size) - BT_SIZE;
    
    // <= OR <. blocks of 0 size? NOPE
    if(available_space_for_new_block_with_its_header <= sizeof(mem_block_t)){
        return 0;
    }

    size_t new_block_size = available_space_for_new_block_with_its_header - sizeof(mem_block_t);

    *new_block = (mem_block_t*)((size_t)block->mb_data + desired_size + BT_SIZE);

    block->mb_size = -ABS(desired_size);
    set_boundary_tag_of_block(block, BT_ALLOCATED);
    (*new_block)->mb_size = new_block_size;
    set_boundary_tag_of_block(*new_block, BT_FREE);

    // add new block on list
    LIST_INSERT_AFTER(block, *new_block, mb_node);

    // delete allocated block from list
    LIST_REMOVE(block, mb_node);

    return 1;
}