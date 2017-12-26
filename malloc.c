#include "malloc.h"

#define is_power_of_two(x)     ((((x) - 1) & (x)) == 0)
#define MB_DATA_ALIGNMENT 8
#define WORD (sizeof(void*))
#define BT_SIZE (sizeof(void*))
#define PAGESIZE (getpagesize())

static mem_block_t* find_free_block(size_t size);
static mem_chunk_t* get_new_chunk(size_t size);
static void* _posix_memalign(size_t alignment, size_t size);
static size_t round_up_to_multiply_of(size_t x, size_t r);

static size_t round_up_to_multiply_of(size_t x, size_t r)
{
    return x / r + (x % r ? 1 : 0);
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
    LIST_FOREACH(chunk, &chunk_list, ma_node){
        // chunk_nr, address, size as whole size - sizeof(mem_chunk_t)
        printf("0x%016x\t0x%016x\t0x%016x\n", 
            chunk_nr++, (size_t) chunk, chunk->size);

        LIST_FOREACH(block, &chunk->ma_freeblks, mb_node){
            // block_nr, address, size as mb_data size
            printf("\t0x%016x\t0x%016x\t0x%016x\n", 
                block_nr++, (size_t) block, block->mb_size);
        }

        block_nr = 0;
    }
}

static mem_block_t* find_free_block(size_t size)
{
    mem_block_t* iter_block;
    mem_chunk_t* iter_chunk;

    LIST_FOREACH(iter_chunk, &chunk_list, ma_node){
        LIST_FOREACH(iter_block, &iter_chunk->ma_freeblks, mb_node){
            if(iter_block->mb_size >= size)
                return iter_block;
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
    // need new chunk
    // assign first block pointer to found_block
    size_t needed_bytes = sizeof(mem_chunk_t) + min_block_data_bytes;
    size_t page_bytes_needed = round_up_to_multiply_of(needed_bytes, PAGESIZE);
    size_t pages_needed = page_bytes_needed / PAGESIZE;
    mem_chunk_t* new_chunk;

    new_chunk = (mem_chunk_t*) mmap(NULL, page_bytes_needed, 
        PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0);
        
    if(new_chunk == MAP_FAILED)
        return NULL;
    
    // init chunk
    new_chunk->size = page_bytes_needed - sizeof(mem_chunk_t);
    LIST_INSERT_HEAD(&chunk_list, new_chunk, ma_node);
    
    // init first block
    LIST_INSERT_HEAD(&new_chunk->ma_freeblks, &new_chunk->ma_first, mb_node);
    new_chunk->ma_first.mb_size = page_bytes_needed - sizeof(mem_chunk_t);

    // set its boundary tag
    size_t bt_address = (size_t)new_chunk->ma_first.mb_data + (size_t)new_chunk->ma_first.mb_size;
    *((mem_block_t**)bt_address) = &new_chunk->ma_first;
    
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

/*
 * Allocates aligned memory of size size.
 */
static void* _posix_memalign(size_t alignment, size_t data_bytes)
{
    mem_block_t* found_block = NULL;
    mem_chunk_t* new_chunk = NULL;
    void* aligned_memory = NULL;
    size_t align_bytes;
    size_t total_bytes;

    /* Overhead needed for alignment. mb_data is aligned due to default struct alignment */
    align_bytes = alignment <= MB_DATA_ALIGNMENT ? 0 : alignment - MB_DATA_ALIGNMENT;
    total_bytes = data_bytes + align_bytes + BT_SIZE;

    found_block = find_free_block(total_bytes);

    /* Need to allocate new chunk */
    if(found_block == NULL){
        new_chunk = get_new_chunk(total_bytes);

        /* No memory available */
        if(new_chunk == NULL)
            return NULL;
        
        found_block = &new_chunk->ma_first;
    }

    // we have right block in found_block
    found_block->mb_size = -found_block->mb_size;
    
    // need to set aligned_memory
    if(alignment <= MB_DATA_ALIGNMENT)
        aligned_memory = (void*)&found_block->mb_data;
    else
        aligned_memory = (void**)(((size_t)(&found_block->mb_data) + align_bytes) & ~(alignment - 1));


    // clear bytes between mb_data and aligned_memory


    // split blocks



    // set boundary tag
    void* boundary_tag_address = aligned_memory + data_bytes;
    mem_block_t* boundary_tag_value = (mem_block_t*)((size_t)found_block || 1);
    *((mem_block_t**)boundary_tag_address) = boundary_tag_value;

    return aligned_memory;
}
