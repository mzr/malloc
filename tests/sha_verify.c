#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <assert.h>
#include "../queue.h"

#define HASH_LENGTH_BYTES 32
#define _1GB 1073741824ll
#define OVERALL_MAX_ALLOC_BYTES (10 * _1GB)
#define AVG_ALLOC _1GB
#define MIN_SINGLE_ALLOC 1
#define MAX_SINGLE_ALLOC (_1GB / 16)
#define MAX_ALLOCS 40000

// #define ALLOW_PRINTFS

#define _assert(b,msg) (assert((b) && (msg)))

typedef struct {
    unsigned char value[HASH_LENGTH_BYTES];
} hash_t;

typedef struct alloc {
    void* ptr;
    size_t size;
    hash_t hash;
    LIST_ENTRY(alloc) a_node;
} alloc_t;

size_t now_allocated_bytes = 0;
size_t overall_allocated_bytes = 0;
size_t actions_taken = 0;
size_t allocated_structures = 0;
size_t free_structures = MAX_ALLOCS;
alloc_t alloc[MAX_ALLOCS];
int __z = 0;
LIST_HEAD(, alloc) free_allocs;
LIST_HEAD(, alloc) allocated_allocs;

void calculate_hash(void* data, size_t size, void* hash)
{
    SHA256(data, size, hash);
}

void calc_hash(alloc_t* a)
{
    calculate_hash(a->ptr, a->size, a->hash.value);
}

int same_hashes(hash_t* h1, hash_t* h2)
{
    for(int i=0; i<HASH_LENGTH_BYTES; i++)
        if(h1->value[i] != h2->value[i])
            return 0;
    return 1;
}

void printProgress (double percentage)
{
    #define PBSTR "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
    #define PBWIDTH 60

    int val = (int) (percentage * 100);
    int lpad = (int) (percentage * PBWIDTH);
    int rpad = PBWIDTH - lpad;
    printf ("\r%3d%% [%.*s%*s]", val, lpad, PBSTR, rpad, "");
    fflush (stdout);
}

void init_test()
{
    for(int i=0; i<MAX_ALLOCS; i++)
        LIST_INSERT_HEAD(&free_allocs, &alloc[i], a_node);
}

void fill_with_data(alloc_t* a, size_t size)
{
    for(int i=0; i<size; i++){
        *(uint8_t*)(a->ptr + i) = (uint8_t)rand();
    }
}

void call_malloc(size_t size)
{   
    #ifdef ALLOW_PRINTFS
    printf("calling malloc(%lu)\n", size);
    #endif
    alloc_t* free_alloc = LIST_FIRST(&free_allocs);
    free_alloc->ptr = malloc(size);
    _assert(free_alloc->ptr != NULL, "malloc returned NULL pointer");
    free_alloc->size = size;
    fill_with_data(free_alloc, size);
    calc_hash(free_alloc);
    LIST_REMOVE(free_alloc, a_node);
    LIST_INSERT_HEAD(&allocated_allocs, free_alloc, a_node);
    allocated_structures++;
    now_allocated_bytes += size;
    overall_allocated_bytes += size;
}

void call_posix_memalign(size_t size, size_t alignment)
{
    #ifdef ALLOW_PRINTFS
    printf("calling posi_memalign(%lu, %lu)\n", size, alignment);
    #endif
    alloc_t* free_alloc = LIST_FIRST(&free_allocs);
    free_alloc->ptr = malloc(size);
    int result = posix_memalign(&free_alloc->ptr, alignment, size);
    // _assert(result)
    // _assert(free_alloc->ptr != NULL, "malloc returned NULL pointer");
    free_alloc->size = size;
    fill_with_data(free_alloc, size);
    calc_hash(free_alloc);
    LIST_REMOVE(free_alloc, a_node);
    LIST_INSERT_HEAD(&allocated_allocs, free_alloc, a_node);
    allocated_structures++;
    now_allocated_bytes += size;
    overall_allocated_bytes += size;
}

void verify_zeroed(void* ptr, size_t size)
{
    for(int i=0; i<size; i++){
        _assert(*(uint8_t*)(ptr + i) == 0, "memory not zeroed");
    }
}

void call_calloc(size_t count, size_t size)
{
    #ifdef ALLOW_PRINTFS
    printf("calling calloc(%lu, %lu)\n", count, size);
    #endif
    alloc_t* free_alloc = LIST_FIRST(&free_allocs);
    free_alloc->ptr = calloc(count, size);
    _assert(free_alloc->ptr != NULL, "malloc returned NULL pointer");
    free_alloc->size = size;
    verify_zeroed(free_alloc->ptr, free_alloc->size);
    fill_with_data(free_alloc, size);
    calc_hash(free_alloc);
    LIST_REMOVE(free_alloc, a_node);
    LIST_INSERT_HEAD(&allocated_allocs, free_alloc, a_node);
    allocated_structures++;
    now_allocated_bytes += count * size;
    overall_allocated_bytes += count * size;
}

void call_realloc_bigger()
{

}

void verify_hash(alloc_t* a)
{
    hash_t h;
    calculate_hash(a->ptr, a->size, h.value);
    int result = same_hashes(&a->hash, &h);

    _assert(result == 1, "hashes not the same");
}

void call_free()
{
    #ifdef ALLOW_PRINTFS
    printf("calling free\n");
    #endif
    size_t rand_taken_block = rand() % allocated_structures;

    alloc_t* taken_block;
    size_t i = 0;
    LIST_FOREACH(taken_block, &allocated_allocs, a_node){
        if(i++ == rand_taken_block)
            break;
    }

    verify_hash(taken_block);
    free(alloc->ptr);

    now_allocated_bytes -= taken_block->size;
    allocated_structures--;

    LIST_REMOVE(taken_block, a_node);
    LIST_INSERT_HEAD(&free_allocs, taken_block, a_node);
}

void call_realloc_smaller()
{

}

void single_action()
{
    int64_t jitter = ((rand() % 2) == 0 ? -1 : 1) * (_1GB / 4);
    if(now_allocated_bytes < AVG_ALLOC + jitter){
        int op_type = rand() % 4;
        size_t alloc_size = rand() % MAX_SINGLE_ALLOC + MIN_SINGLE_ALLOC;
        size_t alignment;
        switch(op_type){
        case 0: call_malloc(alloc_size);
                break;
        case 1: alignment = ((1 << (rand() % 8)) << 3);  // rand alignment [8, 2^10]
                call_posix_memalign(alloc_size, alignment);
                break;
        case 2: call_calloc(4, alloc_size / 4 + MIN_SINGLE_ALLOC);
                break;
        case 3: call_realloc_bigger();
            
        }
    } else {
        int op_type = rand() % 2;
        switch(op_type){
        case 0: call_free();
                break;
        case 1: call_realloc_smaller();

        }
        // update allocated!!
    }
    actions_taken++;
}

void teardown_test()
{
    for(int i=0; i<allocated_structures; i++)
        call_free();
}

void run_test(){
    init_test();
    while(overall_allocated_bytes < OVERALL_MAX_ALLOC_BYTES && actions_taken < MAX_ALLOCS){
        #ifdef ALLOW_PRINTFS
        printf("------------------------------ TEST BEGIN ------------------------------\n");
        #endif
        printProgress((overall_allocated_bytes * 1.0) / (OVERALL_MAX_ALLOC_BYTES * 1.0));
        single_action();
        __z++;  // for gdb conditional breakpoint / watchpoint
        #ifdef ALLOW_PRINTFS
        printf("------------------------------ END OF TEST ------------------------------\n");
        #endif
    }
 
    teardown_test();  
    
    #define GREEN   "\033[32m"
    #define RESET   "\033[0m"
    printf(GREEN "\n\nAll %d tests sucessfully passed!\n" RESET, __z);
}

int main(int argc, char** argv){

    if(argc == 1){
        srand(1337);
    } else {
        srand(atoi(argv[1]));
    }
 
    run_test();
}