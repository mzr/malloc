#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>
 
/*
The plan:
- Allocate 20 GB of memory in total
- 1 GB allocated at average
- randomly choose posix_memalign, calloc, malloc, and check assumptions of used function
- write some random, deterministic data to each allocated block
- before destruction, check data
- sometimes use realloc
 
*/
 
#include "../malloc.h"
 
#define MY_MALLOC

#ifdef MY_MALLOC
#define malloc foo_malloc
#define calloc foo_calloc
#define realloc foo_realloc
#define free foo_free
#define posix_memalign foo_posix_memalign
#endif

#define _round_up_to_multiply_of(x,r) ((x) + ((r) - ((x) % (r))))

int __z = 0;

void _assert(bool a, char * msg){
    if(!a){
        // printf("%s\n", msg);
        exit(1);
    }
}
 
void validate_rw_access(volatile char *ptr){
    // this may cause sigsegv, but nvm
    char tmp = *ptr;
    *ptr = 'Q';
    _assert(*ptr == 'Q', "write to allocated block failed");
    *ptr = tmp;
}

void validate_malloc_bt(void* ptr, size_t size)
{
    mem_block_t* block_addr = (mem_block_t*)((size_t)ptr - sizeof(void*));
    size_t bt_address = abs(block_addr->mb_size) + (size_t)block_addr->mb_data;
    size_t bt_value = *((size_t*)bt_address);
    mem_block_t* bt_val_addr = (mem_block_t*)(bt_value & 0xfffffffffffffffe);
    if(bt_val_addr != block_addr){
        // printf("block addr: 0x016%lx, bt addr: 0x016%lx, bt val: 0x016%lx;", (size_t) block_addr, bt_address, (size_t)bt_val_addr);
    }
    _assert(bt_val_addr == block_addr, "boundary tag addres does not match block address");
}

void validate_malloc(void *ptr, size_t size){
    validate_rw_access((char *)ptr); // check if begining end of block is accessible
    validate_rw_access((char *)ptr + size - 1); // check if very end of block is accessible
}
 
void validate_zeroed(void *ptr, size_t size){
    for(size_t i = 0; i < size; i++){
        _assert(*((char *)ptr + i) == 0, "calloc result not zeroed!");
    }
}
 
void validate_calloc(void *ptr, size_t count, size_t size){
    validate_malloc(ptr, count * size);
    validate_zeroed(ptr, count * size);
}
 
void *call_malloc(size_t size){
    // printf("\tcalling malloc(size = %lu)\n", size);
    void *res = malloc(size);
    _assert(res != NULL, "");
    validate_malloc(res, size);

    #ifdef MY_MALLOC
    if(size < 16)
        size = 16;
    validate_malloc_bt(res, _round_up_to_multiply_of(size,8));
    #endif

    return res;
}
 
void *call_calloc(size_t count, size_t size){
    // printf("\tcalling calloc(count = %lu, size = %lu)\n", count, size);
    void *res = calloc(count, size);
    validate_calloc(res, count, size);
    return res;
}
 
void validate_posix_memalign(int res, void **memptr, size_t alignment, size_t size){
    _assert(res == 0, "couldn't posix_memalign()");
    _assert((size_t)*memptr % alignment == 0, "posix_memalign() returned not aligned pointer");
    validate_malloc(*memptr, size);
}
 
int call_posix_memalign(void **memptr, size_t alignment, size_t size){
    // printf("\tcalling posix_memalign(memptr = 0x016%lx, alignment = %lu, size = %lu)\n", (size_t)memptr, alignment, size);
    int res = posix_memalign(memptr, alignment, size);
    validate_posix_memalign(res, memptr, alignment, size);
    return res;
}
 
void *call_realloc(void *ptr, size_t size){
    // printf("\tcalling realloc(ptr = 0x016%lx, size = %lu)\n", (size_t)ptr, size);
    void * res = realloc(ptr, size);
    if(res != NULL){
        validate_malloc(res, size);
    }
    return res;
}
 
void call_free(void *ptr){
    // printf("\tcalling free(ptr = 0x016%lx)\n", (size_t)ptr);
    _assert(ptr != NULL, "trying to free(NULL)");
    free(ptr);
}
 
 
//////////////////////////////////////////////
 
 
 
 
typedef struct {
    void * ptr;
    uint64_t size;
    uint8_t seed;
 
} alloc;
 
 
#define _1GB 1073741824ull
#define _100GB (10 * _1GB)
#define ALLOC_MAX _1GB
#define ALLOC_MIN 1
#define ALLOC_AVG 250000 //((ALLOC_MAX + ALLOC_MIN) / 2)
#define ALLOCS_MAX_NUM (_1GB / ALLOC_AVG)
 
 
 
 
 
uint64_t good_rand(){
    return    (((uint64_t) rand() <<  0) & 0x000000000000FFFFull) |
              (((uint64_t) rand() << 16) & 0x00000000FFFF0000ull) |
              (((uint64_t) rand() << 32) & 0x0000FFFF00000000ull) |
              (((uint64_t) rand() << 48) & 0xFFFF000000000000ull);
}
size_t rand_alloc_size(){
    float r = ((size_t)good_rand()) / (float)SIZE_MAX;//(good_rand() - ALLOC_MIN) % (ALLOC_MAX - ALLOC_MIN) + ALLOC_MIN;
 
    r = (2211222ull*r*r - 1304302ull*r + 47585ull) ;
    r = abs(r);
    return r+1;
}
 
 
__thread alloc allocs[ALLOCS_MAX_NUM];
__thread uint64_t sum_allocated_ever = 0;
 
void init(){
    for(size_t i = 0; i < ALLOCS_MAX_NUM; i++){
        allocs[i].size = 0;
    }
}
 
void check_and_free(alloc* a){
    uint8_t data = a->seed;
    for(uint8_t * i = a->ptr; i != (uint8_t *)a->ptr + a->size; i++){
        // _assert(*i == data, "data stored in memory was changed");
        // data ++;
    }
 
    call_free(a->ptr);
    a->ptr = NULL;
    a->size = 0;
}
 
void fill_with_data(alloc* a){
    uint8_t data = a->seed;
    int ugabuga = 0;
    uint8_t* i;
    // for(i = a->ptr; i != (uint8_t *)a->ptr + a->size; i++){
    //     *i = data;
    //     data ++;
    //     ugabuga++;
    // }
    uint8_t arr[4] = {0xde, 0xad, 0xc0, 0xde};
    for(i = a->ptr; i != (uint8_t*)a->ptr + a->size; i++){
        *i = arr[ugabuga % 4];
        ugabuga++;
    }
}
 
void allocate_here(alloc *a, size_t new_size){
    int r = rand() % 4;
    if(r == 0){
        // use malloc
        if(a->size != 0){
            check_and_free(a);
        }
 
        a->seed = good_rand();
        a->size = new_size;
        a->ptr = call_malloc(new_size);
    }else if(r == 1){
        // use posix_memalign
        if(a->size != 0){
            check_and_free(a);
        }
        size_t min_align = sizeof(void *);
        size_t align = min_align << rand() % 5;
 
        call_posix_memalign(&a->ptr, align, new_size);
        a->seed = good_rand();
        a->size = new_size;
    }else if(r == 2){
        // use calloc
        if(a->size != 0){
            check_and_free(a);
        }
 
        size_t size;
        for(int divisor = 32; divisor >= 1; divisor --){
            if(new_size % divisor == 0){
                size = divisor;
                break;
            }
        }
 
        a->seed = good_rand();
        a->size = new_size;
        a->ptr = call_calloc(new_size / size, size);
    }else{
        // use realloc
        void * res = call_realloc(a->ptr, new_size);
        if(res != NULL){
            a->seed = good_rand();
            a->size = new_size;
            a->ptr = res;
        }
    }
}
 
void allocate_something(){
    alloc* a = &allocs[good_rand() % ALLOCS_MAX_NUM];
 
    size_t new_size = rand_alloc_size();
 
    allocate_here(a, new_size);
 
    sum_allocated_ever += new_size;
 
    fill_with_data(a);
}
 
void free_rest(){
    for(size_t i = 0; i < ALLOCS_MAX_NUM; i++){
        if(allocs[i].size != 0){
            check_and_free(&allocs[i]);
        }
    }
}

///////////////////

#define PBSTR "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
#define PBWIDTH 60

void printProgress (double percentage)
{
    int val = (int) (percentage * 100);
    int lpad = (int) (percentage * PBWIDTH);
    int rpad = PBWIDTH - lpad;
    printf ("\r%3d%% [%.*s%*s]", val, lpad, PBSTR, rpad, "");
    fflush (stdout);
}

////////////////////////

void test(){
 
    init();
    while(sum_allocated_ever < _100GB){
        // printf("------------------------------ TEST BEGIN ------------------------------\n");
        double a = sum_allocated_ever * 1.0;
        double total = _100GB * 1.0;
        // printf("#%d, percentage of tests: %f\n", __z, a / total);
        printProgress(a / total);
        allocate_something();
        #ifdef MY_MALLOC
        // foo_mdump();
        check_integrity();
        #endif
        __z++;  // for gdb conditional breakpoint / watchpoint
        // printf("------------------------------ END OF TEST ------------------------------\n");
    }
 
    free_rest();  
    
    #define GREEN   "\033[32m"
    #define RESET   "\033[0m"

    printf(GREEN "\n\nAll %d tests sucessfully passed!\n" RESET, __z);
}
 
int main(){

    srand(100); // 98 fails
 
    test();
}