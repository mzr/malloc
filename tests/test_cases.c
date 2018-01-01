#include "../malloc.h"

void write_bytes(void* ptr, size_t bytes){
    memset(ptr, 0, bytes);
}

void test_case_1(){
    void* ptr1 = foo_malloc(10);
    write_bytes(ptr1, 10);
    void* ptr2 = foo_malloc(15);
    write_bytes(ptr2, 15);
    void* ptr3 = foo_malloc(43);
    write_bytes(ptr3, 43);
    foo_free(ptr2);
    foo_free(ptr1);
    foo_free(ptr3);

    foo_mdump();
}

void test_case_2(){
    void* ptr1 = foo_malloc(10);
    write_bytes(ptr1, 10);
    void* ptr2;
    foo_posix_memalign(&ptr2,64,56);
    write_bytes(ptr2, 15);
    void* ptr3 = foo_malloc(43);
    write_bytes(ptr3, 43);
    foo_free(ptr2);
    foo_free(ptr1);
    foo_free(ptr3);

    foo_mdump();
}

void test_case_3(){
    void* ptr1 = foo_malloc(10);
    write_bytes(ptr1, 10);
    void* ptr2;
    foo_posix_memalign(&ptr2,64,56);
    write_bytes(ptr2, 56);
    void* ptr3 = foo_malloc(43);
    write_bytes(ptr3, 43);

    ptr2 = foo_realloc(ptr2, 124);

    write_bytes(ptr2, 124);

    foo_free(ptr2);
    foo_free(ptr1);

    foo_free(ptr3);

    foo_mdump();
}

int main(){

    test_case_1();
    test_case_2();
    test_case_3();

    #define GREEN   "\033[32m"
    #define RESET   "\033[0m"

    printf(GREEN "\n\nAll tests sucessfully passed!\n" RESET);

    return 0;
}