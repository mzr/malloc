#include "malloc.h"

void *mmalloc(size_t size)
{
    return (void*)0x800000;
}

void *mcalloc(size_t count, size_t size)
{

}

void *mrealloc(void *ptr, size_t size)
{

}

int mposix_memalign(void **memptr, size_t alignment, size_t size)
{

}

void mfree(void *ptr)
{

}