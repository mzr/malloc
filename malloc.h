#ifndef __MALLOC_H_INCLUDED__
#define __MALLOC_H_INCLUDED__

#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <error.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "queue.h"
#include "malloc_types.h"   /* struct definitions for malloc implementation */

void check_integrity();

void *foo_malloc(size_t size);
void *foo_calloc(size_t count, size_t size);
void *foo_realloc(void *ptr, size_t size);
int foo_posix_memalign(void **memptr, size_t alignment, size_t size);
void foo_free(void *ptr);
void foo_mdump();

LIST_HEAD(, mem_chunk) chunk_list;      /* list of all chunks */

#endif