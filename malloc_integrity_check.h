#ifndef __MALLOC_INTEGRITY_CHECK_H_INCLUDED__
#define __MALLOC_INTEGRITY_CHECK_H_INCLUDED__

#include "malloc_types.h"
#include "queue.h"

void check_integrity();
void walk_the_chunk();

#endif