#include <stdlib.h>
#include <stdio.h>
#include "malloc.h"
#include "minunit.h"

int main()
{
	void* a = mmalloc(1);

	printf("%d\n", (int)a);

	return 0;
}
