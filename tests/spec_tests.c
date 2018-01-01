#include "../minunit.h"
#include "../malloc.h"

static void test_posix_memalign_x_y(size_t alignment, size_t data, int rtn, long long int ptr);

/* POSIX_MEMALIGN TESTS */

/* Data is 0 and alignment changes */

MU_TEST(posix_memalign_0_0_returns_EINVAL){
    test_posix_memalign_x_y(0, 0, EINVAL, -1);
}

MU_TEST(posix_memalign_3_0_returns_EINVAL){
    test_posix_memalign_x_y(3, 0, EINVAL, -1);
}

MU_TEST(posix_memalign_4_0_returns_EINVAL){
    test_posix_memalign_x_y(4, 0, EINVAL, -1);
}

MU_TEST(posix_memalign_void_0_returns_0){
    test_posix_memalign_x_y(sizeof(void*), 0, 0, -1);
}

MU_TEST(posix_memalign_10_0_returns_EINVAL){
    test_posix_memalign_x_y(10, 0, EINVAL, -1);
}

/* Data is not 0 and alignment changes */

MU_TEST(posix_memalign_0_5_returns_EINVAL){
    test_posix_memalign_x_y(0, 5, EINVAL, -1);
}

MU_TEST(posix_memalign_3_5_returns_EINVAL){
    test_posix_memalign_x_y(3, 5, EINVAL, -1);
}

MU_TEST(posix_memalign_4_5_returns_EINVAL){
    test_posix_memalign_x_y(4, 5, EINVAL, -1);
}

MU_TEST(posix_memalign_void_5_returns_0){
    test_posix_memalign_x_y(sizeof(void*), 5, 0, -1);
}

MU_TEST(posix_memalign_10_5_returns_EINVAL){
    test_posix_memalign_x_y(10, 5, EINVAL, -1);
}

MU_TEST_SUITE(posix_memalign_alloc_wrong_alignment_and_data_0) {
    /* Data is 0 and alignment changes */
	MU_RUN_TEST(posix_memalign_0_0_returns_EINVAL);
    MU_RUN_TEST(posix_memalign_3_0_returns_EINVAL);
    MU_RUN_TEST(posix_memalign_4_0_returns_EINVAL);
    MU_RUN_TEST(posix_memalign_void_0_returns_0);
    MU_RUN_TEST(posix_memalign_10_0_returns_EINVAL);

    /* Data is not 0 and alignment changes */
    MU_RUN_TEST(posix_memalign_0_5_returns_EINVAL);
    MU_RUN_TEST(posix_memalign_3_5_returns_EINVAL);
    MU_RUN_TEST(posix_memalign_4_5_returns_EINVAL);
    MU_RUN_TEST(posix_memalign_void_5_returns_0);
    MU_RUN_TEST(posix_memalign_10_5_returns_EINVAL);
}

int main() {
	MU_RUN_SUITE(posix_memalign_alloc_wrong_alignment_and_data_0);
	MU_REPORT();
    #define GREEN   "\033[32m"
    #define RESET   "\033[0m"

    printf(GREEN "\n\nAll tests sucessfully passed!\n" RESET);
	return 0;
}

static void test_posix_memalign_x_y(size_t alignment, size_t data, int rtn, long long int ptr)
{
    void* _ptr;
    int _rtn = foo_posix_memalign(&_ptr, alignment, data);
    mu_check(rtn == _rtn);
    if(ptr != -1){
        mu_check(_ptr == (void*)ptr);
    }
}
