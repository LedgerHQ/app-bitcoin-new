#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "common/bitvector.h"

static int popcount(unsigned int n) {
    int result = 0;
    while (n != 0) {
        result += n & 1;
        n /= 2;
    }
    return result;
}

static unsigned int popcount_vec(const uint8_t *vec, size_t size) {
    unsigned int result = 0;
    for (size_t i = 0; i < size; i++) {
        result += popcount(vec[i]);
    }
    return result;
}

static void test_bitvector_size(void **state) {
    (void) state;

    for (unsigned int i = 0; i < 10; i++) {
        for (unsigned int b = 1; i <= 8; i++) {
            unsigned int n = i * 8 + b;
            assert_int_equal(BITVECTOR_REAL_SIZE(n), i + 1);
        }
    }
}

static void test_bitvector_get(void **state) {
    (void) state;

    uint8_t vec[] = {
        150,  // 0b10010110
        57,   // 0b00111001
        81    // 0b01010001
    };

    unsigned int i = 0;
    assert_int_equal(bitvector_get(vec, i++), 1);
    assert_int_equal(bitvector_get(vec, i++), 0);
    assert_int_equal(bitvector_get(vec, i++), 0);
    assert_int_equal(bitvector_get(vec, i++), 1);
    assert_int_equal(bitvector_get(vec, i++), 0);
    assert_int_equal(bitvector_get(vec, i++), 1);
    assert_int_equal(bitvector_get(vec, i++), 1);
    assert_int_equal(bitvector_get(vec, i++), 0);

    assert_int_equal(bitvector_get(vec, i++), 0);
    assert_int_equal(bitvector_get(vec, i++), 0);
    assert_int_equal(bitvector_get(vec, i++), 1);
    assert_int_equal(bitvector_get(vec, i++), 1);
    assert_int_equal(bitvector_get(vec, i++), 1);
    assert_int_equal(bitvector_get(vec, i++), 0);
    assert_int_equal(bitvector_get(vec, i++), 0);
    assert_int_equal(bitvector_get(vec, i++), 1);

    assert_int_equal(bitvector_get(vec, i++), 0);
    assert_int_equal(bitvector_get(vec, i++), 1);
    assert_int_equal(bitvector_get(vec, i++), 0);
    assert_int_equal(bitvector_get(vec, i++), 1);
    assert_int_equal(bitvector_get(vec, i++), 0);
    assert_int_equal(bitvector_get(vec, i++), 0);
    assert_int_equal(bitvector_get(vec, i++), 0);
    assert_int_equal(bitvector_get(vec, i++), 1);
}

static void test_bitvector_set(void **state) {
    (void) state;

    uint8_t vec[BITVECTOR_REAL_SIZE(129)];

    for (int i = 0; i < 129; i++) {
        memset(vec, 0, sizeof(vec));

        bitvector_set(vec, i, 1);

        assert_int_equal(bitvector_get(vec, i), 1);
        assert_int_equal(popcount_vec(vec, sizeof(vec)), 1);  // exactly 1 bit should be 1

        bitvector_set(vec, i, 0);

        assert_int_equal(bitvector_get(vec, i), 0);
        assert_int_equal(popcount_vec(vec, sizeof(vec)), 0);  // exactly 0 bits should be 1
    }
}

int main() {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_bitvector_size),
                                       cmocka_unit_test(test_bitvector_get),
                                       cmocka_unit_test(test_bitvector_set)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
