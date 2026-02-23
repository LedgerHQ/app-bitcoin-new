/**
 * Non-regression unit tests for the call_get_merkleized_map_value() return
 * value checking fixes.
 *
 * Background:
 *   call_get_merkle_preimage() can return error codes from -1 to -10.
 *   call_get_merkle_leaf_element() forwards those.
 *   call_get_merkleized_map_value() returns them to callers.
 *
 *   Several callers (sign_psbt.c, policy.c, txhashes.c) were checking
 *   `result == -1` which would miss error codes -2 through -10. The fix
 *   changed these to `result < 0`.
 *
 * These tests verify:
 *   1. call_get_merkleized_map_value() faithfully propagates negative error
 *      codes from call_get_merkle_leaf_element() (not just -1).
 *   2. call_get_merkleized_map_value_u32_le() correctly returns -1 for ALL
 *      negative sub-call results (it normalizes via `res != 4`).
 *   3. The "< 0" check pattern catches all error codes that the old "== -1"
 *      pattern would miss.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "handler/lib/get_merkleized_map_value.h"
#include "merkle_test_mocks.h"

/* ===================================================================== */
/* Test: call_get_merkleized_map_value propagates negative return values  */
/* ===================================================================== */

/**
 * Sanity check: a successful call returns the expected length.
 */
static void test_map_value_success_returns_length(void **state) {
    (void) state;

    merkle_mock_reset();
    merkle_mock_set_leaf_index_retval(3);    /* found at index 3 */
    merkle_mock_set_leaf_element_retval(10); /* 10 bytes returned */

    merkleized_map_commitment_t map = {.size = 5};
    uint8_t out[32];
    uint8_t key = 0x42;

    int ret = call_get_merkleized_map_value(NULL, &map, &key, 1, out, sizeof(out));

    assert_int_equal(ret, 10);
}

/**
 * When call_get_merkle_leaf_index returns a negative value, the function
 * should return -1 (key not found / error).
 */
static void test_map_value_returns_neg1_on_index_failure(void **state) {
    (void) state;

    /* Test all possible negative returns from call_get_merkle_leaf_index */
    int error_codes[] = {-1, -2, -3, -4, -5};

    for (int i = 0; i < 5; i++) {
        merkle_mock_reset();
        merkle_mock_set_leaf_index_retval(error_codes[i]);

        merkleized_map_commitment_t map = {.size = 5};
        uint8_t out[32];
        uint8_t key = 0x42;

        int ret = call_get_merkleized_map_value(NULL, &map, &key, 1, out, sizeof(out));

        /* Index failure always returns -1 from call_get_merkleized_map_value */
        assert_true(ret < 0);
        assert_int_equal(ret, -1);
    }
}

/**
 * KEY REGRESSION TEST: When call_get_merkle_leaf_element returns a negative
 * value other than -1, call_get_merkleized_map_value propagates it directly.
 *
 * This proves that the function CAN return values like -2, -5, -10, which
 * means callers MUST use `< 0` (not `== -1`) to catch all errors.
 *
 * Before the fix, callers checking `== -1` would treat -2..-10 as a valid
 * non-negative length, leading to undefined behavior (e.g. passing a negative
 * int as a buffer size to buffer_create).
 */
static void test_map_value_propagates_all_negative_leaf_element_errors(void **state) {
    (void) state;

    /* All possible error codes from call_get_merkle_preimage (via leaf_element) */
    int error_codes[] = {-1, -2, -3, -4, -5, -6, -7, -8, -9, -10};

    for (int i = 0; i < 10; i++) {
        merkle_mock_reset();
        merkle_mock_set_leaf_index_retval(0);               /* index lookup succeeds */
        merkle_mock_set_leaf_element_retval(error_codes[i]); /* element fetch fails */

        merkleized_map_commitment_t map = {.size = 5};
        uint8_t out[32];
        uint8_t key = 0x42;

        int ret = call_get_merkleized_map_value(NULL, &map, &key, 1, out, sizeof(out));

        /* The return value should be exactly the error code from leaf_element */
        assert_int_equal(ret, error_codes[i]);

        /* The FIXED check (< 0) catches this */
        assert_true(ret < 0);
    }
}

/**
 * Demonstrates that the OLD check pattern (== -1) would miss errors -2..-10.
 *
 * For error codes -2 through -10 returned by call_get_merkle_leaf_element:
 *   - call_get_merkleized_map_value forwards them unchanged
 *   - The old `if (ret == -1)` check would NOT catch them
 *   - The new `if (ret < 0)` check DOES catch them
 */
static void test_old_eq_neg1_check_misses_non_neg1_errors(void **state) {
    (void) state;

    /* Error codes that the old == -1 check would MISS */
    int missed_error_codes[] = {-2, -3, -4, -5, -6, -7, -8, -9, -10};

    for (int i = 0; i < 9; i++) {
        merkle_mock_reset();
        merkle_mock_set_leaf_index_retval(0);
        merkle_mock_set_leaf_element_retval(missed_error_codes[i]);

        merkleized_map_commitment_t map = {.size = 5};
        uint8_t out[32];
        uint8_t key = 0x42;

        int ret = call_get_merkleized_map_value(NULL, &map, &key, 1, out, sizeof(out));

        /* This is a real error, but... */
        assert_true(ret < 0);

        /* ...the old check (== -1) would NOT catch it! */
        assert_int_not_equal(ret, -1);

        /* The new check (< 0) does catch it */
        assert_true(ret < 0);  /* redundant, but makes the point explicit */
    }
}

/* ===================================================================== */
/* Test: call_get_merkleized_map_value_u32_le (inline helper)            */
/* ===================================================================== */

/**
 * call_get_merkleized_map_value_u32_le checks `res != 4`, which correctly
 * catches all negative values (since they're all != 4). Verify this.
 */
static void test_u32_le_catches_all_negative_errors(void **state) {
    (void) state;

    int error_codes[] = {-1, -2, -3, -4, -5, -6, -7, -8, -9, -10};

    for (int i = 0; i < 10; i++) {
        merkle_mock_reset();
        merkle_mock_set_leaf_index_retval(0);
        merkle_mock_set_leaf_element_retval(error_codes[i]);

        merkleized_map_commitment_t map = {.size = 5};
        uint8_t key = 0x42;
        uint32_t out_val = 0xDEADBEEF;

        int ret = call_get_merkleized_map_value_u32_le(NULL, &map, &key, 1, &out_val);

        /* u32_le normalizes all errors to -1 (via res != 4 check) */
        assert_int_equal(ret, -1);

        /* The output should NOT have been modified */
        assert_int_equal(out_val, 0xDEADBEEF);
    }
}

/**
 * call_get_merkleized_map_value_u32_le succeeds when exactly 4 bytes are returned.
 */
static void test_u32_le_success(void **state) {
    (void) state;

    merkle_mock_reset();
    merkle_mock_set_leaf_index_retval(0);
    merkle_mock_set_leaf_element_retval(4);  /* returns exactly 4 bytes */

    merkleized_map_commitment_t map = {.size = 5};
    uint8_t key = 0x42;
    uint32_t out_val = 0;

    int ret = call_get_merkleized_map_value_u32_le(NULL, &map, &key, 1, &out_val);

    assert_int_equal(ret, 4);
    /* Mock fills buffer with 0xBB, so u32_le of {0xBB, 0xBB, 0xBB, 0xBB} */
    assert_int_equal(out_val, 0xBBBBBBBB);
}

/**
 * call_get_merkleized_map_value_u32_le rejects when fewer/more than 4 bytes returned.
 */
static void test_u32_le_rejects_wrong_length(void **state) {
    (void) state;

    int wrong_lengths[] = {0, 1, 2, 3, 5, 8, 32};

    for (int i = 0; i < 7; i++) {
        merkle_mock_reset();
        merkle_mock_set_leaf_index_retval(0);
        merkle_mock_set_leaf_element_retval(wrong_lengths[i]);

        merkleized_map_commitment_t map = {.size = 5};
        uint8_t key = 0x42;
        uint32_t out_val = 0xDEADBEEF;

        int ret = call_get_merkleized_map_value_u32_le(NULL, &map, &key, 1, &out_val);

        assert_int_equal(ret, -1);
        /* Output should NOT have been modified */
        assert_int_equal(out_val, 0xDEADBEEF);
    }
}

/* ===================================================================== */
/* Test runner                                                           */
/* ===================================================================== */

int main(void) {
    const struct CMUnitTest tests[] = {
        /* Basic success path */
        cmocka_unit_test(test_map_value_success_returns_length),

        /* Index lookup failure always returns -1 */
        cmocka_unit_test(test_map_value_returns_neg1_on_index_failure),

        /* KEY REGRESSION: leaf_element errors -2..-10 are forwarded, not just -1 */
        cmocka_unit_test(test_map_value_propagates_all_negative_leaf_element_errors),

        /* Demonstrates the old == -1 check bug */
        cmocka_unit_test(test_old_eq_neg1_check_misses_non_neg1_errors),

        /* u32_le helper catches all negatives via != 4 check */
        cmocka_unit_test(test_u32_le_catches_all_negative_errors),

        /* u32_le helper success and wrong-length rejection */
        cmocka_unit_test(test_u32_le_success),
        cmocka_unit_test(test_u32_le_rejects_wrong_length),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
