/**
 * Non-regression unit tests for the musig nonce zeroing changes.
 *
 * These tests verify that musig_nonce_gen properly zeroes secret nonce material
 * (secnonce->k_1 and secnonce->k_2) on ALL failure paths, not just on success.
 *
 * Before the fix, failures in point_mul or crypto_get_compressed_pubkey would
 * return -1 without zeroing the computed nonce values, potentially leaking
 * secret nonce material on the stack/in the caller's struct.
 *
 * After the fix, all error paths go through `nonce_gen_fail:` which explicitly
 * zeroes k_1 and k_2 before returning.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "musig/musig.h"
#include "musig_test_mocks.h"

/* ---------- Helper: check if a buffer is all zeros ---------- */
static bool is_all_zeros(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0) return false;
    }
    return true;
}

/* ---------- Common test data ---------- */

/* Fake 32-byte randomness */
static const uint8_t test_rand[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
};

/* Fake compressed public key (33 bytes: 02 || x) */
static const plain_pk_t test_pk = {
    0x02,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
};

/* Fake x-only aggregate public key (32 bytes) */
static const xonly_pk_t test_aggpk = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
};

/* ---------- Test: success path - secnonce should contain non-zero nonces ---------- */

/**
 * Verifies that on a successful call, secnonce contains non-zero k_1 and k_2.
 * This is a sanity check that our mocks produce meaningful (non-zero) nonce values.
 * Without this, the zeroing tests would be vacuously true.
 */
static void test_nonce_gen_success_has_nonzero_nonces(void **state) {
    (void) state;

    mock_reset_all();

    musig_secnonce_t secnonce;
    musig_pubnonce_t pubnonce;
    memset(&secnonce, 0, sizeof(secnonce));
    memset(&pubnonce, 0, sizeof(pubnonce));

    int ret = musig_nonce_gen(test_rand, sizeof(test_rand), test_pk, test_aggpk,
                              &secnonce, &pubnonce);

    assert_int_equal(ret, 0);
    /* k_1 and k_2 must be non-zero after a successful nonce generation */
    assert_false(is_all_zeros(secnonce.k_1, sizeof(secnonce.k_1)));
    assert_false(is_all_zeros(secnonce.k_2, sizeof(secnonce.k_2)));
}

/* ---------- Failure tests: secnonce must be zeroed on every error path ---------- */

/**
 * Fail cx_math_modm_no_throw on the 1st call (reducing k_1).
 *
 * At this point: k_1 contains the hash output (non-zero), k_2 is uninitialized.
 * The fix ensures BOTH k_1 and k_2 are zeroed via nonce_gen_fail.
 */
static void test_nonce_gen_zeroes_on_modm_k1_failure(void **state) {
    (void) state;

    mock_reset_all();
    mock_set_modm_fail_at(0);  /* fail on first modm call (k_1) */

    musig_secnonce_t secnonce;
    musig_pubnonce_t pubnonce;
    /* Pre-fill with 0xFF to detect zeroing */
    memset(&secnonce, 0xFF, sizeof(secnonce));
    memset(&pubnonce, 0xFF, sizeof(pubnonce));

    int ret = musig_nonce_gen(test_rand, sizeof(test_rand), test_pk, test_aggpk,
                              &secnonce, &pubnonce);

    assert_int_equal(ret, -1);
    assert_true(is_all_zeros(secnonce.k_1, sizeof(secnonce.k_1)));
    assert_true(is_all_zeros(secnonce.k_2, sizeof(secnonce.k_2)));
}

/**
 * Fail cx_math_modm_no_throw on the 2nd call (reducing k_2).
 *
 * At this point: k_1 has been successfully reduced (non-zero hash),
 * k_2 contains the hash output but modm failed.
 * Both must be zeroed.
 */
static void test_nonce_gen_zeroes_on_modm_k2_failure(void **state) {
    (void) state;

    mock_reset_all();
    mock_set_modm_fail_at(1);  /* fail on second modm call (k_2) */

    musig_secnonce_t secnonce;
    musig_pubnonce_t pubnonce;
    memset(&secnonce, 0xFF, sizeof(secnonce));
    memset(&pubnonce, 0xFF, sizeof(pubnonce));

    int ret = musig_nonce_gen(test_rand, sizeof(test_rand), test_pk, test_aggpk,
                              &secnonce, &pubnonce);

    assert_int_equal(ret, -1);
    assert_true(is_all_zeros(secnonce.k_1, sizeof(secnonce.k_1)));
    assert_true(is_all_zeros(secnonce.k_2, sizeof(secnonce.k_2)));
}

/**
 * Fail cx_ecfp_scalar_mult_no_throw on the 1st call (computing R_s1 = k_1 * G).
 *
 * At this point: BOTH k_1 and k_2 have been successfully computed as valid nonces.
 * This is the critical regression test: before the fix, this failure path did
 * `return -1` leaving the nonce values in secnonce, potentially leaking them.
 */
static void test_nonce_gen_zeroes_on_point_mul_R1_failure(void **state) {
    (void) state;

    mock_reset_all();
    mock_set_scalar_mult_fail_at(0);  /* fail on first point_mul (R_s1) */

    musig_secnonce_t secnonce;
    musig_pubnonce_t pubnonce;
    memset(&secnonce, 0xFF, sizeof(secnonce));
    memset(&pubnonce, 0xFF, sizeof(pubnonce));

    int ret = musig_nonce_gen(test_rand, sizeof(test_rand), test_pk, test_aggpk,
                              &secnonce, &pubnonce);

    assert_int_equal(ret, -1);
    assert_true(is_all_zeros(secnonce.k_1, sizeof(secnonce.k_1)));
    assert_true(is_all_zeros(secnonce.k_2, sizeof(secnonce.k_2)));
}

/**
 * Fail cx_ecfp_scalar_mult_no_throw on the 2nd call (computing R_s2 = k_2 * G).
 *
 * Same as above but the failure happens one step later.
 * Before the fix, k_1 and k_2 would remain in secnonce.
 */
static void test_nonce_gen_zeroes_on_point_mul_R2_failure(void **state) {
    (void) state;

    mock_reset_all();
    mock_set_scalar_mult_fail_at(1);  /* fail on second point_mul (R_s2) */

    musig_secnonce_t secnonce;
    musig_pubnonce_t pubnonce;
    memset(&secnonce, 0xFF, sizeof(secnonce));
    memset(&pubnonce, 0xFF, sizeof(pubnonce));

    int ret = musig_nonce_gen(test_rand, sizeof(test_rand), test_pk, test_aggpk,
                              &secnonce, &pubnonce);

    assert_int_equal(ret, -1);
    assert_true(is_all_zeros(secnonce.k_1, sizeof(secnonce.k_1)));
    assert_true(is_all_zeros(secnonce.k_2, sizeof(secnonce.k_2)));
}

/**
 * Fail crypto_get_compressed_pubkey on the 1st call (compressing R_s1).
 *
 * k_1 and k_2 contain valid nonce values. Before the fix, the nonce values
 * would remain in secnonce after this failure.
 */
static void test_nonce_gen_zeroes_on_compress_R1_failure(void **state) {
    (void) state;

    mock_reset_all();
    mock_set_compress_fail_at(0);  /* fail on first compress (R_s1) */

    musig_secnonce_t secnonce;
    musig_pubnonce_t pubnonce;
    memset(&secnonce, 0xFF, sizeof(secnonce));
    memset(&pubnonce, 0xFF, sizeof(pubnonce));

    int ret = musig_nonce_gen(test_rand, sizeof(test_rand), test_pk, test_aggpk,
                              &secnonce, &pubnonce);

    assert_int_equal(ret, -1);
    assert_true(is_all_zeros(secnonce.k_1, sizeof(secnonce.k_1)));
    assert_true(is_all_zeros(secnonce.k_2, sizeof(secnonce.k_2)));
}

/**
 * Fail crypto_get_compressed_pubkey on the 2nd call (compressing R_s2).
 *
 * This is the latest possible failure point. Before the fix, the nonce values
 * would remain in secnonce.
 */
static void test_nonce_gen_zeroes_on_compress_R2_failure(void **state) {
    (void) state;

    mock_reset_all();
    mock_set_compress_fail_at(1);  /* fail on second compress (R_s2) */

    musig_secnonce_t secnonce;
    musig_pubnonce_t pubnonce;
    memset(&secnonce, 0xFF, sizeof(secnonce));
    memset(&pubnonce, 0xFF, sizeof(pubnonce));

    int ret = musig_nonce_gen(test_rand, sizeof(test_rand), test_pk, test_aggpk,
                              &secnonce, &pubnonce);

    assert_int_equal(ret, -1);
    assert_true(is_all_zeros(secnonce.k_1, sizeof(secnonce.k_1)));
    assert_true(is_all_zeros(secnonce.k_2, sizeof(secnonce.k_2)));
}

/* ---------- Test runner ---------- */

int main(void) {
    const struct CMUnitTest tests[] = {
        /* Sanity: success produces non-zero nonces (validates mock correctness) */
        cmocka_unit_test(test_nonce_gen_success_has_nonzero_nonces),

        /* Regression: every failure path must zero k_1 and k_2 */
        cmocka_unit_test(test_nonce_gen_zeroes_on_modm_k1_failure),
        cmocka_unit_test(test_nonce_gen_zeroes_on_modm_k2_failure),
        cmocka_unit_test(test_nonce_gen_zeroes_on_point_mul_R1_failure),
        cmocka_unit_test(test_nonce_gen_zeroes_on_point_mul_R2_failure),
        cmocka_unit_test(test_nonce_gen_zeroes_on_compress_R1_failure),
        cmocka_unit_test(test_nonce_gen_zeroes_on_compress_R2_failure),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
