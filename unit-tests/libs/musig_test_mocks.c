/**
 * Mock implementations of SDK crypto functions for musig unit tests.
 *
 * These mocks allow musig.c to compile and link in the unit test environment.
 * They provide configurable failure injection to test error handling paths.
 */

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cx_errors.h"
#include "musig_test_mocks.h"

/* ---------- Internal mock state ---------- */

static int g_modm_call_count;
static int g_modm_fail_at;

static int g_scalar_mult_call_count;
static int g_scalar_mult_fail_at;

static int g_compress_call_count;
static int g_compress_fail_at;

static int g_cmp_call_count;
static int g_cmp_fail_at;

static int g_hash_digest_count;  /* counts CX_LAST calls to produce distinct outputs */

/* ---------- Mock control API ---------- */

void mock_reset_all(void) {
    g_modm_call_count = 0;
    g_modm_fail_at = -1;

    g_scalar_mult_call_count = 0;
    g_scalar_mult_fail_at = -1;

    g_compress_call_count = 0;
    g_compress_fail_at = -1;

    g_cmp_call_count = 0;
    g_cmp_fail_at = -1;

    g_hash_digest_count = 0;
}

void mock_set_modm_fail_at(int call_index) {
    g_modm_fail_at = call_index;
}

void mock_set_scalar_mult_fail_at(int call_index) {
    g_scalar_mult_fail_at = call_index;
}

void mock_set_compress_fail_at(int call_index) {
    g_compress_fail_at = call_index;
}

void mock_set_cmp_fail_at(int call_index) {
    g_cmp_fail_at = call_index;
}

/* ---------- SDK crypto function mocks ---------- */

/**
 * Mock cx_hash_no_throw.
 *
 * When mode includes CX_LAST (1), fills the output with a predictable non-zero pattern
 * so that nonce hash outputs are not accidentally all zeros.
 * Different calls produce different patterns (0xAA, 0xAB, ...).
 */
cx_err_t cx_hash_no_throw(cx_hash_t *hash,
                          int mode,
                          const unsigned char *in,
                          unsigned int len,
                          unsigned char *out,
                          unsigned int out_len) {
    (void) hash;
    (void) in;
    (void) len;

    if ((mode & CX_LAST) && out != NULL && out_len > 0) {
        /* Fill with a distinct non-zero pattern per digest call */
        uint8_t fill = (uint8_t)(0xAA + g_hash_digest_count);
        memset(out, fill, out_len);
        /* Make last byte different to avoid any zero-array checks */
        out[out_len - 1] = (uint8_t)(fill ^ 0x01);
        g_hash_digest_count++;
    }
    return CX_OK;
}

/**
 * Mock cx_sha256_init_no_throw - no-op, just returns success.
 */
cx_err_t cx_sha256_init_no_throw(cx_sha256_t *hash) {
    if (hash) {
        memset(hash, 0, sizeof(cx_sha256_t));
        hash->header.algo = CX_SHA256;
    }
    return CX_OK;
}

/**
 * Mock cx_math_modm_no_throw.
 * Returns CX_INTERNAL_ERROR at the configured call index.
 * Otherwise returns CX_OK without modifying the data.
 */
cx_err_t cx_math_modm_no_throw(unsigned char *v,
                               unsigned int len_v,
                               const unsigned char *m,
                               unsigned int len_m) {
    (void) v;
    (void) len_v;
    (void) m;
    (void) len_m;

    int current = g_modm_call_count++;
    if (g_modm_fail_at >= 0 && current == g_modm_fail_at) {
        return CX_INTERNAL_ERROR;
    }
    return CX_OK;
}

/**
 * Mock cx_math_cmp_no_throw.
 * On success, sets *diff = -1 (meaning a < b), which allows range checks to pass.
 */
cx_err_t cx_math_cmp_no_throw(const unsigned char *a,
                              const unsigned char *b,
                              unsigned int len,
                              int *diff) {
    (void) a;
    (void) b;
    (void) len;

    int current = g_cmp_call_count++;
    if (g_cmp_fail_at >= 0 && current == g_cmp_fail_at) {
        return CX_INTERNAL_ERROR;
    }
    /* Set diff to -1 so that "diff >= 0" checks pass (value is in range) */
    if (diff) {
        *diff = -1;
    }
    return CX_OK;
}

/**
 * Mock cx_math_sub_no_throw - success without modifying data.
 */
cx_err_t cx_math_sub_no_throw(unsigned char *r,
                              const unsigned char *a,
                              const unsigned char *b,
                              unsigned int len) {
    (void) r;
    (void) a;
    (void) b;
    (void) len;
    return CX_OK;
}

/**
 * Mock cx_math_multm_no_throw - success, fills r with non-zero pattern.
 */
cx_err_t cx_math_multm_no_throw(unsigned char *r,
                                const unsigned char *a,
                                const unsigned char *b,
                                const unsigned char *m,
                                unsigned int len) {
    (void) a;
    (void) b;
    (void) m;
    if (r && len > 0) {
        memset(r, 0x11, len);
    }
    return CX_OK;
}

/**
 * Mock cx_math_addm_no_throw - success, fills r with non-zero pattern.
 */
cx_err_t cx_math_addm_no_throw(unsigned char *r,
                               const unsigned char *a,
                               const unsigned char *b,
                               const unsigned char *m,
                               unsigned int len) {
    (void) a;
    (void) b;
    (void) m;
    if (r && len > 0) {
        memset(r, 0x22, len);
    }
    return CX_OK;
}

/**
 * Mock cx_ecfp_scalar_mult_no_throw.
 * On success, sets P to a fake valid uncompressed point (04 || x || y).
 */
cx_err_t cx_ecfp_scalar_mult_no_throw(cx_curve_t curve,
                                      unsigned char *P,
                                      const unsigned char *k,
                                      unsigned int k_len) {
    (void) curve;
    (void) k;
    (void) k_len;

    int current = g_scalar_mult_call_count++;
    if (g_scalar_mult_fail_at >= 0 && current == g_scalar_mult_fail_at) {
        return CX_INTERNAL_ERROR;
    }

    /* Set P to a fake valid uncompressed point: 04 || x(32 bytes) || y(32 bytes)
     * y[31] is even so has_even_y returns true */
    if (P) {
        P[0] = 0x04;
        memset(P + 1, 0xCC, 32);   /* x */
        memset(P + 33, 0xDD, 31);  /* y[0..30] */
        P[64] = 0x02;              /* y[31] even */
    }
    return CX_OK;
}

/**
 * Mock cx_ecfp_add_point_no_throw.
 * Copies P to R (simplistic, but sufficient for testing).
 */
cx_err_t cx_ecfp_add_point_no_throw(cx_curve_t curve,
                                    unsigned char *R,
                                    const unsigned char *P,
                                    const unsigned char *Q) {
    (void) curve;
    (void) Q;
    if (R && P) {
        memmove(R, P, 65);
    }
    return CX_OK;
}

/* ---------- App crypto function mocks ---------- */

/**
 * Mock crypto_tr_tagged_hash_init - just initializes the hash context.
 */
void crypto_tr_tagged_hash_init(cx_sha256_t *hash_context,
                                const uint8_t *tag,
                                uint16_t tag_len) {
    (void) tag;
    (void) tag_len;
    if (hash_context) {
        memset(hash_context, 0, sizeof(cx_sha256_t));
        hash_context->header.algo = CX_SHA256;
    }
}

/**
 * Mock crypto_tr_tagged_hash (one-shot version) - fills output with non-zero pattern.
 */
void crypto_tr_tagged_hash(const uint8_t *tag,
                           uint16_t tag_len,
                           const uint8_t *data,
                           uint16_t data_len,
                           const uint8_t *data2,
                           uint16_t data2_len,
                           uint8_t out[32]) {
    (void) tag;
    (void) tag_len;
    (void) data;
    (void) data_len;
    (void) data2;
    (void) data2_len;
    memset(out, 0x55, 32);
}

/**
 * Mock crypto_get_compressed_pubkey.
 * On success, fills out with a fake compressed pubkey (02 || 32 bytes).
 */
int crypto_get_compressed_pubkey(const uint8_t uncompressed_key[65],
                                 uint8_t out[33]) {
    (void) uncompressed_key;

    int current = g_compress_call_count++;
    if (g_compress_fail_at >= 0 && current == g_compress_fail_at) {
        return -1;
    }

    out[0] = 0x02;
    memset(out + 1, 0xBB, 32);
    return 0;
}

/**
 * Mock crypto_tr_lift_x - fills output with a fake uncompressed point.
 */
int crypto_tr_lift_x(const uint8_t x[32], uint8_t out[65]) {
    (void) x;
    out[0] = 0x04;
    memset(out + 1, 0xEE, 32);
    memset(out + 33, 0x02, 32);  /* even y */
    return 0;
}
