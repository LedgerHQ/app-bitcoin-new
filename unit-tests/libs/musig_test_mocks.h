#pragma once

/**
 * Mock control interface for musig unit tests.
 *
 * These functions allow tests to configure which mock crypto call should fail,
 * enabling fine-grained control over error paths in musig_nonce_gen and musig_sign.
 */

/**
 * Resets all mock call counters and failure injection points.
 * Must be called in each test's setup or at the start of each test case.
 */
void mock_reset_all(void);

/**
 * Configure cx_math_modm_no_throw to fail on the N-th call (0-indexed).
 * Pass -1 to never fail (default).
 */
void mock_set_modm_fail_at(int call_index);

/**
 * Configure cx_ecfp_scalar_mult_no_throw to fail on the N-th call (0-indexed).
 * Pass -1 to never fail (default).
 */
void mock_set_scalar_mult_fail_at(int call_index);

/**
 * Configure crypto_get_compressed_pubkey to fail on the N-th call (0-indexed).
 * Pass -1 to never fail (default).
 */
void mock_set_compress_fail_at(int call_index);

/**
 * Configure cx_math_cmp_no_throw to fail on the N-th call (0-indexed).
 * Pass -1 to never fail (default).
 */
void mock_set_cmp_fail_at(int call_index);
