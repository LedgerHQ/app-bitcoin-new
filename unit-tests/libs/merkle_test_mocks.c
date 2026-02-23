/**
 * Mock implementations for merkle/map value unit tests.
 *
 * Provides controllable mock versions of:
 *   - call_get_merkle_leaf_index()
 *   - call_get_merkle_leaf_element()
 *   - merkle_compute_element_hash()
 *
 * These are the three functions called by call_get_merkleized_map_value().
 */

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "merkle_test_mocks.h"

/* Minimal type definitions needed - dispatcher_context_t is an opaque pointer here */
typedef struct dispatcher_context_s dispatcher_context_t;

/* ---------- Internal mock state ---------- */

static int g_leaf_index_retval = 0;
static int g_leaf_element_retval = 0;

/* ---------- Mock control API ---------- */

void merkle_mock_reset(void) {
    g_leaf_index_retval = 0;
    g_leaf_element_retval = 0;
}

void merkle_mock_set_leaf_index_retval(int retval) {
    g_leaf_index_retval = retval;
}

void merkle_mock_set_leaf_element_retval(int retval) {
    g_leaf_element_retval = retval;
}

/* ---------- Mocked functions ---------- */

/**
 * Mock merkle_compute_element_hash.
 * Just fills the output with a dummy hash (no real SHA256 needed).
 */
void merkle_compute_element_hash(const uint8_t *in, size_t in_len, uint8_t out[32]) {
    (void) in;
    (void) in_len;
    memset(out, 0xAA, 32);
}

/**
 * Mock call_get_merkle_leaf_index.
 * Returns whatever was configured via merkle_mock_set_leaf_index_retval().
 *
 * In real code, can return:
 *   >= 0 on success (the index)
 *   -1   parse failure
 *   -2   invalid found value
 *   -3   not found / interruption failure
 *   -4   hash failure
 *   -5   hash mismatch
 */
int call_get_merkle_leaf_index(dispatcher_context_t *dispatcher_context,
                               size_t size,
                               const uint8_t root[32],
                               const uint8_t leaf_hash[32]) {
    (void) dispatcher_context;
    (void) size;
    (void) root;
    (void) leaf_hash;
    return g_leaf_index_retval;
}

/**
 * Mock call_get_merkle_leaf_element.
 * Returns whatever was configured via merkle_mock_set_leaf_element_retval().
 *
 * When the configured return value is >= 0 (success), fills the output buffer
 * with a pattern of that many bytes.
 *
 * In real code, can return:
 *   >= 0  on success (the length of the element)
 *   -1 through -10  from call_get_merkle_preimage (various error codes)
 */
int call_get_merkle_leaf_element(dispatcher_context_t *dispatcher_context,
                                 const uint8_t merkle_root[32],
                                 uint32_t tree_size,
                                 uint32_t leaf_index,
                                 uint8_t *out_ptr,
                                 size_t out_ptr_len) {
    (void) dispatcher_context;
    (void) merkle_root;
    (void) tree_size;
    (void) leaf_index;

    if (g_leaf_element_retval >= 0) {
        /* Simulate a successful read: fill buffer with dummy data */
        size_t fill_len = (size_t) g_leaf_element_retval;
        if (fill_len > out_ptr_len) {
            fill_len = out_ptr_len;
        }
        memset(out_ptr, 0xBB, fill_len);
    }
    return g_leaf_element_retval;
}
