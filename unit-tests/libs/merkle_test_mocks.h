#pragma once

/**
 * Mock control interface for merkle/map value unit tests.
 *
 * These allow configuring what call_get_merkle_leaf_index and
 * call_get_merkle_leaf_element return, enabling us to test
 * call_get_merkleized_map_value's error propagation behavior.
 */

/**
 * Resets all mock state. Call before each test.
 */
void merkle_mock_reset(void);

/**
 * Set the return value that the mock call_get_merkle_leaf_index will return
 * on the next call.
 */
void merkle_mock_set_leaf_index_retval(int retval);

/**
 * Set the return value that the mock call_get_merkle_leaf_element will return
 * on the next call. When >= 0, the mock will also fill the output buffer
 * with a dummy pattern.
 */
void merkle_mock_set_leaf_element_retval(int retval);
