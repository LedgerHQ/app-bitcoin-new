/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2024 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>

#include "boilerplate/io.h"
#include "boilerplate/dispatcher.h"
#include "boilerplate/sw.h"
#include "../common/bip32.h"
#include "../commands.h"
#include "../constants.h"
#include "../crypto.h"
#include "../common/read.h"
#include "../ui/display.h"
#include "../ui/menu.h"
#include "lib/get_merkle_leaf_element.h"

#include "handlers.h"

#define DATA_CHUNK_INDEX_1    5
#define DATA_CHUNK_INDEX_2    7
#define CHUNK_SIZE_IN_BYTES   64
#define ADDRESS_SIZE_IN_BYTES 20
#define ADDRESS_SIZE_IN_CHARS 40
#define AMOUNT_SIZE_IN_BYTES  8
#define AMOUNT_SIZE_IN_CHARS  16 + 10

// Constants for hash computation

////////////////////////

static unsigned char const BSM_SIGN_MAGIC[] = {'\x18', 'B', 'i', 't', 'c', 'o', 'i', 'n', ' ',
                                               'S',    'i', 'g', 'n', 'e', 'd', ' ', 'M', 'e',
                                               's',    's', 'a', 'g', 'e', ':', '\n'};

static bool display_data_content_and_confirm(dispatcher_context_t* dc,
                                             uint8_t* data_merkle_root,
                                             size_t n_chunks) {
    reset_streaming_index();
    uint8_t data_chunk[CHUNK_SIZE_IN_BYTES];
    char value[AMOUNT_SIZE_IN_CHARS + 1];
    char spender[ADDRESS_SIZE_IN_BYTES * 2 + 2 + 1];
    char redeemer[ADDRESS_SIZE_IN_BYTES * 2 + 2 + 1];

    // Get the first chunk that contains the data to display
    int current_chunk_len = call_get_merkle_leaf_element(dc,
                                                         data_merkle_root,
                                                         n_chunks,
                                                         DATA_CHUNK_INDEX_1,
                                                         data_chunk,
                                                         CHUNK_SIZE_IN_BYTES);
    // Start Parsing

    // format spender
    const int offset_address = 12;
    spender[0] = '0';
    spender[1] = 'x';
    if (!format_hex(&data_chunk[offset_address],
                    ADDRESS_SIZE_IN_BYTES,
                    spender + 2,
                    sizeof(spender))) {
        return false;
    }
    // format value
    int offset_value = 12 + ADDRESS_SIZE_IN_BYTES + 24;
    uint64_t value_u64 = read_u64_be(data_chunk, offset_value);

    if (!format_fpu64(value, sizeof(value), value_u64, 18)) {
        return false;
    };

    // Concat the COIN_COINID_SHORT to the value
    char value_with_ticker[AMOUNT_SIZE_IN_CHARS + 1 + 5 + 1];
    snprintf(value_with_ticker, sizeof(value_with_ticker), "%s %s", COIN_COINID_SHORT, value);

    // Trim the value of trailing zeros in a char of size of value
    int i = sizeof(value_with_ticker) - 1;
    while (value_with_ticker[i] == '0' || value_with_ticker[i] == '\0') {
        value_with_ticker[i] = '\0';
        i--;
    }
    // Get the second chunk that contains the data to display
    current_chunk_len = call_get_merkle_leaf_element(dc,
                                                     data_merkle_root,
                                                     n_chunks,
                                                     DATA_CHUNK_INDEX_2,
                                                     data_chunk,
                                                     CHUNK_SIZE_IN_BYTES);

    // format redeemer
    redeemer[0] = '0';
    redeemer[1] = 'x';
    if (!format_hex(&data_chunk[offset_address],
                    ADDRESS_SIZE_IN_BYTES,
                    redeemer + 2,
                    sizeof(redeemer))) {
        return false;
    }

    // Display data
    if (!ui_validate_withdraw_data_and_confirm(dc, spender, value_with_ticker, redeemer)) {
        return false;

        // while (get_streaming_index() <= (n_chunks - 1)) {
        // }
    }

    return true;
}

/**
 * @brief Adds leading zeroes to a source buffer and copies it to a destination buffer.
 *
 * This function clears the destination buffer, calculates the offset where the source data
 * should start, and then copies the source data to the destination buffer starting from
 * the calculated offset. The leading part of the destination buffer will be filled with zeroes.
 *
 * @param dest_buffer Pointer to the destination buffer.
 * @param dest_size Size of the destination buffer.
 * @param src_buffer Pointer to the source buffer.
 * @param src_size Size of the source buffer.
 */
void add_leading_zeroes(uint8_t* dest_buffer,
                        size_t dest_size,
                        uint8_t* src_buffer,
                        size_t src_size) {
    // Clear the destination buffer
    memset(dest_buffer, 0, dest_size);

    // Calculate the offset where the data should start
    size_t buffer_offset = dest_size - src_size;

    // Copy the source data to the destination buffer starting from the calculated offset
    memcpy(dest_buffer + buffer_offset, src_buffer, src_size);
}

void fetch_and_add_chunk_to_hash(dispatcher_context_t* dc,
                                 uint8_t* data_merkle_root,
                                 size_t n_chunks,
                                 cx_sha3_t* hash_context,
                                 size_t chunk_index,
                                 size_t chunk_offset,
                                 size_t chunk_data_size,
                                 bool abi_encode) {
    uint8_t data_chunk[CHUNK_SIZE_IN_BYTES];
    int current_chunk_len = call_get_merkle_leaf_element(dc,
                                                         data_merkle_root,
                                                         n_chunks,
                                                         chunk_index,
                                                         data_chunk,
                                                         CHUNK_SIZE_IN_BYTES);
    if (current_chunk_len < 0) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        ui_post_processing_confirm_withdraw(dc, false);
        return;
    }
    size_t input_buffer_size;
    uint8_t input_buffer[32];

    if (abi_encode) {
        input_buffer_size = 32;
        add_leading_zeroes(input_buffer,
                           sizeof(input_buffer),
                           data_chunk + chunk_offset,
                           chunk_data_size);
    } else {
        input_buffer_size = chunk_data_size;
        memcpy(input_buffer, data_chunk + chunk_offset, input_buffer_size);
    }
    CX_THROW(cx_hash_no_throw((cx_hash_t*) hash_context,
                              0,                  // mode
                              input_buffer,       // input data
                              input_buffer_size,  // input length
                              NULL,               // output (intermediate)
                              0));                // no output yet
}
/**
 * @brief Fetches a chunk of data from a Merkle tree and adds it to the output buffer.
 *
 * This function retrieves a specific chunk of data from a Merkle tree using the provided
 * dispatcher context and Merkle root. The chunk is then optionally ABI-encoded and added
 * to the specified position in the output buffer.
 *
 * @param dc The dispatcher context used for the operation.
 * @param data_merkle_root The Merkle root of the data tree.
 * @param n_chunks The total number of chunks in the data tree.
 * @param chunk_index The index of the chunk to fetch.
 * @param chunk_offset The offset within the chunk to start reading data from.
 * @param chunk_data_size The size of the data to read from the chunk.
 * @param abi_encode A boolean flag indicating whether to ABI-encode the data.
 * @param output_buffer The buffer to which the fetched data will be added.
 * @param output_buffer_offset The offset within the output buffer to start writing data to.
 */
void fetch_and_add_chunk_to_buffer(dispatcher_context_t* dc,
                                   uint8_t* data_merkle_root,
                                   size_t n_chunks,
                                   size_t chunk_index,
                                   size_t chunk_offset,
                                   size_t chunk_data_size,
                                   bool abi_encode,
                                   uint8_t* output_buffer,
                                   size_t output_buffer_offset) {
    uint8_t data_chunk[CHUNK_SIZE_IN_BYTES];
    int current_chunk_len = call_get_merkle_leaf_element(dc,
                                                         data_merkle_root,
                                                         n_chunks,
                                                         chunk_index,
                                                         data_chunk,
                                                         CHUNK_SIZE_IN_BYTES);
    if (current_chunk_len < 0) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        ui_post_processing_confirm_withdraw(dc, false);
        return;
    }
    size_t input_buffer_size;
    uint8_t input_buffer[32];

    if (abi_encode && chunk_data_size < 32) {
        input_buffer_size = 32;
        add_leading_zeroes(input_buffer,
                           sizeof(input_buffer),
                           data_chunk + chunk_offset,
                           chunk_data_size);
    } else {
        input_buffer_size = chunk_data_size;
        memcpy(input_buffer, data_chunk + chunk_offset, input_buffer_size);
    }
    memcpy(output_buffer + output_buffer_offset, input_buffer, input_buffer_size);
}

void fetch_and_hash_tx_data(dispatcher_context_t* dc,
                            uint8_t* data_merkle_root,
                            size_t n_chunks,
                            cx_sha3_t* hash_context,
                            uint8_t* output_buffer) {
    // Fetch and add the first 4 bytes of the tx.data to the hash
    fetch_and_add_chunk_to_hash(dc, data_merkle_root, n_chunks, hash_context, 4, 0, 4, false);
    // Fetch and add the other value is tx.data to the hash
    for (size_t i = 5; i < n_chunks; i++) {
        // Fetch and add data[32] to the hash
        fetch_and_add_chunk_to_hash(dc, data_merkle_root, n_chunks, hash_context, i, 0, 32, false);
        // Fetch and add data[32] to the hash
        fetch_and_add_chunk_to_hash(dc, data_merkle_root, n_chunks, hash_context, i, 32, 32, false);
    }
    // Finalize the hash and store the result in output_hash
    CX_THROW(cx_hash_no_throw((cx_hash_t*) hash_context,
                              CX_LAST,        // final block mode
                              NULL,           // no more input
                              0,              // no more input length
                              output_buffer,  // output hash buffer
                              32));           // output hash length (32 bytes)
}

void fetch_and_abi_encode_tx_fields(dispatcher_context_t* dc,
                                    uint8_t* data_merkle_root,
                                    size_t n_chunks,
                                    uint8_t* keccak_of_tx_data,
                                    uint8_t* output_buffer) {
    size_t offset = 0;
    // Fetch 'SafeTxTypeHash' field, add leading zeroes and add to output_buffer
    offset += 32;
    // Fetch 'to' field, add leading zeroes and add to output_buffer
    fetch_and_add_chunk_to_buffer(dc,
                                  data_merkle_root,
                                  n_chunks,
                                  0,
                                  0,
                                  20,
                                  true,
                                  output_buffer,
                                  offset);
    offset += 32;
    // Fetch 'value' field, add leading zeroes and add to output_buffer
    fetch_and_add_chunk_to_buffer(dc,
                                  data_merkle_root,
                                  n_chunks,
                                  1,
                                  0,
                                  32,
                                  true,
                                  output_buffer,
                                  offset);
    offset += 32;
    // Add keccak_of_tx_data to output_buffer
    memcpy(output_buffer + offset, keccak_of_tx_data, 32);
    offset += 32;
    // Fetch 'operation' field, add leading zeroes and add to output_buffer
    fetch_and_add_chunk_to_buffer(dc,
                                  data_merkle_root,
                                  n_chunks,
                                  3,
                                  0,
                                  1,
                                  true,
                                  output_buffer,
                                  offset);
    offset += 32;
    // Fetch 'safeTXGas' field, add leading zeroes and add to output_buffer
    fetch_and_add_chunk_to_buffer(dc,
                                  data_merkle_root,
                                  n_chunks,
                                  1,
                                  32,
                                  32,
                                  true,
                                  output_buffer,
                                  offset);
    offset += 32;
    // Fetch 'baseGas' field, add leading zeroes and add to output_buffer
    fetch_and_add_chunk_to_buffer(dc,
                                  data_merkle_root,
                                  n_chunks,
                                  2,
                                  1,
                                  32,
                                  true,
                                  output_buffer,
                                  offset);
    offset += 32;
    // Fetch 'gasPrice' field, add leading zeroes and add to output_buffer
    fetch_and_add_chunk_to_buffer(dc,
                                  data_merkle_root,
                                  n_chunks,
                                  2,
                                  32,
                                  32,
                                  true,
                                  output_buffer,
                                  offset);
    offset += 32;
    // Fetch 'gasToken' field, add leading zeroes and add to output_buffer
    fetch_and_add_chunk_to_buffer(dc,
                                  data_merkle_root,
                                  n_chunks,
                                  0,
                                  20,
                                  20,
                                  true,
                                  output_buffer,
                                  offset);
    offset += 32;
    // Fetch 'refundReceiver' field, add leading zeroes and add to output_buffer
    fetch_and_add_chunk_to_buffer(dc,
                                  data_merkle_root,
                                  n_chunks,
                                  0,
                                  40,
                                  20,
                                  true,
                                  output_buffer,
                                  offset);
    offset += 32;
    // Fetch '_nonce' field, add leading zeroes and add to output_buffer
    fetch_and_add_chunk_to_buffer(dc,
                                  data_merkle_root,
                                  n_chunks,
                                  3,
                                  0,
                                  32,
                                  true,
                                  output_buffer,
                                  offset);
    offset += 32;
}

void compute_tx_hash(dispatcher_context_t* dc,
                     uint8_t* data_merkle_root,
                     size_t n_chunks,
                     u_int8_t output_buffer[32]) {
    cx_sha3_t hash_context;

    // Initialize the SHA-3 context for Keccak-256 (256-bit output)
    CX_THROW(cx_keccak_init_no_throw(&hash_context, 256));
    u_int8_t keccak_of_tx_data[32];
    // Compute keccak256 hash of the tx_data_data
    fetch_and_hash_tx_data(dc, data_merkle_root, n_chunks, &hash_context, keccak_of_tx_data);
    // Fetch and ABI-encode the tx fields
    u_int8_t abi_encoded_tx_fields[32 * 11];
    fetch_and_abi_encode_tx_fields(dc,
                                   data_merkle_root,
                                   n_chunks,
                                   keccak_of_tx_data,
                                   &abi_encoded_tx_fields);
    // Abi.encode 2
    // Compute keccak256 hash of abi.encode 2
    // Abi.encodePacked
    // Keccak256 hash of abi.encodePacked
}

void handler_withdraw(dispatcher_context_t* dc, uint8_t protocol_version) {
    (void) protocol_version;

    uint8_t bip32_path_len;
    uint32_t bip32_path[MAX_BIP32_PATH_STEPS];
    uint64_t n_chunks;
    uint8_t data_merkle_root[32];

    if (!buffer_read_u8(&dc->read_buffer, &bip32_path_len) ||
        !buffer_read_bip32_path(&dc->read_buffer, bip32_path, bip32_path_len) ||
        !buffer_read_varint(&dc->read_buffer, &n_chunks) ||
        !buffer_read_bytes(&dc->read_buffer, data_merkle_root, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        ui_post_processing_confirm_withdraw(dc, false);
        return;
    }

    if (bip32_path_len > MAX_BIP32_PATH_STEPS) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        ui_post_processing_confirm_withdraw(dc, false);
        return;
    }

    char path_str[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1] = "(Master key)";
    if (bip32_path_len > 0) {
        bip32_path_format(bip32_path, bip32_path_len, path_str, sizeof(path_str));
    }

#ifndef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    // // ui_pre_processing_message();
    // if (!display_data_content_and_confirm(dc, data_merkle_root, n_chunks)) {
    //     SEND_SW(dc, SW_DENY);
    //     ui_post_processing_confirm_withdraw(dc, false);
    //     return;
    // }

#endif
    // COMPUTE THE HASH THAT WE WILL SIGN
    uint8_t tx_hash[32];
    compute_tx_hash(dc, data_merkle_root, n_chunks, tx_hash);
    // SIGN MESSAGE (the message is the hash previously computed)

    // Send the response to the JS Library
    uint8_t sig[65];
    SEND_RESPONSE(dc, sig, sizeof(sig), SW_OK);
    ui_post_processing_confirm_withdraw(dc, true);
    return;
}