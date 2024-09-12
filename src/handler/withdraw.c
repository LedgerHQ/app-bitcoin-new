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
 * @brief Fetches a chunk of data from a Merkle tree and adds it to a hash.
 *
 * This function retrieves a specific chunk of data from a Merkle tree using the provided
 * dispatcher context and Merkle root. The retrieved chunk is then added to a hash buffer
 * at a specified offset and hashed using the provided SHA-3 context.
 *
 * @param dc                Pointer to the dispatcher context. (in)
 * @param data_merkle_root  Pointer to the Merkle root of the data. (in)
 * @param n_chunks          Total number of chunks in the Merkle tree. (in)
 * @param chunk_index       Index of the chunk to fetch. (in)
 * @param hash              Pointer to the SHA-3 hash context. (in/out)
 * @param buffer_offset     Offset within the hash buffer where the chunk data should be added. (in)
 * @param chunk_offset      Offset within the chunk data to start copying from. (in)
 * @param chunk_data_size   Size of the chunk data to copy. (in)
 *
 * @return void
 */
void fetch_and_add_chunk_to_hash(dispatcher_context_t* dc,
                                 uint8_t* data_merkle_root,
                                 size_t n_chunks,
                                 size_t chunk_index,
                                 cx_sha3_t* hash,
                                 size_t buffer_offset,
                                 size_t chunk_offset,
                                 size_t chunk_data_size) {
    uint8_t data_chunk[CHUNK_SIZE_IN_BYTES];
    int current_chunk_len = call_get_merkle_leaf_element(dc,
                                                         data_merkle_root,
                                                         n_chunks,
                                                         chunk_index,
                                                         data_chunk,
                                                         CHUNK_SIZE_IN_BYTES);
    if (current_chunk_len < 0) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
    }
    uint8_t hash_buffer[32];
    memset(hash_buffer, 0, sizeof(hash_buffer));

    memcpy(hash_buffer + buffer_offset, data_chunk + chunk_offset, chunk_data_size);

    CX_THROW(cx_hash_no_throw((cx_hash_t*) hash,
                              0,                    // mode
                              hash_buffer,          // input
                              sizeof(hash_buffer),  // input length
                              NULL,                 // output
                              0));                  // output length
}

void compute_hash(dispatcher_context_t* dc,
                  uint8_t* data_merkle_root,
                  size_t n_chunks,
                  cx_sha3_t* hash) {
    CX_THROW(cx_keccak_init_no_throw(hash, 256));

    fetch_and_add_chunk_to_hash(dc,
                                data_merkle_root,
                                n_chunks,
                                0,
                                hash,
                                12,
                                0,
                                ADDRESS_SIZE_IN_BYTES);
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
    // ui_pre_processing_message();
    if (!display_data_content_and_confirm(dc, data_merkle_root, n_chunks)) {
        SEND_SW(dc, SW_DENY);
        ui_post_processing_confirm_withdraw(dc, false);
        return;
    }

#endif
    // COMPUTE THE HASH THAT WE WILL SIGN
    cx_sha3_t hash;
    compute_hash(dc, data_merkle_root, n_chunks, &hash);
    // SIGN MESSAGE (the message is the hash previously computed)
    uint8_t sig[MAX_DER_SIG_LEN];

    SEND_RESPONSE(dc, sig, sizeof(sig), SW_OK);

    ui_post_processing_confirm_withdraw(dc, true);
    return;
}