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

// #define MAX_DISPLAYBLE_CHUNK_NUMBER \
//     (5 * MESSAGE_CHUNK_PER_DISPLAY)  // If the message is too long we will not display it

static unsigned char const BSM_SIGN_MAGIC[] = {'\x18', 'B', 'i', 't', 'c', 'o', 'i', 'n', ' ',
                                               'S',    'i', 'g', 'n', 'e', 'd', ' ', 'M', 'e',
                                               's',    's', 'a', 'g', 'e', ':', '\n'};

static bool display_data_content_and_confirm(dispatcher_context_t* dc,
                                             uint8_t* data_merkle_root,
                                             size_t n_chunks,
                                             uint8_t* path_str) {
    reset_streaming_index();
    uint8_t data_chunk[CHUNK_SIZE_IN_BYTES];
    char value[AMOUNT_SIZE_IN_CHARS + 1];
    char spender[ADDRESS_SIZE_IN_BYTES * 2 + 1];
    char redeemer[ADDRESS_SIZE_IN_BYTES * 2 + 1];

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
    if (!format_hex(&data_chunk[offset_address], ADDRESS_SIZE_IN_BYTES, spender, sizeof(spender))) {
        return false;
    }
    // format value
    int offset_value = 12 + ADDRESS_SIZE_IN_BYTES + 24;
    uint64_t value_u64 = read_u64_be(data_chunk, offset_value);

    if (!format_fpu64(value, sizeof(value), value_u64, 18)) {
        return false;
    };

    // Concat the COIN_COINID_SHORT to the value
    int ticker_len = strlen(COIN_COINID_SHORT);
    char value_with_ticker[AMOUNT_SIZE_IN_CHARS + 1 + ticker_len + 1];
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
    if (!format_hex(&data_chunk[offset_address],
                    ADDRESS_SIZE_IN_BYTES,
                    redeemer,
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

void handler_withdraw(dispatcher_context_t* dc, uint8_t protocol_version) {
    (void) protocol_version;

    uint8_t bip32_path_len;
    uint32_t bip32_path[MAX_BIP32_PATH_STEPS];
    uint64_t n_chunks;
    uint8_t data_merkle_root[32];
    bool printable = true;

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
    if (!display_data_content_and_confirm(dc, data_merkle_root, n_chunks, (uint8_t*) path_str)) {
        SEND_SW(dc, SW_DENY);
        ui_post_processing_confirm_withdraw(dc, false);
        return;
    }

#endif
    // COMPUTE THE HASH THAT WE WILL SIGN
    // SIGN MESSAGE (the message is the hash previously computed)
    uint8_t sig[MAX_DER_SIG_LEN] = {7};

    SEND_RESPONSE(dc, sig, sizeof(sig), SW_OK);

    ui_post_processing_confirm_withdraw(dc, true);
    return;
}