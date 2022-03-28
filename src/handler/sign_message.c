/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2021 Ledger SAS.
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
#include "../commands.h"
#include "../constants.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"

extern global_context_t *G_coin_config;

static void send_response(dispatcher_context_t *dc);

static unsigned char const BSM_SIGN_MAGIC[] = {'\x18', 'B', 'i', 't', 'c', 'o', 'i', 'n', ' ',
                                               'S',    'i', 'g', 'n', 'e', 'd', ' ', 'M', 'e',
                                               's',    's', 'a', 'g', 'e', ':', '\n'};

void handler_sign_message(dispatcher_context_t *dc, uint8_t p2) {
    (void) p2;

    sign_message_state_t *state = (sign_message_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        SEND_SW(dc, SW_SECURITY_STATUS_NOT_SATISFIED);
        return;
    }

    if (!buffer_read_u8(&dc->read_buffer, &state->bip32_path_len) ||
        !buffer_read_bip32_path(&dc->read_buffer, state->bip32_path, state->bip32_path_len) ||
        !buffer_read_varint(&dc->read_buffer, &state->message_length) ||
        !buffer_read_bytes(&dc->read_buffer, state->message_merkle_root, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    if (state->bip32_path_len > MAX_BIP32_PATH_STEPS || state->message_length >= (1LL << 32)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    char path_str[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1] = "(Master key)";
    if (state->bip32_path_len > 0) {
        bip32_path_format(state->bip32_path, state->bip32_path_len, path_str, sizeof(path_str));
    }

    cx_sha256_init(&state->msg_hash_context);
    cx_sha256_init(&state->bsm_digest_context);

    crypto_hash_update(&state->bsm_digest_context.header, BSM_SIGN_MAGIC, sizeof(BSM_SIGN_MAGIC));
    crypto_hash_update_varint(&state->bsm_digest_context.header, state->message_length);

    size_t n_chunks = (state->message_length + 63) / 64;
    for (unsigned int i = 0; i < n_chunks; i++) {
        uint8_t message_chunk[64];
        int chunk_len = call_get_merkle_leaf_element(dc,
                                                     state->message_merkle_root,
                                                     n_chunks,
                                                     i,
                                                     message_chunk,
                                                     sizeof(message_chunk));

        if (chunk_len < 0 || (chunk_len != 64 && i != n_chunks - 1)) {
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            return;
        }

        crypto_hash_update(&state->msg_hash_context.header, message_chunk, chunk_len);
        crypto_hash_update(&state->bsm_digest_context.header, message_chunk, chunk_len);
    }

    crypto_hash_digest(&state->msg_hash_context.header, state->message_hash, 32);
    crypto_hash_digest(&state->bsm_digest_context.header, state->bsm_digest, 32);
    cx_hash_sha256(state->bsm_digest, 32, state->bsm_digest, 32);

    char message_hash_str[64 + 1];
    for (int i = 0; i < 32; i++) {
        snprintf(message_hash_str + 2 * i, 3, "%02X", state->message_hash[i]);
    }

    ui_display_message_hash(dc, path_str, message_hash_str, send_response);
}

static void send_response(dispatcher_context_t *dc) {
    sign_message_state_t *state = (sign_message_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    uint8_t sig[MAX_DER_SIG_LEN];

    uint32_t info;
    int sig_len = crypto_ecdsa_sign_sha256_hash_with_key(state->bip32_path,
                                                         state->bip32_path_len,
                                                         state->bsm_digest,
                                                         NULL,
                                                         sig,
                                                         &info);

    if (sig_len < 0) {
        // unexpected error when signing
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    // convert signature to the standard Bitcoin format, always 65 bytes long

    uint8_t result[65];
    memset(result, 0, sizeof(result));

    // # Format signature into standard bitcoin format
    int r_length = sig[3];
    int s_length = sig[4 + r_length + 1];

    if (r_length > 33 || s_length > 33) {
        SEND_SW(dc, SW_BAD_STATE);  // can never happen
        return;
    }

    // Write s, r, and the first byte in reverse order, as the two loops will underflow by 1 byte
    // (that needs to be discarded) when s_length and r_length (respectively) are equal to 33.
    for (int i = s_length - 1; i >= 0; --i) {
        result[1 + 32 + 32 - s_length + i] = sig[4 + r_length + 2 + i];
    }
    for (int i = r_length - 1; i >= 0; --i) {
        result[1 + 32 - r_length + i] = sig[4 + i];
    }
    result[0] = 27 + 4 + ((info & CX_ECCINFO_PARITY_ODD) ? 1 : 0);

    SEND_RESPONSE(dc, result, sizeof(result), SW_OK);
}
