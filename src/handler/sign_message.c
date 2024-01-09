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
#include "../common/bip32.h"
#include "../commands.h"
#include "../constants.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"
#include "lib/get_merkle_leaf_element.h"

#include "handlers.h"

static unsigned char const BSM_SIGN_MAGIC[] = {'\x18', 'B', 'i', 't', 'c', 'o', 'i', 'n', ' ',
                                               'S',    'i', 'g', 'n', 'e', 'd', ' ', 'M', 'e',
                                               's',    's', 'a', 'g', 'e', ':', '\n'};

void handler_sign_message(dispatcher_context_t *dc, uint8_t protocol_version) {
    (void) protocol_version;

    uint8_t bip32_path_len;
    uint32_t bip32_path[MAX_BIP32_PATH_STEPS];
    uint64_t message_length;
    uint8_t message_merkle_root[32];

    if (!buffer_read_u8(&dc->read_buffer, &bip32_path_len) ||
        !buffer_read_bip32_path(&dc->read_buffer, bip32_path, bip32_path_len) ||
        !buffer_read_varint(&dc->read_buffer, &message_length) ||
        !buffer_read_bytes(&dc->read_buffer, message_merkle_root, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    if (bip32_path_len > MAX_BIP32_PATH_STEPS || message_length >= (1LL << 32)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    char path_str[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1] = "(Master key)";
    if (bip32_path_len > 0) {
        bip32_path_format(bip32_path, bip32_path_len, path_str, sizeof(path_str));
    }

    cx_sha256_t msg_hash_context;    // used to compute sha256(message)
    cx_sha256_t bsm_digest_context;  // used to compute the Bitcoin Message Signing digest
    cx_sha256_init(&msg_hash_context);
    cx_sha256_init(&bsm_digest_context);

    crypto_hash_update(&bsm_digest_context.header, BSM_SIGN_MAGIC, sizeof(BSM_SIGN_MAGIC));
    crypto_hash_update_varint(&bsm_digest_context.header, message_length);

    size_t n_chunks = (message_length + 63) / 64;
    for (unsigned int i = 0; i < n_chunks; i++) {
        uint8_t message_chunk[64];
        int chunk_len = call_get_merkle_leaf_element(dc,
                                                     message_merkle_root,
                                                     n_chunks,
                                                     i,
                                                     message_chunk,
                                                     sizeof(message_chunk));

        if (chunk_len < 0 || (chunk_len != 64 && i != n_chunks - 1)) {
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            return;
        }

        crypto_hash_update(&msg_hash_context.header, message_chunk, chunk_len);
        crypto_hash_update(&bsm_digest_context.header, message_chunk, chunk_len);
    }

    uint8_t message_hash[32];
    uint8_t bsm_digest[32];

    crypto_hash_digest(&msg_hash_context.header, message_hash, 32);
    crypto_hash_digest(&bsm_digest_context.header, bsm_digest, 32);
    cx_hash_sha256(bsm_digest, 32, bsm_digest, 32);

    char message_hash_str[64 + 1];
    for (int i = 0; i < 32; i++) {
        snprintf(message_hash_str + 2 * i, 3, "%02X", message_hash[i]);
    }

    if (!ui_display_message_hash(dc, path_str, message_hash_str)) {
        SEND_SW(dc, SW_DENY);
        ui_post_processing_confirm_message(dc, false);
        return;
    }

    uint8_t sig[MAX_DER_SIG_LEN];

    uint32_t info;
    int sig_len = crypto_ecdsa_sign_sha256_hash_with_key(bip32_path,
                                                         bip32_path_len,
                                                         bsm_digest,
                                                         NULL,
                                                         sig,
                                                         &info);
    if (sig_len < 0) {
        // unexpected error when signing
        SEND_SW(dc, SW_BAD_STATE);
        ui_post_processing_confirm_message(dc, false);
        return;
    }

    {
        // convert signature to the standard Bitcoin format, always 65 bytes long

        uint8_t result[65];
        memset(result, 0, sizeof(result));

        // # Format signature into standard bitcoin format
        int r_length = sig[3];
        int s_length = sig[4 + r_length + 1];

        if (r_length > 33 || s_length > 33) {
            SEND_SW(dc, SW_BAD_STATE);  // can never happen
            ui_post_processing_confirm_message(dc, false);
            return;
        }

        // Write s, r, and the first byte in reverse order, as the two loops will underflow by 1
        // byte (that needs to be discarded) when s_length and r_length (respectively) are equal
        // to 33.
        for (int i = s_length - 1; i >= 0; --i) {
            result[1 + 32 + 32 - s_length + i] = sig[4 + r_length + 2 + i];
        }
        for (int i = r_length - 1; i >= 0; --i) {
            result[1 + 32 - r_length + i] = sig[4 + i];
        }
        result[0] = 27 + 4 + ((info & CX_ECCINFO_PARITY_ODD) ? 1 : 0);

        SEND_RESPONSE(dc, result, sizeof(result), SW_OK);
        ui_post_processing_confirm_message(dc, true);
        return;
    }
}
