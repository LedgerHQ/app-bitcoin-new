/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2021 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  Y
 * ou may obtain a copy of the License at
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
#include "boilerplate/sw.h"
#include "../common/base58.h"
#include "../common/segwit_addr.h"
#include "../constants.h"
#include "../types.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"

#include "get_wallet_address.h"
#include "wallet.h"
#include "client_commands.h"

extern global_context_t G_context;

static void request_next_cosigner(dispatcher_context_t *dc);
static void read_next_cosigner(dispatcher_context_t *dc);
static void generate_address(dispatcher_context_t *dc);
static void ui_action_validate_address(dispatcher_context_t *dc, bool accepted);

void handler_get_wallet_address(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;
    if (p1 != 0 && p1 != 1) {
        io_send_sw(SW_WRONG_P1P2);
        return;
    }

    if (p2 != ADDRESS_TYPE_P2SH && p2 != ADDRESS_TYPE_SH_WSH && p2 != ADDRESS_TYPE_WSH) {
        io_send_sw(SW_WRONG_P1P2);
        return;
    }

    state->p1 = p1;
    state->p2 = p2;

    //      32           1        len(sig)        Var             4
    // <wallet hash> <len(sig)>  <  sig   > <wallet header> <address_index>

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        io_send_sw(SW_SECURITY_STATUS_NOT_SATISFIED);
        return;
    }

    if (!buffer_read_bytes(&dispatcher_context->read_buffer, state->wallet_hash, 32)) {
        io_send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    uint8_t sig_len;
    uint8_t sig[MAX_DER_SIG_LEN];
    if (!buffer_read_u8(&dispatcher_context->read_buffer, &sig_len) ||
        !buffer_read_bytes(&dispatcher_context->read_buffer, sig, sig_len)
    ) {
        io_send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    // Verify signature
    if (!crypto_verify_sha256_hash(state->wallet_hash, sig, sig_len)) {
        io_send_sw(SW_SIGNATURE_FAIL);
        return;
    }

    if (read_wallet_header(&dispatcher_context->read_buffer, &state->wallet_header) < 0) {
        io_send_sw(SW_INCORRECT_DATA);
        return;
    }

    if (!buffer_read_u32(&dispatcher_context->read_buffer, &state->address_index, BE)) {
        io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    cx_sha256_init(&state->wallet_hash_context);
    hash_update_append_wallet_header(&state->wallet_hash_context.header, &state->wallet_header);

    state->next_pubkey_index = 0;
    request_next_cosigner(dispatcher_context);
}

/**
 * Interrupts the command, asking the host for the next pubkey.
 */
static void request_next_cosigner(dispatcher_context_t *dc) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;

    dc->continuation = read_next_cosigner;

    uint8_t req[] = { CCMD_GET_COSIGNER_PUBKEY, state->next_pubkey_index};

    io_send_response(req, 2, SW_INTERRUPTED_EXECUTION);
}

/**
 * Receives the next xpub, accumulates it in the hash context, derives the appropriate child key.
 */
static void read_next_cosigner(dispatcher_context_t *dc) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;

    uint8_t pubkey_len;
    uint8_t pubkey[MAX_SERIALIZED_PUBKEY_LENGTH + 1];

    if (!buffer_read_u8(&dc->read_buffer, &pubkey_len)) {
        io_send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }
    if (pubkey_len > MAX_SERIALIZED_PUBKEY_LENGTH) {
        io_send_sw(SW_INCORRECT_DATA);
        return;
    }

    if (!buffer_move(&dc->read_buffer, pubkey, pubkey_len)) {
        io_send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    crypto_hash_update(&state->wallet_hash_context.header, &pubkey_len, 1);
    crypto_hash_update(&state->wallet_hash_context.header, &pubkey, pubkey_len);

    // TODO: decode pubkey, derive child pubkey, add push opcode to script hash (0x22<pubkey starting with 02 or 03>)
    serialized_extended_pubkey_check_t decoded_pubkey_check;
    if (base58_decode((char *)pubkey, pubkey_len, (uint8_t *)&decoded_pubkey_check, sizeof(decoded_pubkey_check)) == -1) {

        io_send_sw(SW_INCORRECT_DATA);
        return;
    }
    serialized_extended_pubkey_t *decoded_pubkey = &decoded_pubkey_check.serialize_extended_pubkey;

    // TODO: validate checksum

    // we derive the /0/i child of this pubkey
    serialized_extended_pubkey_t tmp_pubkey; // temporary variable to store the /0 derivation
    serialized_extended_pubkey_t cosigner_derived_pubkey; // pubkey of the /0/i derivation
    bip32_CKDpub(decoded_pubkey, 0, &tmp_pubkey);
    bip32_CKDpub(&tmp_pubkey, state->address_index, &cosigner_derived_pubkey);

    memcpy(state->derived_cosigner_pubkeys[state->next_pubkey_index], cosigner_derived_pubkey.compressed_pubkey, 33);

    ++state->next_pubkey_index;
    if (state->next_pubkey_index < state->wallet_header.n_keys) {
        request_next_cosigner(dc);
    } else {
        generate_address(dc);
    }
}


static void generate_address(dispatcher_context_t *dc) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;

    uint8_t wallet_hash[32];

    crypto_hash_digest(&state->wallet_hash_context.header, wallet_hash, 32);

    if (memcmp(state->wallet_hash, wallet_hash, 32) != 0) {
        io_send_sw(SW_INCORRECT_DATA); // TODO: add specific SW for hash mismatch?
    } else {
        // we do not need the wallet_hash_context any more, therefore we
        // overwrite it to save a little memory.
        cx_sha256_t *script_hash_context = &state->wallet_hash_context;

        // sort pubkeys
        uint8_t keys_rank[15];
        for (int i = 0; i < state->wallet_header.n_keys; i++) {
            keys_rank[i] = i;
        }
        // bubble sort, good enough for up to 15 keys.
        for (int i = 0; i < state->wallet_header.n_keys; i++) {
            for (int j = i + 1; j < state->wallet_header.n_keys; j++) {
                uint8_t *key_i = state->derived_cosigner_pubkeys[keys_rank[i]];
                uint8_t *key_j = state->derived_cosigner_pubkeys[keys_rank[j]];
                if (memcmp(key_i, key_j, 33) > 0) {
                    uint8_t tmp = keys_rank[i];
                    keys_rank[i] = keys_rank[j];
                    keys_rank[j] = tmp;
                }
            }
        }

        cx_sha256_init(script_hash_context);

        uint8_t script_header[] = {
            0x50 + state->wallet_header.threshold, // OP_m
        };
        crypto_hash_update(&script_hash_context->header, script_header, sizeof(script_header));

        for (int i = 0; i < state->wallet_header.n_keys; i++) {
            // PUSH <i-th pubkey>
            uint8_t push33 = 0x21;
            crypto_hash_update(&script_hash_context->header, &push33, 1);
            crypto_hash_update(&script_hash_context->header, state->derived_cosigner_pubkeys[keys_rank[i]], 33);
        }

        uint8_t script_final[] = {
            0x50 + state->wallet_header.n_keys, // OP_n
            0xae	                            // OP_CHECKMULTISIG
        };
        crypto_hash_update(&script_hash_context->header, script_final, sizeof(script_final));

        uint8_t script_sha256[32];
        crypto_hash_digest(&script_hash_context->header, script_sha256, 32);

        uint8_t script_rip[20];
        crypto_ripemd160(script_sha256, 32, script_rip);

        uint8_t redeem_script[34];
        uint8_t redeem_script_rip[20];

        int address_len;

        // Compute address
        switch (state->p2) {
            case ADDRESS_TYPE_P2SH:
                redeem_script[0] = 0xa9;                   // OP_HASH160
                redeem_script[1] = 0x14;                   // PUSH 20 bytes
                memcpy(&redeem_script[2], script_rip, 20); // <scripthash>
                redeem_script[2+20] = 0x87;                // OP_EQUAL

                crypto_hash160(redeem_script, sizeof(2+20+1), redeem_script_rip);
                address_len = base58_encode_address(redeem_script_rip, G_context.p2sh_version, state->address, sizeof(state->address));
                if (address_len == -1) {
                    io_send_sw(SW_BAD_STATE); // should never happen
                    return;
                } else {
                    state->address_len = (unsigned int)address_len;
                }

                break;
            case ADDRESS_TYPE_SH_WSH: // wrapped segwit
            case ADDRESS_TYPE_WSH:    // native segwit
                redeem_script[0] = 0x00; // OP_0
                redeem_script[1] = 0x20; // PUSH 32 bytes
                memcpy(&redeem_script[2], script_sha256, 32);

                crypto_hash160(redeem_script, sizeof(redeem_script), redeem_script_rip);
                if (state->p2 == ADDRESS_TYPE_SH_WSH) {
                    int address_len = base58_encode_address(redeem_script_rip, G_context.p2sh_version, state->address, sizeof(state->address));
                    if (address_len == -1) {
                        io_send_sw(SW_BAD_STATE); // should never happen
                        return;
                    } else {
                        state->address_len = (unsigned int)address_len;
                    }
                } else {
                    int ret = segwit_addr_encode(
                        state->address,
                        G_context.native_segwit_prefix,
                        0, redeem_script + 2, 32
                    );

                    if (ret != 1) {
                        io_send_sw(SW_BAD_STATE); // should never happen
                        return;
                    }

                    state->address_len = strlen(state->address);
                }
                break;
            default:
                io_send_sw(SW_BAD_STATE);
                return; // this can never happen
        }

        state->address[state->address_len] = '\0';

        if (state->p1 == 0) {
            io_send_response(state->address, state->address_len, SW_OK);
        } else {
            ui_display_wallet_address(dc, state->wallet_header.name, state->address, ui_action_validate_address);
        }
    }
}


static void ui_action_validate_address(dispatcher_context_t *dc, bool accepted) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;

    if (accepted) {
        io_send_response(state->address, state->address_len, SW_OK);
    } else {
        io_send_sw(SW_DENY);
    }

    ui_menu_main();
}
