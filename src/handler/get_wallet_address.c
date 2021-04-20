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
#include "../common/buffer.h"
#include "../common/merkle.h"
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
    dispatcher_context_t *dc
) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;
    if (p1 != 0 && p1 != 1) {
        dc->send_sw(SW_WRONG_P1P2);
        return;
    }

    if (p2 != 0) {
        dc->send_sw(SW_WRONG_P1P2);
        return;
    }

    state->display_address = p1;

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        dc->send_sw(SW_SECURITY_STATUS_NOT_SATISFIED);
        return;
    }

    uint8_t wallet_id[32];
    if (!buffer_read_bytes(&dc->read_buffer, wallet_id, 32)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    uint8_t sig_len;
    uint8_t sig[MAX_DER_SIG_LEN];
    if (!buffer_read_u8(&dc->read_buffer, &sig_len) ||
        !buffer_read_bytes(&dc->read_buffer, sig, sig_len)
    ) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    // Verify signature
    if (!crypto_verify_sha256_hash(wallet_id, sig, sig_len)) {
        dc->send_sw(SW_SIGNATURE_FAIL);
        return;
    }

    if (read_wallet_header(&dc->read_buffer, &state->wallet_header) < 0) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    uint16_t policy_map_len;
    if (!buffer_read_u16(&dc->read_buffer, &policy_map_len, BE)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }
    if (policy_map_len > MAX_POLICY_MAP_LEN) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }
    char policy_map[MAX_POLICY_MAP_LEN];
    if (!buffer_read_bytes(&dc->read_buffer, policy_map, policy_map_len)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    buffer_t policy_map_buffer = {
        .ptr = (uint8_t *)&policy_map,
        .offset = 0,
        .size = policy_map_len
    };
    if (buffer_read_multisig_policy_map(&policy_map_buffer, &state->wallet_header.multisig_policy) == -1) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    uint16_t n_policy_keys;
    if (!buffer_read_u16(&dc->read_buffer, &n_policy_keys, BE)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }
    if (n_policy_keys != state->wallet_header.multisig_policy.n_keys) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    if (!buffer_read_bytes(&dc->read_buffer, state->wallet_header.keys_info_merkle_root, 20)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }


    if (!buffer_read_u32(&dc->read_buffer, &state->address_index, BE)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }


    // Compute the wallet id (sha256 of the serialization)
    uint8_t computed_wallet_id[32];
    get_policy_wallet_id(&state->wallet_header,
                         policy_map_len,
                         policy_map,
                         state->wallet_header.multisig_policy.n_keys,
                         state->wallet_header.keys_info_merkle_root,
                         computed_wallet_id);

    if (memcmp(wallet_id, computed_wallet_id, sizeof(wallet_id)) != 0) {
        dc->send_sw(SW_INCORRECT_DATA); // TODO: more specific error code
        return;
    }

    // Init command state
    state->next_pubkey_index = 0;
    memset(state->used_pubkey_indexes, 0, sizeof(state->used_pubkey_indexes));
    memset(state->prev_compressed_pubkey, 0, sizeof(state->prev_compressed_pubkey));

    cx_sha256_init(&state->script_hash_context);
    uint8_t script_header[] = {
        0x50 + state->wallet_header.multisig_policy.threshold, // OP_m
    };
    crypto_hash_update(&state->script_hash_context.header, script_header, sizeof(script_header));

    dc->next(request_next_cosigner);
}


/**
 * Interrupts the command, asking the host for the next pubkey.
 */
static void request_next_cosigner(dispatcher_context_t *dc) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;

    if (state->wallet_header.multisig_policy.sorted) {
        // if sortedmulti, we ask the keys by rank based on the derived child pubkeys

        uint8_t req[1+1+1+4+4];
        buffer_t req_buffer = {
            .ptr = req,
            .offset = 0,
            .size = sizeof(req)
        };

        buffer_write_u8(&req_buffer, CCMD_GET_SORTED_PUBKEY_INFO);
        buffer_write_u8(&req_buffer, state->next_pubkey_index);

        buffer_write_u8(&req_buffer, 2); // BIP32 derivation length, followed by /0/address_index
        buffer_write_u32(&req_buffer, 0, BE);
        buffer_write_u32(&req_buffer, state->address_index, BE);

        dc->send_response(req, sizeof(req), SW_INTERRUPTED_EXECUTION);
    } else {
        // if multi, ask the keys in order

        uint8_t req[] = { CCMD_GET_PUBKEY_INFO, state->next_pubkey_index};

        dc->send_response(req, 2, SW_INTERRUPTED_EXECUTION);
    }

    dc->next(read_next_cosigner);
}


/**
 * Receives the next pubkey, accumulates it in the hash context, derives the appropriate child key.
 */
static void read_next_cosigner(dispatcher_context_t *dc) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;

    uint8_t key_index; // index of the key in the Merkle tree

    if (state->wallet_header.multisig_policy.sorted) {
        // if sortedmulti, the host computes the order
        if (!buffer_read_u8(&dc->read_buffer, &key_index)) {
            dc->send_sw(SW_WRONG_DATA_LENGTH);
            return;
        }
    } else {
        // if multi, the order is kept as in the registered Merkle tree
        key_index = state->address_index;
    }

    // the rest of the CCMD_GET_PUBKEY_INFO or CCMD_GET_SORTED_PUBKEY_INFO response is the same
    uint8_t key_info_len;

    if (!buffer_read_u8(&dc->read_buffer, &key_info_len)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }
    if (key_info_len > MAX_MULTISIG_SIGNER_INFO_LEN) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    if (!buffer_can_read(&dc->read_buffer, key_info_len)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    uint8_t key_info_hash[20];
    merkle_compute_element_hash(&dc->read_buffer.ptr[dc->read_buffer.offset], key_info_len, key_info_hash);

    // Make a sub-buffer for the pubkey info
    buffer_t key_info_buffer = {
        .ptr = &dc->read_buffer.ptr[dc->read_buffer.offset],
        .offset = 0,
        .size = key_info_len
    };

    policy_map_key_info_t key_info;
    if (parse_policy_map_key_info(&key_info_buffer, &key_info) == -1) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    buffer_seek_cur(&dc->read_buffer, key_info_len); // skip, data already parsed 


    // read Merkle proof and validate it.
    size_t proof_tree_size, proof_leaf_index;
    if (!buffer_read_u32(&dc->read_buffer, &proof_tree_size, BE) || !buffer_read_u32(&dc->read_buffer, &proof_leaf_index, BE)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    if (proof_leaf_index >= state->wallet_header.multisig_policy.n_keys) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    if (!buffer_read_and_verify_merkle_proof(&dc->read_buffer,
                                             state->wallet_header.keys_info_merkle_root,
                                             proof_tree_size,
                                             proof_leaf_index,
                                             key_info_hash)) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }


    if (state->used_pubkey_indexes[proof_leaf_index]) {
        PRINTF("Key index had already been seen\n");
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }
    state->used_pubkey_indexes[proof_leaf_index] = 1;

    // decode pubkey
    serialized_extended_pubkey_check_t decoded_pubkey_check;
    if (base58_decode(key_info.ext_pubkey, strlen(key_info.ext_pubkey), (uint8_t *)&decoded_pubkey_check, sizeof(decoded_pubkey_check)) == -1) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }
    // TODO: validate checksum

    serialized_extended_pubkey_t *decoded_pubkey = &decoded_pubkey_check.serialize_extended_pubkey;

    // we derive the /0/i child of this pubkey
    serialized_extended_pubkey_t tmp_pubkey; // temporary variable to store the /0 derivation
    serialized_extended_pubkey_t cosigner_derived_pubkey; // pubkey of the /0/i derivation
    bip32_CKDpub(decoded_pubkey, 0, &tmp_pubkey);
    bip32_CKDpub(&tmp_pubkey, state->address_index, &cosigner_derived_pubkey);

    // TODO: remove debug code

    // PRINTF("Key %d with rank %d: ", proof_leaf_index, state->next_pubkey_index);
    // for (int i = 0; i < 33; i++)
    //     PRINTF("%02x", cosigner_derived_pubkey.compressed_pubkey[i]);
    // PRINTF("\n");


    // PRINTF("Prev: ");
    // for (int i = 0; i < 33; i++)
    //     PRINTF("%02x", state->prev_compressed_pubkey[i]);
    // PRINTF("\n");

    // check lexicographic sorting if appropriate
    if (state->wallet_header.multisig_policy.sorted) {
        if (memcmp(state->prev_compressed_pubkey, cosigner_derived_pubkey.compressed_pubkey, 33) >= 0) {
            PRINTF("Keys provided in wrong order\n");
            dc->send_sw(SW_INCORRECT_DATA);
            return;
        }
    }

    memcpy(state->prev_compressed_pubkey, cosigner_derived_pubkey.compressed_pubkey, 33);


    // update script hash with PUSH opcode for this pubkey
    uint8_t push33 = 0x21;
    crypto_hash_update(&state->script_hash_context.header, &push33, 1);
    crypto_hash_update(&state->script_hash_context.header, cosigner_derived_pubkey.compressed_pubkey, 33);

    // TODO: add push opcode to script hash (0x22<pubkey starting with 02 or 03>)
    ++state->next_pubkey_index;
    if (state->next_pubkey_index < state->wallet_header.multisig_policy.n_keys) {
        dc->next(request_next_cosigner);
    } else {
        dc->next(generate_address);
    }
}


static void generate_address(dispatcher_context_t *dc) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;

    uint8_t script_final[] = {
        0x50 + state->wallet_header.multisig_policy.n_keys, // OP_n
        0xae	                                            // OP_CHECKMULTISIG
    };
    crypto_hash_update(&state->script_hash_context.header, script_final, sizeof(script_final));

    uint8_t script_sha256[32];
    crypto_hash_digest(&state->script_hash_context.header, script_sha256, 32);

    uint8_t script_rip[20];
    crypto_ripemd160(script_sha256, 32, script_rip);


    uint8_t redeem_script[34];
    uint8_t redeem_script_rip[20];

    int address_len;

    // Compute address
    int address_type = state->wallet_header.multisig_policy.address_type;
    switch (address_type) {
        case ADDRESS_TYPE_LEGACY:
            address_len = base58_encode_address(script_rip, G_context.p2sh_version, state->address, sizeof(state->address));
            if (address_len == -1) {
                dc->send_sw(SW_BAD_STATE); // should never happen
                return;
            } else {
                state->address_len = (unsigned int)address_len;
            }

            break;
        case ADDRESS_TYPE_WIT:    // wrapped segwit
        case ADDRESS_TYPE_SH_WIT: // native segwit
            redeem_script[0] = 0x00; // OP_0
            redeem_script[1] = 0x20; // PUSH 32 bytes
            memcpy(&redeem_script[2], script_sha256, 32);

            crypto_hash160(redeem_script, 2 + 32, redeem_script_rip);
            if (address_type == ADDRESS_TYPE_SH_WIT) {
                int address_len = base58_encode_address(redeem_script_rip, G_context.p2sh_version, state->address, sizeof(state->address));
                if (address_len == -1) {
                    dc->send_sw(SW_BAD_STATE); // should never happen
                    return;
                } else {
                    state->address_len = (unsigned int)address_len;
                }
            } else { // address_type == ADDRESS_TYPE_WIT
                int ret = segwit_addr_encode(
                    state->address,
                    G_context.native_segwit_prefix,
                    0, redeem_script + 2, 32
                );

                if (ret != 1) {
                    dc->send_sw(SW_BAD_STATE); // should never happen
                    return;
                }

                state->address_len = strlen(state->address);
            }
            break;
        default:
            dc->send_sw(SW_BAD_STATE);
            return; // this can never happen
    }
    state->address[state->address_len] = '\0';

    if (state->display_address == 0) {
        ui_action_validate_address(dc, true);
    } else {
        ui_display_wallet_address(dc, state->wallet_header.name, state->address, ui_action_validate_address);
    }
}


static void ui_action_validate_address(dispatcher_context_t *dc, bool accepted) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;

    if (accepted) {
        dc->send_response(state->address, state->address_len, SW_OK);
    } else {
        dc->send_sw(SW_DENY);
    }

    dc->run();
}
