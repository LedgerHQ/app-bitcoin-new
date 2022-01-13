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

#include "../boilerplate/dispatcher.h"
#include "../boilerplate/sw.h"
#include "../common/merkle.h"
#include "../common/psbt.h"
#include "../common/read.h"
#include "../common/script.h"
#include "../common/varint.h"
#include "../common/write.h"

#include "../commands.h"
#include "../constants.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"

#include "client_commands.h"

#include "lib/policy.h"
#include "lib/check_merkle_tree_sorted.h"
#include "lib/get_preimage.h"
#include "lib/get_merkleized_map.h"
#include "lib/get_merkleized_map_value.h"
#include "lib/psbt_parse_rawtx.h"

#include "sign_psbt.h"

#include "sign_psbt/compare_wallet_script_at_path.h"
#include "sign_psbt/get_fingerprint_and_path.h"
#include "sign_psbt/update_hashes_with_map_value.h"

extern global_context_t *G_coin_config;

// UI callbacks
static void ui_action_validate_wallet_authorized(dispatcher_context_t *dc, bool accept);
static void ui_alert_external_inputs_result(dispatcher_context_t *dc, bool accept);
static void ui_action_validate_output(dispatcher_context_t *dc, bool accept);
static void ui_action_validate_transaction(dispatcher_context_t *dc, bool accept);

// Read global map
static void process_global_map(dispatcher_context_t *dc);

// Input validation
static void process_input_map(dispatcher_context_t *dc);
static void check_input_owned(dispatcher_context_t *dc);

static void alert_external_inputs(dispatcher_context_t *dc);

// Output validation
static void verify_outputs_init(dispatcher_context_t *dc);
static void process_output_map(dispatcher_context_t *dc);
static void check_output_owned(dispatcher_context_t *dc);
static void output_validate_external(dispatcher_context_t *dc);
static void output_next(dispatcher_context_t *dc);

// User confirmation (all)
static void confirm_transaction(dispatcher_context_t *dc);

// Signing process (all)
static void sign_init(dispatcher_context_t *dc);
static void sign_process_input_map(dispatcher_context_t *dc);

// Legacy sighash computation (P2PKH and P2SH)
static void sign_legacy(dispatcher_context_t *dc);
static void sign_legacy_compute_sighash(dispatcher_context_t *dc);

// Segwit sighash computation (P2WPKH, P2WSH and P2TR)
static void sign_segwit(dispatcher_context_t *dc);
static void sign_segwit_v0(dispatcher_context_t *dc);
static void sign_segwit_v1(dispatcher_context_t *dc);

// Sign input and yield result
static void sign_sighash_ecdsa(dispatcher_context_t *dc);
static void sign_sighash_schnorr(dispatcher_context_t *dc);

// End point and return
static void finalize(dispatcher_context_t *dc);

/* BIP0341 tags for computing the tagged hashes when computing he sighash */
static const uint8_t BIP0341_sighash_tag[] = {'T', 'a', 'p', 'S', 'i', 'g', 'h', 'a', 's', 'h'};

/*
Current assumptions during signing:
  1) exactly one of the keys in the wallet is internal (enforce during wallet registration)
  2) all the keys in the wallet have a wildcard (that is, they end with '**'), with at most
     4 derivation steps before it.

Assumption 2 simplifies the handling of pubkeys (and their paths) used for signing,
as all the internal keys will have a path that ends with /change/address_index (BIP44-style).

It would be possible to generalize to more complex scripts, but it makes it more difficult to detect
the right paths to identify internal inputs/outputs.
*/

// HELPER FUNCTIONS

// Updates the hash_context with the network serialization of all the outputs
// returns -1 on error (in that case, a response is already set). 0 on success.
static int hash_outputs(dispatcher_context_t *dc, cx_hash_t *hash_context) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    // TODO: support other SIGHASH FLAGS
    for (unsigned int i = 0; i < state->n_outputs; i++) {
        // get this output's map
        merkleized_map_commitment_t ith_map;

        int res = call_get_merkleized_map(dc, state->outputs_root, state->n_outputs, i, &ith_map);
        if (res < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return -1;
        }

        // get output's amount
        uint8_t amount_raw[8];
        if (8 != call_get_merkleized_map_value(dc,
                                               &ith_map,
                                               (uint8_t[]){PSBT_OUT_AMOUNT},
                                               1,
                                               amount_raw,
                                               8)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return -1;
        }

        crypto_hash_update(hash_context, amount_raw, 8);

        // get output's scriptPubKey

        uint8_t out_script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
        int out_script_len = call_get_merkleized_map_value(dc,
                                                           &ith_map,
                                                           (uint8_t[]){PSBT_OUT_SCRIPT},
                                                           1,
                                                           out_script,
                                                           sizeof(out_script));
        if (out_script_len == -1) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return -1;
        }

        crypto_hash_update_varint(hash_context, out_script_len);
        crypto_hash_update(hash_context, out_script, out_script_len);
    }
    return 0;
}

static int get_segwit_version(const uint8_t scriptPubKey[], int scriptPubKey_len) {
    if (scriptPubKey_len <= 1) {
        return -1;
    }

    if (scriptPubKey[0] == 0x00) {
        return 0;
    } else if (scriptPubKey[0] >= 0x51 && scriptPubKey[0] <= 0x60) {
        return scriptPubKey[0] - 0x50;
    }

    return -1;
}

/**
 * Validates the input, initializes the hash context and starts accumulating the wallet header in
 * it.
 */
void handler_sign_psbt(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        SEND_SW(dc, SW_SECURITY_STATUS_NOT_SATISFIED);
        return;
    }

    if (!buffer_read_varint(&dc->read_buffer, &state->global_map.size)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    if (!buffer_read_bytes(&dc->read_buffer, state->global_map.keys_root, 32) ||
        !buffer_read_bytes(&dc->read_buffer, state->global_map.values_root, 32)) {
        LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    uint64_t n_inputs;
    if (!buffer_read_varint(&dc->read_buffer, &n_inputs) ||
        !buffer_read_bytes(&dc->read_buffer, state->inputs_root, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    if (n_inputs > MAX_N_INPUTS_CAN_SIGN) {
        // TODO: remove this limitation
        PRINTF("At most %d inputs are supported\n", MAX_N_INPUTS_CAN_SIGN);
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return;
    }
    state->n_inputs = (unsigned int) n_inputs;

    uint64_t n_outputs;
    if (!buffer_read_varint(&dc->read_buffer, &n_outputs) ||
        !buffer_read_bytes(&dc->read_buffer, state->outputs_root, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    state->n_outputs = (unsigned int) n_outputs;

    if (n_outputs > MAX_N_OUTPUTS_CAN_SIGN) {
        // could remove this limitation; paranoia more than anything else
        PRINTF("At most %d outputs are supported\n", MAX_N_OUTPUTS_CAN_SIGN);
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return;
    }

    uint8_t wallet_id[32];
    uint8_t wallet_hmac[32];
    if (!buffer_read_bytes(&dc->read_buffer, wallet_id, 32) ||
        !buffer_read_bytes(&dc->read_buffer, wallet_hmac, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    // Fetch the serialized wallet policy from the client
    uint8_t serialized_wallet_policy[MAX_POLICY_MAP_SERIALIZED_LENGTH];
    int serialized_wallet_policy_len = call_get_preimage(dc,
                                                         wallet_id,
                                                         serialized_wallet_policy,
                                                         sizeof(serialized_wallet_policy));
    if (serialized_wallet_policy_len < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    policy_map_wallet_header_t wallet_header;
    buffer_t serialized_wallet_policy_buf =
        buffer_create(serialized_wallet_policy, serialized_wallet_policy_len);
    if ((read_policy_map_wallet(&serialized_wallet_policy_buf, &wallet_header)) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    memcpy(state->wallet_header_keys_info_merkle_root,
           wallet_header.keys_info_merkle_root,
           sizeof(wallet_header.keys_info_merkle_root));
    state->wallet_header_n_keys = wallet_header.n_keys;

    buffer_t policy_map_buffer =
        buffer_create(&wallet_header.policy_map, wallet_header.policy_map_len);

    if (parse_policy_map(&policy_map_buffer,
                         state->wallet_policy_map_bytes,
                         sizeof(state->wallet_policy_map_bytes)) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    uint8_t hmac_or =
        0;  // the binary OR of all the hmac bytes (so == 0 iff the hmac is identically 0)
    for (int i = 0; i < 32; i++) {
        hmac_or = hmac_or | wallet_hmac[i];
    }
    if (hmac_or == 0) {
        // No hmac, verify that the policy is a canonical one that is allowed by default

        if (state->wallet_header_n_keys != 1) {
            PRINTF("Non-standard policy, it should only have 1 key\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        state->address_type = get_policy_address_type(&state->wallet_policy_map);
        if (state->address_type == -1) {
            PRINTF("Non-standard policy, and no hmac provided\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        state->is_wallet_canonical = true;

        // Based on the address type, we set the expected bip44 purpose for this canonical wallet
        state->bip44_purpose = get_bip44_purpose(state->address_type);
        if (state->bip44_purpose < 0) {
            SEND_SW(dc, SW_BAD_STATE);
            return;
        }

        // We do not check here that the purpose field, coin_type and account (first three step of
        // the bip44 derivation) are standard. Will check at signing time that the path is valid.
    } else {
        // Verify hmac

        if (!check_wallet_hmac(wallet_id, wallet_hmac)) {
            PRINTF("Incorrect hmac\n");
            SEND_SW(dc, SW_SIGNATURE_FAIL);
            return;
        }

        state->is_wallet_canonical = false;
    }

    state->inputs_total_value = 0;
    state->internal_inputs_total_value = 0;
    memset(state->internal_inputs, 0, sizeof state->internal_inputs);

    state->master_key_fingerprint = crypto_get_master_key_fingerprint();

    // Check integrity of the global map
    if (call_check_merkle_tree_sorted(dc,
                                      state->global_map.keys_root,
                                      (size_t) state->global_map.size) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    if (state->is_wallet_canonical) {
        // Canonical wallet, we start processing the psbt directly
        dc->next(process_global_map);
    } else {
        // Show screen to authorize spend from a registered wallet
        dc->pause();
        ui_authorize_wallet_spend(dc, wallet_header.name, ui_action_validate_wallet_authorized);
    }
}

static void ui_action_validate_wallet_authorized(dispatcher_context_t *dc, bool accept) {
    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    if (!accept) {
        SEND_SW(dc, SW_DENY);
    } else {
        dc->next(process_global_map);
    }

    dc->run();
}

static void process_global_map(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    uint8_t raw_result[9];  // max size for a varint
    int result_len;

    // Read tx version
    result_len = call_get_merkleized_map_value(dc,
                                               &state->global_map,
                                               (uint8_t[]){PSBT_GLOBAL_TX_VERSION},
                                               1,
                                               raw_result,
                                               sizeof(raw_result));
    if (result_len != 4) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    state->tx_version = read_u32_le(raw_result, 0);

    // Read fallback locktime.
    // Unlike BIP-0370 recommendation, we use the fallback locktime as-is, ignoring each input's
    // preferred height/block locktime. If that's relevant, the client must set the fallback
    // locktime to the appropriate value before calling sign_psbt.
    result_len = call_get_merkleized_map_value(dc,
                                               &state->global_map,
                                               (uint8_t[]){PSBT_GLOBAL_FALLBACK_LOCKTIME},
                                               1,
                                               raw_result,
                                               sizeof(raw_result));
    if (result_len == -1) {
        state->locktime = 0;
    } else if (result_len != 4) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    } else {
        state->locktime = read_u32_le(raw_result, 0);
    }

    // we already know n_inputs and n_outputs, so we skip reading from the global map

    state->cur_input_index = 0;
    dc->next(process_input_map);
}

/** Inputs verification flow
 *
 *  Go though all the inputs:
 *  - verify the non_witness_utxo
 *  - compute value spent
 *  - detect internal inputs that should be signed, and external inputs that shouldn't
 */

/**
 * Callback to process all the keys of the current input map.
 * Keeps track if the current input has a witness_utxo and/or a redeemScript.
 */
static void input_keys_callback(sign_psbt_state_t *state, buffer_t *data) {
    size_t data_len = data->size - data->offset;
    if (data_len >= 1) {
        uint8_t key_type;
        buffer_read_u8(data, &key_type);
        if (key_type == PSBT_IN_WITNESS_UTXO) {
            state->cur_input.has_witnessUtxo = true;
        } else if (key_type == PSBT_IN_NON_WITNESS_UTXO) {
            state->cur_input.has_nonWitnessUtxo = true;
        } else if (key_type == PSBT_IN_REDEEM_SCRIPT) {
            state->cur_input.has_redeemScript = true;
        } else if (key_type == PSBT_IN_SIGHASH_TYPE) {
            state->cur_input.has_sighash_type = true;
        } else if (key_type == PSBT_IN_BIP32_DERIVATION && !state->cur_input.has_bip32_derivation) {
            // The first time that we encounter a PSBT_IN_BIP32_DERIVATION or
            // PSBT_IN_TAP_BIP32_DERIVATION (handled below) key, we store the pubkey. Since we only
            // use this to identify the change and address_index, it does not matter which of the
            // keys we use here (if there are multiple), as per the assumptions above.
            state->cur_input.has_bip32_derivation = true;

            if (!buffer_read_bytes(data,
                                   state->cur_input.bip32_derivation_pubkey,
                                   33)       // read compressed pubkey
                || buffer_can_read(data, 1)  // ...but should not be able to read more
            ) {
                state->cur_input.unexpected_pubkey_error = true;
            }
        } else if (key_type == PSBT_IN_TAP_BIP32_DERIVATION &&
                   !state->cur_input.has_bip32_derivation) {
            // See comment above
            state->cur_input.has_bip32_derivation = true;

            if (!buffer_read_bytes(data,
                                   state->cur_input.bip32_derivation_pubkey,
                                   32)       // read x-only pubkey
                || buffer_can_read(data, 1)  // ...but should not be able to read more
            ) {
                state->cur_input.unexpected_pubkey_error = true;
            }
        }
    }
}

static void process_input_map(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    if (state->cur_input_index >= state->n_inputs) {
        // all inputs already processed
        dc->next(alert_external_inputs);
        return;
    }

    // Reset cur_input struct
    memset(&state->cur_input, 0, sizeof(state->cur_input));

    int res = call_get_merkleized_map_with_callback(
        dc,
        state->inputs_root,
        state->n_inputs,
        state->cur_input_index,
        make_callback(state, (dispatcher_callback_t) input_keys_callback),
        &state->cur_input.map);
    if (res < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    if (state->cur_input.unexpected_pubkey_error) {
        PRINTF("Unexpected pubkey length\n");  // only compressed pubkeys are supported
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // Read the prevout index
    uint32_t prevout_n;
    if (4 != call_get_merkleized_map_value_u32_le(dc,
                                                  &state->cur_input.map,
                                                  (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                                  1,
                                                  &prevout_n)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // either witness utxo or non-witness utxo (or both) must be present.
    if (!state->cur_input.has_nonWitnessUtxo && !state->cur_input.has_witnessUtxo) {
        PRINTF("No witness utxo nor non-witness utxo present in input.\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // validate non-witness utxo (if present) and witness utxo (if present)

    if (state->cur_input.has_nonWitnessUtxo) {
        txid_parser_outputs_t parser_outputs;
        // request non-witness utxo, and get the prevout's value and scriptpubkey
        res = call_psbt_parse_rawtx(dc,
                                    &state->cur_input.map,
                                    (uint8_t[]){PSBT_IN_NON_WITNESS_UTXO},
                                    1,
                                    prevout_n,
                                    &parser_outputs);
        if (res < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        uint8_t prevout_hash[32];

        // check if the prevout_hash of the transaction matches the computed one from the
        // non-witness utxo
        res = call_get_merkleized_map_value(dc,
                                            &state->cur_input.map,
                                            (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                            1,
                                            prevout_hash,
                                            sizeof(prevout_hash));

        if (res == -1 || memcmp(parser_outputs.txid, prevout_hash, 32) != 0) {
            PRINTF("Prevout hash did not match non-witness-utxo transaction hash\n");

            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        uint64_t prevout_value = parser_outputs.vout_value;

        state->inputs_total_value += prevout_value;

        state->cur_input.prevout_amount = prevout_value;

        state->cur_input.prevout_scriptpubkey_len = parser_outputs.vout_scriptpubkey_len;

        if (state->cur_input.prevout_scriptpubkey_len > MAX_PREVOUT_SCRIPTPUBKEY_LEN) {
            PRINTF("Prevout's scriptPubKey too long: %d bytes.\n",
                   state->cur_input.prevout_scriptpubkey_len);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        memcpy(state->cur_input.prevout_scriptpubkey,
               parser_outputs.vout_scriptpubkey,
               state->cur_input.prevout_scriptpubkey_len);
    }

    if (state->cur_input.has_witnessUtxo) {
        uint8_t raw_witnessUtxo[8 + 1 + MAX_PREVOUT_SCRIPTPUBKEY_LEN];

        int wit_utxo_len = call_get_merkleized_map_value(dc,
                                                         &state->cur_input.map,
                                                         (uint8_t[]){PSBT_IN_WITNESS_UTXO},
                                                         1,
                                                         raw_witnessUtxo,
                                                         sizeof(raw_witnessUtxo));
        if (wit_utxo_len < 0) {
            PRINTF("Error fetching witness utxo\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        int wit_utxo_scriptPubkey_len = raw_witnessUtxo[8];

        if (wit_utxo_len != 8 + 1 + wit_utxo_scriptPubkey_len) {
            PRINTF("Length mismatch for witness utxo's scriptPubKey\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        uint8_t *wit_utxo_scriptPubkey = raw_witnessUtxo + 9;

        uint64_t wit_utxo_prevout_amount = read_u64_le(&raw_witnessUtxo[0], 0);

        if (state->cur_input.has_nonWitnessUtxo) {
            // we already know the scriptPubKey, but we double check that it matches
            if (state->cur_input.prevout_scriptpubkey_len != wit_utxo_scriptPubkey_len ||
                memcmp(state->cur_input.prevout_scriptpubkey,
                       wit_utxo_scriptPubkey,
                       wit_utxo_scriptPubkey_len) != 0 ||
                state->cur_input.prevout_amount != wit_utxo_prevout_amount) {
                PRINTF(
                    "scriptPubKey or amount in non-witness utxo doesn't match with witness utxo\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
            }
        } else {
            // we extract the scriptPubKey and prevout amount from the witness utxo
            state->inputs_total_value += wit_utxo_prevout_amount;

            state->cur_input.prevout_amount = wit_utxo_prevout_amount;
            state->cur_input.prevout_scriptpubkey_len = wit_utxo_scriptPubkey_len;
            memcpy(state->cur_input.prevout_scriptpubkey,
                   wit_utxo_scriptPubkey,
                   wit_utxo_scriptPubkey_len);
        }
    }

    dc->next(check_input_owned);
}

static void check_input_owned(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    int script_type = get_script_type(state->cur_input.prevout_scriptpubkey,
                                      state->cur_input.prevout_scriptpubkey_len);

    bool external = false;

    do {
        if (!state->cur_input.has_bip32_derivation) {
            external = true;
            break;
        }

        // get path, obtain change and address_index,

        int bip32_path_len;
        uint32_t bip32_path[MAX_BIP32_PATH_STEPS];
        uint32_t fingerprint;

        if (script_type == -1) {
            external = true;  // unknown script, definitely external
            break;
        } else if (script_type == SCRIPT_TYPE_P2TR) {
            // taproot input, use PSBT_IN_TAP_BIP32_DERIVATION
            uint8_t key[1 + 32];
            key[0] = PSBT_IN_TAP_BIP32_DERIVATION;
            memcpy(key + 1, state->cur_input.bip32_derivation_pubkey, 32);

            bip32_path_len = get_emptyhashes_fingerprint_and_path(dc,
                                                                  &state->cur_input.map,
                                                                  key,
                                                                  sizeof(key),
                                                                  &fingerprint,
                                                                  bip32_path);
        } else {
            // legacy or segwitv0 input, use PSBT_IN_BIP32_DERIVATION
            uint8_t key[1 + 33];
            key[0] = PSBT_IN_BIP32_DERIVATION;
            memcpy(key + 1, state->cur_input.bip32_derivation_pubkey, 33);

            bip32_path_len = get_fingerprint_and_path(dc,
                                                      &state->cur_input.map,
                                                      key,
                                                      sizeof(key),
                                                      &fingerprint,
                                                      bip32_path);
        }

        if (bip32_path_len < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        // As per wallet policy assumptions, the path must have change and address index
        if (bip32_path_len < 2) {
            external = true;
            break;
        }

        if (state->is_wallet_canonical) {
            // check if path is as expected
            uint32_t coin_types[2] = {G_coin_config->bip44_coin_type,
                                      G_coin_config->bip44_coin_type2};
            if (!is_address_path_standard(bip32_path,
                                          bip32_path_len,
                                          state->bip44_purpose,
                                          coin_types,
                                          2,
                                          -1)) {
                external = true;
                break;
            }
        }

        uint32_t change = bip32_path[bip32_path_len - 2];
        uint32_t address_index = bip32_path[bip32_path_len - 1];

        int res = compare_wallet_script_at_path(dc,
                                                change,
                                                address_index,
                                                &state->wallet_policy_map,
                                                state->wallet_header_keys_info_merkle_root,
                                                state->wallet_header_n_keys,
                                                state->cur_input.prevout_scriptpubkey,
                                                state->cur_input.prevout_scriptpubkey_len);
        if (res < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        } else if (res == 0) {
            external = true;
            break;
        } else if (res == 1) {
            // input is internal, nothing to do
        } else {
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            return;
        }
    } while (false);  // executed only once; in a block only to be able to break out of it

    if (external) {
        PRINTF("INPUT %d is external\n", state->cur_input_index);
    } else {
        state->internal_inputs[state->cur_input_index] = 1;
        state->internal_inputs_total_value += state->cur_input.prevout_amount;

        int segwit_version = get_segwit_version(state->cur_input.prevout_scriptpubkey,
                                                state->cur_input.prevout_scriptpubkey_len);

        // For legacy or segwit-v0 inputs, the non-witness utxo must be present
        if ((segwit_version == -1 || segwit_version == 0) && !state->cur_input.has_nonWitnessUtxo) {
            PRINTF("Non-witness utxo missing for legacy or segwitv0 input\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        // For all segwit transactions, the witness utxo must be present
        if (segwit_version >= 0 && !state->cur_input.has_witnessUtxo) {
            PRINTF("Witness utxo missing for segwit input\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }

    ++state->cur_input_index;
    dc->next(process_input_map);
}

// If there are external inputs, it is unsafe to sign, therefore we warn the user
static void alert_external_inputs(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    size_t count_external_inputs = 0;
    for (unsigned int i = 0; i < state->n_inputs; i++) {
        if (!state->internal_inputs[i]) {
            ++count_external_inputs;
        }
    }

    if (count_external_inputs == 0) {
        // no external inputs
        dc->next(verify_outputs_init);
    } else if (count_external_inputs == state->n_inputs) {
        // no internal inputs, nothing to sign
        PRINTF("No internal inputs. Aborting\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    } else {
        // some internal and some external inputs, warn the user first
        dc->pause();
        ui_warn_external_inputs(dc, ui_alert_external_inputs_result);
    }
}

static void ui_alert_external_inputs_result(dispatcher_context_t *dc, bool accept) {
    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    if (!accept) {
        SEND_SW(dc, SW_DENY);
    } else {
        dc->next(verify_outputs_init);
    }

    dc->run();
}

/** OUTPUTS VERIFICATION FLOW
 *
 *  For each output, check if it's a change address.
 *  Show each output that is not a change address to the user for verification.
 */

// entry point for the outputs verification flow
static void verify_outputs_init(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    state->outputs_total_value = 0;
    state->change_outputs_total_value = 0;
    state->change_count = 0;

    state->cur_output_index = 0;

    state->external_outputs_count = 0;

    dc->next(process_output_map);
}

/**
 * Callback to process all the keys of the current input map.
 * Keeps track if the current input has a witness_utxo and/or a redeemScript.
 */
static void output_keys_callback(sign_psbt_state_t *state, buffer_t *data) {
    size_t data_len = data->size - data->offset;
    if (data_len >= 1) {
        uint8_t key_type;
        buffer_read_u8(data, &key_type);

        if (key_type == PSBT_OUT_BIP32_DERIVATION && !state->cur_output.has_bip32_derivation) {
            // The first time that we encounter a PSBT_OUT_BIP32_DERIVATION or
            // PSBT_OUT_TAP_BIP32_DERIVATION key, we store the pubkey.
            state->cur_output.has_bip32_derivation = true;

            if (!buffer_read_bytes(data,
                                   state->cur_output.bip32_derivation_pubkey,
                                   33)       // read compressed pubkey
                || buffer_can_read(data, 1)  // ...but should not be able to read more
            ) {
                state->cur_output.unexpected_pubkey_error = true;
            }
        } else if (key_type == PSBT_OUT_TAP_BIP32_DERIVATION &&
                   !state->cur_output.has_bip32_derivation) {
            state->cur_output.has_bip32_derivation = true;

            if (!buffer_read_bytes(data,
                                   state->cur_output.bip32_derivation_pubkey,
                                   32)       // read x-only pubkey
                || buffer_can_read(data, 1)  // ...but should not be able to read more
            ) {
                state->cur_output.unexpected_pubkey_error = true;
            }
        }
    }
}

static void process_output_map(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    if (state->cur_output_index >= state->n_outputs) {
        // all outputs already processed
        dc->next(confirm_transaction);
        return;
    }

    memset(&state->cur_output, 0, sizeof(state->cur_output));

    int res = call_get_merkleized_map_with_callback(
        dc,
        state->outputs_root,
        state->n_outputs,
        state->cur_output_index,
        make_callback(state, (dispatcher_callback_t) output_keys_callback),
        &state->cur_output.map);
    if (res < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    if (state->cur_output.unexpected_pubkey_error) {
        PRINTF("Unexpected pubkey length\n");  // only compressed pubkeys are supported
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // read output amount and scriptpubkey

    uint8_t raw_result[8];

    // Read the output's amount
    int result_len = call_get_merkleized_map_value(dc,
                                                   &state->cur_output.map,
                                                   (uint8_t[]){PSBT_OUT_AMOUNT},
                                                   1,
                                                   raw_result,
                                                   sizeof(raw_result));
    if (result_len != 8) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    uint64_t value = read_u64_le(raw_result, 0);

    state->cur_output.value = value;
    state->outputs_total_value += value;

    // Read the output's scriptPubKey

    // Read the output's amount
    result_len = call_get_merkleized_map_value(dc,
                                               &state->cur_output.map,
                                               (uint8_t[]){PSBT_OUT_SCRIPT},
                                               1,
                                               state->cur_output.scriptpubkey,
                                               sizeof(state->cur_output.scriptpubkey));
    if (result_len == -1) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    } else if (result_len > (int) sizeof(state->cur_output.scriptpubkey)) {
        PRINTF("Output's scriptPubKey too long: %d\n", result_len);
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    state->cur_output.scriptpubkey_len = result_len;

    dc->next(check_output_owned);
}

// TODO: lots of code duplication with check_input_owned, consider refactoring
static void check_output_owned(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    int script_type =
        get_script_type(state->cur_output.scriptpubkey, state->cur_output.scriptpubkey_len);

    bool external = false;

    do {
        if (!state->cur_output.has_bip32_derivation) {
            external = true;
            break;
        }

        // get path, obtain change and address_index,

        int bip32_path_len;
        uint32_t bip32_path[MAX_BIP32_PATH_STEPS];
        uint32_t fingerprint;

        if (script_type == -1) {
            external = true;  // unknown script, definitely external
            break;
        } else if (script_type == SCRIPT_TYPE_P2TR) {
            // taproot output, use PSBT_OUT_TAP_BIP32_DERIVATION
            uint8_t key[1 + 32];
            key[0] = PSBT_OUT_TAP_BIP32_DERIVATION;
            memcpy(key + 1, state->cur_output.bip32_derivation_pubkey, 32);

            bip32_path_len = get_emptyhashes_fingerprint_and_path(dc,
                                                                  &state->cur_output.map,
                                                                  key,
                                                                  sizeof(key),
                                                                  &fingerprint,
                                                                  bip32_path);
        } else {
            // legacy or segwitv0 output, use PSBT_OUT_BIP32_DERIVATION
            uint8_t key[1 + 33];
            key[0] = PSBT_OUT_BIP32_DERIVATION;
            memcpy(key + 1, state->cur_output.bip32_derivation_pubkey, 33);

            bip32_path_len = get_fingerprint_and_path(dc,
                                                      &state->cur_output.map,
                                                      key,
                                                      sizeof(key),
                                                      &fingerprint,
                                                      bip32_path);
        }

        if (bip32_path_len < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        // As per wallet policy assumptions, the path must have change and address index
        if (bip32_path_len < 2) {
            external = true;
            break;
        }
        uint32_t change = bip32_path[bip32_path_len - 2];
        uint32_t address_index = bip32_path[bip32_path_len - 1];

        if (change != 1) {
            // unlike for inputs, change must be 1 for this output to be considered internal
            external = true;
            break;
        }

        if (state->is_wallet_canonical) {
            // for canonical wallets, the path must be exactly as expected for a change output
            uint32_t coin_types[2] = {G_coin_config->bip44_coin_type,
                                      G_coin_config->bip44_coin_type2};
            if (!is_address_path_standard(bip32_path,
                                          bip32_path_len,
                                          state->bip44_purpose,
                                          coin_types,
                                          2,
                                          1)) {
                external = true;
                break;
            }
        }

        int res = compare_wallet_script_at_path(dc,
                                                change,
                                                address_index,
                                                &state->wallet_policy_map,
                                                state->wallet_header_keys_info_merkle_root,
                                                state->wallet_header_n_keys,
                                                state->cur_output.scriptpubkey,
                                                state->cur_output.scriptpubkey_len);
        if (res < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        } else if (res == 0) {
            external = true;
        } else if (res == 1) {
            // output is internal, nothing to do
        } else {
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            return;
        }
    } while (false);  // execute only once; just to be able to break out

    if (external) {
        // external output, user needs to validate
        ++state->external_outputs_count;

        dc->next(output_validate_external);
        return;
    } else {
        // valid change address, nothing to show to the user

        state->change_outputs_total_value += state->cur_output.value;
        ++state->change_count;

        dc->next(output_next);
        return;
    }
}

static void output_validate_external(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // show this output's address
    // TODO: handle outputs without an address (e.g.: OP_RETURN)
    char output_address[MAX_ADDRESS_LENGTH_STR + 1];
    int address_len = get_script_address(state->cur_output.scriptpubkey,
                                         state->cur_output.scriptpubkey_len,
                                         G_coin_config,
                                         output_address,
                                         sizeof(output_address));
    if (address_len < 0) {
        PRINTF("Unknown or unsupported script type for output %d\n", state->cur_output_index);
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return;
    }

    dc->pause();
    ui_validate_output(dc,
                       state->external_outputs_count,
                       output_address,
                       G_coin_config->name_short,
                       state->cur_output.value,
                       ui_action_validate_output);
}

static void ui_action_validate_output(dispatcher_context_t *dc, bool accept) {
    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    if (!accept) {
        SEND_SW(dc, SW_DENY);
    } else {
        dc->next(output_next);
    }

    dc->run();
}

static void output_next(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    ++state->cur_output_index;
    dc->next(process_output_map);
}

// Show fees and confirm transaction with the user
static void confirm_transaction(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    if (state->inputs_total_value < state->outputs_total_value) {
        // negative fee transaction is invalid
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    if (state->change_count > 10) {
        // As the information regarding change outputs is aggregated, we want to prevent the user
        // from unknowingly signing a transaction that sends the change to too many (possibly
        // unspendable) outputs.
        PRINTF("Too many change outputs: %d\n", state->change_count);
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return;
    }

    uint64_t fee = state->inputs_total_value - state->outputs_total_value;

    dc->pause();
    ui_validate_transaction(dc, G_coin_config->name_short, fee, ui_action_validate_transaction);
}

static void ui_action_validate_transaction(dispatcher_context_t *dc, bool accept) {
    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    if (!accept) {
        SEND_SW(dc, SW_DENY);
    } else {
        dc->next(sign_init);
    }

    dc->run();
}

/** SIGNING FLOW
 *
 * Iterate over all inputs. For each input that should be signed, compute and sign sighash.
 */

// entry point for the signing flow
static void sign_init(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // find and parse our registered key info in the wallet
    bool our_key_found = false;
    for (unsigned int i = 0; i < state->wallet_header_n_keys; i++) {
        uint8_t key_info_str[MAX_POLICY_KEY_INFO_LEN];

        int key_info_len = call_get_merkle_leaf_element(dc,
                                                        state->wallet_header_keys_info_merkle_root,
                                                        state->wallet_header_n_keys,
                                                        i,
                                                        key_info_str,
                                                        sizeof(key_info_str));

        if (key_info_len < 0) {
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            return;
        }

        // Make a sub-buffer for the pubkey info
        buffer_t key_info_buffer = buffer_create(key_info_str, key_info_len);

        policy_map_key_info_t our_key_info;
        if (parse_policy_map_key_info(&key_info_buffer, &our_key_info) == -1) {
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            return;
        }

        uint32_t fpr = read_u32_be(our_key_info.master_key_fingerprint, 0);
        if (fpr == state->master_key_fingerprint) {
            // it could be a collision on the fingerprint; we verify that we can actually generate
            // the same pubkey
            char pubkey_derived[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
            int serialized_pubkey_len =
                get_serialized_extended_pubkey_at_path(our_key_info.master_key_derivation,
                                                       our_key_info.master_key_derivation_len,
                                                       G_coin_config->bip32_pubkey_version,
                                                       pubkey_derived);
            if (serialized_pubkey_len == -1) {
                SEND_SW(dc, SW_BAD_STATE);
                return;
            }

            if (strncmp(our_key_info.ext_pubkey, pubkey_derived, MAX_SERIALIZED_PUBKEY_LENGTH) ==
                0) {
                our_key_found = true;

                state->our_key_derivation_length = our_key_info.master_key_derivation_len;
                for (int i = 0; i < our_key_info.master_key_derivation_len; i++) {
                    state->our_key_derivation[i] = our_key_info.master_key_derivation[i];
                }

                break;
            }
        }
    }

    if (!our_key_found) {
        PRINTF("Couldn't find internal key\n");
        SEND_SW(
            dc,
            SW_BAD_STATE);  // should never happen if we only register wallets with an internal key
        return;
    }

    state->cur_input_index = 0;
    dc->next(sign_process_input_map);
}

static void sign_process_input_map(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // skip external inputs
    while (state->cur_input_index < state->n_inputs &&
           !state->internal_inputs[state->cur_input_index]) {
        PRINTF("Skipping signing external input %d\n", state->cur_input_index);
        ++state->cur_input_index;
    }

    if (state->cur_input_index >= state->n_inputs) {
        // all inputs already processed
        dc->next(finalize);
        return;
    }

    // Reset cur_input struct
    memset(&state->cur_input, 0, sizeof(state->cur_input));

    int res = call_get_merkleized_map_with_callback(
        dc,
        state->inputs_root,
        state->n_inputs,
        state->cur_input_index,
        make_callback(state, (dispatcher_callback_t) input_keys_callback),
        &state->cur_input.map);
    if (res < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    if (!state->cur_input.has_sighash_type) {
        state->cur_input.sighash_type = SIGHASH_ALL;
    } else {
        // Get sighash type
        if (4 != call_get_merkleized_map_value_u32_le(dc,
                                                      &state->cur_input.map,
                                                      (uint8_t[]){PSBT_IN_SIGHASH_TYPE},
                                                      1,
                                                      &state->cur_input.sighash_type)) {
            PRINTF("Malformed PSBT_IN_SIGHASH_TYPE for input %d\n", state->cur_input_index);

            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }

    // TODO: add support for other sighash flags
    if (state->cur_input.sighash_type != SIGHASH_ALL) {
        PRINTF("Only SIGHASH_ALL is currently supported\n");
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return;
    }

    // get path, obtain change and address_index

    int bip32_path_len;
    uint32_t bip32_path[MAX_BIP32_PATH_STEPS];
    uint32_t fingerprint;

    if (state->wallet_policy_map.type == TOKEN_TR) {
        // taproot input, use PSBT_IN_TAP_BIP32_DERIVATION
        uint8_t key[1 + 32];
        key[0] = PSBT_IN_TAP_BIP32_DERIVATION;
        memcpy(key + 1, state->cur_input.bip32_derivation_pubkey, 32);

        bip32_path_len = get_emptyhashes_fingerprint_and_path(dc,
                                                              &state->cur_input.map,
                                                              key,
                                                              sizeof(key),
                                                              &fingerprint,
                                                              bip32_path);
    } else {
        // legacy or segwitv0 input, use PSBT_IN_BIP32_DERIVATION
        uint8_t key[1 + 33];
        key[0] = PSBT_IN_BIP32_DERIVATION;
        memcpy(key + 1, state->cur_input.bip32_derivation_pubkey, 33);

        bip32_path_len = get_fingerprint_and_path(dc,
                                                  &state->cur_input.map,
                                                  key,
                                                  sizeof(key),
                                                  &fingerprint,
                                                  bip32_path);
    }

    if (bip32_path_len < 2) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    state->cur_input.change = bip32_path[bip32_path_len - 2];
    state->cur_input.address_index = bip32_path[bip32_path_len - 1];

    // Sign as segwit input iff it has a witness utxo
    if (!state->cur_input.has_witnessUtxo) {
        dc->next(sign_legacy);
    } else {
        dc->next(sign_segwit);
    }
}

static void sign_legacy(dispatcher_context_t *dc) {
    // sign legacy P2PKH or P2SH

    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // sign_non_witness(non_witness_utxo.vout[psbt.tx.input_[i].prevout.n].scriptPubKey, i)

    // Read the prevout index
    uint32_t prevout_n;
    if (4 != call_get_merkleized_map_value_u32_le(dc,
                                                  &state->cur_input.map,
                                                  (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                                  1,
                                                  &prevout_n)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    txid_parser_outputs_t parser_outputs;
    // request non-witness utxo, and get the prevout's value and scriptpubkey
    int res = call_psbt_parse_rawtx(dc,
                                    &state->cur_input.map,
                                    (uint8_t[]){PSBT_IN_NON_WITNESS_UTXO},
                                    1,
                                    prevout_n,
                                    &parser_outputs);
    if (res < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    state->cur_input.prevout_scriptpubkey_len = parser_outputs.vout_scriptpubkey_len;
    memcpy(state->cur_input.prevout_scriptpubkey,
           parser_outputs.vout_scriptpubkey,
           parser_outputs.vout_scriptpubkey_len);

    dc->next(sign_legacy_compute_sighash);
}

static void sign_legacy_compute_sighash(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    cx_sha256_t sighash_context;
    cx_sha256_init(&sighash_context);

    uint8_t tmp[4];
    write_u32_le(tmp, 0, state->tx_version);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    crypto_hash_update_varint(&sighash_context.header, state->n_inputs);

    for (unsigned int i = 0; i < state->n_inputs; i++) {
        // get this input's map
        merkleized_map_commitment_t ith_map;

        if (i != state->cur_input_index) {
            int res = call_get_merkleized_map(dc, state->inputs_root, state->n_inputs, i, &ith_map);
            if (res < 0) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }
        } else {
            // Avoid requesting the same map unnecessarily
            // (might be removed once a caching mechanism is implemented)
            memcpy(&ith_map, &state->cur_input.map, sizeof(state->cur_input.map));
        }

        // get prevout hash and output index for the i-th input
        uint8_t ith_prevout_hash[32];
        if (32 != call_get_merkleized_map_value(dc,
                                                &ith_map,
                                                (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                1,
                                                ith_prevout_hash,
                                                32)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        crypto_hash_update(&sighash_context.header, ith_prevout_hash, 32);

        uint8_t ith_prevout_n_raw[4];
        if (4 != call_get_merkleized_map_value(dc,
                                               &ith_map,
                                               (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                               1,
                                               ith_prevout_n_raw,
                                               4)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        crypto_hash_update(&sighash_context.header, ith_prevout_n_raw, 4);

        if (i != state->cur_input_index) {
            // empty scriptcode
            crypto_hash_update_u8(&sighash_context.header, 0x00);
        } else {
            if (!state->cur_input.has_redeemScript) {
                // P2PKH, the script_code is the prevout's scriptPubKey
                crypto_hash_update_varint(&sighash_context.header,
                                          state->cur_input.prevout_scriptpubkey_len);
                crypto_hash_update(&sighash_context.header,
                                   state->cur_input.prevout_scriptpubkey,
                                   state->cur_input.prevout_scriptpubkey_len);
            } else {
                // P2SH, the script_code is the redeemScript

                // update sighash_context with the length-prefixed redeem script
                int redeemScript_len =
                    update_hashes_with_map_value(dc,
                                                 &state->cur_input.map,
                                                 (uint8_t[]){PSBT_IN_REDEEM_SCRIPT},
                                                 1,
                                                 NULL,
                                                 &sighash_context.header);

                if (redeemScript_len < 0) {
                    PRINTF("Error fetching redeemScript\n");
                    SEND_SW(dc, SW_INCORRECT_DATA);
                    return;
                }
            }
        }

        uint8_t ith_nSequence_raw[4];
        if (4 != call_get_merkleized_map_value(dc,
                                               &ith_map,
                                               (uint8_t[]){PSBT_IN_SEQUENCE},
                                               1,
                                               ith_nSequence_raw,
                                               4)) {
            // if no PSBT_IN_SEQUENCE is present, we must assume nSequence 0xFFFFFFFF
            memset(ith_nSequence_raw, 0xFF, 4);
        }

        crypto_hash_update(&sighash_context.header, ith_nSequence_raw, 4);
    }

    // outputs
    crypto_hash_update_varint(&sighash_context.header, state->n_outputs);
    if (hash_outputs(dc, &sighash_context.header) == -1) {
        return;  // response already set
    }

    // nLocktime
    write_u32_le(tmp, 0, state->locktime);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // hash type
    write_u32_le(tmp, 0, state->cur_input.sighash_type);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // compute sighash
    crypto_hash_digest(&sighash_context.header, state->sighash, 32);
    cx_hash_sha256(state->sighash, 32, state->sighash, 32);

    dc->next(sign_sighash_ecdsa);
}

static void sign_segwit(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    uint8_t segwit_version;

    {
        uint8_t raw_witnessUtxo[8 + 1 + MAX_PREVOUT_SCRIPTPUBKEY_LEN];

        int wit_utxo_len = call_get_merkleized_map_value(dc,
                                                         &state->cur_input.map,
                                                         (uint8_t[]){PSBT_IN_WITNESS_UTXO},
                                                         1,
                                                         raw_witnessUtxo,
                                                         sizeof(raw_witnessUtxo));
        if (wit_utxo_len < 0) {
            PRINTF("Error fetching witness utxo\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        int wit_utxo_scriptPubkey_len = raw_witnessUtxo[8];

        if (wit_utxo_len != 8 + 1 + wit_utxo_scriptPubkey_len) {
            PRINTF("Length mismatch for witness utxo's scriptPubKey\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        uint8_t *wit_utxo_scriptPubkey = raw_witnessUtxo + 9;
        uint64_t wit_utxo_prevout_amount = read_u64_le(&raw_witnessUtxo[0], 0);

        // Validation of the witness-utxo was already done during input processing
        state->cur_input.prevout_amount = wit_utxo_prevout_amount;
        state->cur_input.prevout_scriptpubkey_len = wit_utxo_scriptPubkey_len;
        memcpy(state->cur_input.prevout_scriptpubkey,
               wit_utxo_scriptPubkey,
               wit_utxo_scriptPubkey_len);

        if (state->cur_input.has_redeemScript) {
            // Get redeemScript
            uint8_t redeemScript[64];

            int redeemScript_length =
                call_get_merkleized_map_value(dc,
                                              &state->cur_input.map,
                                              (uint8_t[]){PSBT_IN_REDEEM_SCRIPT},
                                              1,
                                              redeemScript,
                                              sizeof(redeemScript));
            if (redeemScript_length < 0) {
                PRINTF("Error fetching redeem script\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            uint8_t p2sh_redeemscript[2 + 20 + 1];
            p2sh_redeemscript[0] = 0xa9;
            p2sh_redeemscript[1] = 0x14;
            crypto_hash160(redeemScript, redeemScript_length, p2sh_redeemscript + 2);
            p2sh_redeemscript[22] = 0x87;

            if (wit_utxo_scriptPubkey_len != 23 ||
                memcmp(wit_utxo_scriptPubkey, p2sh_redeemscript, 23) != 0) {
                PRINTF("witnessUtxo's scriptPubKey does not match redeemScript\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            state->cur_input.script_len = redeemScript_length;
            memcpy(state->cur_input.script, redeemScript, redeemScript_length);
            segwit_version = get_segwit_version(redeemScript, redeemScript_length);
        } else {
            state->cur_input.script_len = wit_utxo_scriptPubkey_len;
            memcpy(state->cur_input.script, wit_utxo_scriptPubkey, wit_utxo_scriptPubkey_len);

            segwit_version = get_segwit_version(wit_utxo_scriptPubkey, wit_utxo_scriptPubkey_len);
        }
    }

    if (segwit_version > 1) {
        PRINTF("Segwit version not supported: %d\n", segwit_version);
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return;
    }

    // compute all the tx-wide hashes

    {
        // compute sha_prevouts and sha_sequences
        cx_sha256_t sha_prevouts_context, sha_sequences_context;

        // compute hashPrevouts and hashSequence
        cx_sha256_init(&sha_prevouts_context);
        cx_sha256_init(&sha_sequences_context);

        for (unsigned int i = 0; i < state->n_inputs; i++) {
            // get this input's map
            merkleized_map_commitment_t ith_map;

            int res = call_get_merkleized_map(dc, state->inputs_root, state->n_inputs, i, &ith_map);
            if (res < 0) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            // get prevout hash and output index for the i-th input
            uint8_t ith_prevout_hash[32];
            if (32 != call_get_merkleized_map_value(dc,
                                                    &ith_map,
                                                    (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                    1,
                                                    ith_prevout_hash,
                                                    32)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            crypto_hash_update(&sha_prevouts_context.header, ith_prevout_hash, 32);

            uint8_t ith_prevout_n_raw[4];
            if (4 != call_get_merkleized_map_value(dc,
                                                   &ith_map,
                                                   (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                                   1,
                                                   ith_prevout_n_raw,
                                                   4)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            crypto_hash_update(&sha_prevouts_context.header, ith_prevout_n_raw, 4);

            uint8_t ith_nSequence_raw[4];
            if (4 != call_get_merkleized_map_value(dc,
                                                   &ith_map,
                                                   (uint8_t[]){PSBT_IN_SEQUENCE},
                                                   1,
                                                   ith_nSequence_raw,
                                                   4)) {
                // if no PSBT_IN_SEQUENCE is present, we must assume nSequence 0xFFFFFFFF
                memset(ith_nSequence_raw, 0xFF, 4);
            }

            crypto_hash_update(&sha_sequences_context.header, ith_nSequence_raw, 4);
        }

        crypto_hash_digest(&sha_prevouts_context.header, state->hashes.sha_prevouts, 32);
        crypto_hash_digest(&sha_sequences_context.header, state->hashes.sha_sequences, 32);
    }

    {
        // compute sha_outputs
        cx_sha256_t sha_outputs_context;
        cx_sha256_init(&sha_outputs_context);

        if (hash_outputs(dc, &sha_outputs_context.header) == -1) {
            return;
        }

        crypto_hash_digest(&sha_outputs_context.header, state->hashes.sha_outputs, 32);
    }

    {
        // compute sha_amounts and sha_scriptpubkeys
        // TODO: could be skipped if there are no segwitv1 inputs to sign

        cx_sha256_t sha_amounts_context, sha_scriptpubkeys_context;

        cx_sha256_init(&sha_amounts_context);
        cx_sha256_init(&sha_scriptpubkeys_context);

        for (unsigned int i = 0; i < state->n_inputs; i++) {
            // get this input's map
            merkleized_map_commitment_t ith_map;

            int res = call_get_merkleized_map(dc, state->inputs_root, state->n_inputs, i, &ith_map);
            if (res < 0) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            // get prevout hash and output index for the i-th input
            uint8_t wit_utxo[8 + 1 + MAX_PREVOUT_SCRIPTPUBKEY_LEN];
            int ret = call_get_merkleized_map_value(dc,
                                                    &ith_map,
                                                    (uint8_t[]){PSBT_IN_WITNESS_UTXO},
                                                    1,
                                                    wit_utxo,
                                                    sizeof(wit_utxo));
            if (ret < 9) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }
            uint8_t scriptPubKey_len = wit_utxo[8];
            if (ret != 8 + 1 + scriptPubKey_len) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            uint8_t *scriptPubKey = wit_utxo + 9;

            crypto_hash_update(&sha_amounts_context.header, wit_utxo, 8);

            crypto_hash_update_varint(&sha_scriptpubkeys_context.header, scriptPubKey_len);
            crypto_hash_update(&sha_scriptpubkeys_context.header, scriptPubKey, scriptPubKey_len);
        }

        crypto_hash_digest(&sha_amounts_context.header, state->hashes.sha_amounts, 32);
        crypto_hash_digest(&sha_scriptpubkeys_context.header, state->hashes.sha_scriptpubkeys, 32);
    }

    if (segwit_version == 0) {
        dc->next(sign_segwit_v0);
        return;
    } else if (segwit_version == 1) {
        dc->next(sign_segwit_v1);

        return;
    }

    SEND_SW(dc, SW_BAD_STATE);  // can't happen
    return;
}

static void sign_segwit_v0(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    cx_sha256_t sighash_context;
    cx_sha256_init(&sighash_context);

    uint8_t tmp[8];

    // nVersion
    write_u32_le(tmp, 0, state->tx_version);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    {
        uint8_t dbl_hash[32];

        // add to hash: hashPrevouts = sha256(sha_prevouts)
        cx_hash_sha256(state->hashes.sha_prevouts, 32, dbl_hash, 32);
        crypto_hash_update(&sighash_context.header, dbl_hash, 32);

        // add to hash: hashSequence sha256(sha_sequences)
        cx_hash_sha256(state->hashes.sha_sequences, 32, dbl_hash, 32);
        crypto_hash_update(&sighash_context.header, dbl_hash, 32);
    }

    {
        // outpoint (32-byte prevout hash, 4-byte index)

        // get prevout hash and output index for the current input
        uint8_t prevout_hash[32];
        if (32 != call_get_merkleized_map_value(dc,
                                                &state->cur_input.map,
                                                (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                1,
                                                prevout_hash,
                                                32)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        crypto_hash_update(&sighash_context.header, prevout_hash, 32);

        uint8_t prevout_n_raw[4];
        if (4 != call_get_merkleized_map_value(dc,
                                               &state->cur_input.map,
                                               (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                               1,
                                               prevout_n_raw,
                                               4)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        crypto_hash_update(&sighash_context.header, prevout_n_raw, 4);
    }

    // scriptCode
    if (is_p2wpkh(state->cur_input.script, state->cur_input.script_len)) {
        // P2WPKH(script[2:22])
        crypto_hash_update_u32(&sighash_context.header, 0x1976a914);
        crypto_hash_update(&sighash_context.header, state->cur_input.script + 2, 20);
        crypto_hash_update_u16(&sighash_context.header, 0x88ac);
    } else if (is_p2wsh(state->cur_input.script, state->cur_input.script_len)) {
        // P2WSH

        // update sighash_context.header with the length-prefixed witnessScript,
        // and also compute sha256(witnessScript)
        cx_sha256_t witnessScript_hash_context;
        cx_sha256_init(&witnessScript_hash_context);

        int witnessScript_len = update_hashes_with_map_value(dc,
                                                             &state->cur_input.map,
                                                             (uint8_t[]){PSBT_IN_WITNESS_SCRIPT},
                                                             1,
                                                             &witnessScript_hash_context.header,
                                                             &sighash_context.header);

        if (witnessScript_len < 0) {
            PRINTF("Error fetching witnessScript\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        uint8_t witnessScript_hash[32];
        crypto_hash_digest(&witnessScript_hash_context.header, witnessScript_hash, 32);

        // check that script == P2WSH(witnessScript)
        if (state->cur_input.script_len != 2 + 32 || state->cur_input.script[0] != 0x00 ||
            state->cur_input.script[1] != 0x20 ||
            memcmp(state->cur_input.script + 2, witnessScript_hash, 32) != 0) {
            PRINTF("Mismatching witnessScript\n");

            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    } else {
        PRINTF("Invalid or unsupported script in segwit transaction\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    {
        // input value, taken from the WITNESS_UTXO field
        uint8_t witness_utxo[8 + 1 + MAX_PREVOUT_SCRIPTPUBKEY_LEN];

        int witness_utxo_len = call_get_merkleized_map_value(dc,
                                                             &state->cur_input.map,
                                                             (uint8_t[]){PSBT_IN_WITNESS_UTXO},
                                                             1,
                                                             witness_utxo,
                                                             sizeof(witness_utxo));
        if (witness_utxo_len < 8) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        crypto_hash_update(&sighash_context.header,
                           witness_utxo,
                           8);  // only the first 8 bytes (amount)
    }

    // nSequence
    {
        uint8_t nSequence_raw[4];
        if (4 != call_get_merkleized_map_value(dc,
                                               &state->cur_input.map,
                                               (uint8_t[]){PSBT_IN_SEQUENCE},
                                               1,
                                               nSequence_raw,
                                               4)) {
            // if no PSBT_IN_SEQUENCE is present, we must assume nSequence 0xFFFFFFFF
            memset(nSequence_raw, 0xFF, 4);
        }
        crypto_hash_update(&sighash_context.header, nSequence_raw, 4);
    }

    {
        // compute hashOutputs = sha256(sha_outputs)

        uint8_t hashOutputs[32];
        cx_hash_sha256(state->hashes.sha_outputs, 32, hashOutputs, 32);

        crypto_hash_update(&sighash_context.header, hashOutputs, 32);
    }

    // nLocktime
    write_u32_le(tmp, 0, state->locktime);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // sighash type
    write_u32_le(tmp, 0, state->cur_input.sighash_type);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // compute sighash
    crypto_hash_digest(&sighash_context.header, state->sighash, 32);
    cx_hash_sha256(state->sighash, 32, state->sighash, 32);

    dc->next(sign_sighash_ecdsa);
}

static void sign_segwit_v1(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    cx_sha256_t sighash_context;
    crypto_tr_tagged_hash_init(&sighash_context, BIP0341_sighash_tag, sizeof(BIP0341_sighash_tag));
    // the first 0x00 byte is not part of SigMsg
    crypto_hash_update_u8(&sighash_context.header, 0x00);

    uint8_t tmp[32];

    // hash type
    uint8_t sighash_byte = (uint8_t) (state->cur_input.sighash_type & 0xFF);
    crypto_hash_update_u8(&sighash_context.header, sighash_byte);

    // nVersion
    write_u32_le(tmp, 0, state->tx_version);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // nLocktime
    write_u32_le(tmp, 0, state->locktime);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    if ((sighash_byte & 0x80) != SIGHASH_ANYONECANPAY) {
        crypto_hash_update(&sighash_context.header, state->hashes.sha_prevouts, 32);
        crypto_hash_update(&sighash_context.header, state->hashes.sha_amounts, 32);
        crypto_hash_update(&sighash_context.header, state->hashes.sha_scriptpubkeys, 32);
        crypto_hash_update(&sighash_context.header, state->hashes.sha_sequences, 32);
    }

    if ((sighash_byte & 3) != SIGHASH_NONE && (sighash_byte & 3) != SIGHASH_SINGLE) {
        crypto_hash_update(&sighash_context.header, state->hashes.sha_outputs, 32);
    }

    // annex and ext_flags not supported, so spend_type = 0
    crypto_hash_update_u8(&sighash_context.header, 0x00);

    if ((sighash_byte & 0x80) == SIGHASH_ANYONECANPAY) {
        // outpoint (hash)
        if (32 != call_get_merkleized_map_value(dc,
                                                &state->cur_input.map,
                                                (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                1,
                                                tmp,
                                                32)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
        crypto_hash_update(&sighash_context.header, tmp, 32);

        // outpoint (output index)
        if (4 != call_get_merkleized_map_value(dc,
                                               &state->cur_input.map,
                                               (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                               1,
                                               tmp,
                                               4)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
        crypto_hash_update(&sighash_context.header, tmp, 4);

        // amount
        write_u64_le(tmp, 0, state->cur_input.prevout_amount);
        crypto_hash_update(&sighash_context.header, tmp, 8);

        // scriptPubKey
        crypto_hash_update(&sighash_context.header,
                           state->cur_input.prevout_scriptpubkey,
                           state->cur_input.prevout_scriptpubkey_len);

        // nSequence
        if (4 != call_get_merkleized_map_value(dc,
                                               &state->cur_input.map,
                                               (uint8_t[]){PSBT_IN_SEQUENCE},
                                               1,
                                               tmp,
                                               4)) {
            // if no PSBT_IN_SEQUENCE is present, we must assume nSequence 0xFFFFFFFF
            memset(tmp, 0xFF, 4);
        }
        crypto_hash_update(&sighash_context.header, tmp, 4);
    } else {
        // input_index
        write_u32_le(tmp, 0, state->cur_input_index);
        crypto_hash_update(&sighash_context.header, tmp, 4);
    }

    // no annex

    // TODO: SIGHASH_SINGLE not implemented

    crypto_hash_digest(&sighash_context.header, state->sighash, 32);

    dc->next(sign_sighash_schnorr);
}

// Common for legacy and segwitv0 transactions
static void sign_sighash_ecdsa(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    uint32_t sign_path[MAX_BIP32_PATH_STEPS];
    for (int i = 0; i < state->our_key_derivation_length; i++) {
        sign_path[i] = state->our_key_derivation[i];
    }
    sign_path[state->our_key_derivation_length] = state->cur_input.change;
    sign_path[state->our_key_derivation_length + 1] = state->cur_input.address_index;

    int sign_path_len = state->our_key_derivation_length + 2;

    uint8_t sig[MAX_DER_SIG_LEN];

    int sig_len =
        crypto_ecdsa_sign_sha256_hash_with_key(sign_path, sign_path_len, state->sighash, sig, NULL);
    if (sig_len < 0) {
        // unexpected error when signing
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    // yield signature
    uint8_t cmd = CCMD_YIELD;
    dc->add_to_response(&cmd, 1);
    uint8_t input_index = (uint8_t) state->cur_input_index;
    dc->add_to_response(&input_index, 1);
    dc->add_to_response(&sig, sig_len);
    uint8_t sighash_byte = (uint8_t) (state->cur_input.sighash_type & 0xFF);
    dc->add_to_response(&sighash_byte, 1);
    dc->finalize_response(SW_INTERRUPTED_EXECUTION);

    if (dc->process_interruption(dc) < 0) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    ++state->cur_input_index;
    dc->next(sign_process_input_map);
}

// Signing for segwitv1 (taproot)
static void sign_sighash_schnorr(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    cx_ecfp_private_key_t private_key = {0};
    uint8_t *seckey = private_key.d;  // convenience alias (entirely within the private_key struct)

    uint8_t chain_code[32] = {0};

    uint32_t sign_path[MAX_BIP32_PATH_STEPS];
    for (int i = 0; i < state->our_key_derivation_length; i++) {
        sign_path[i] = state->our_key_derivation[i];
    }
    sign_path[state->our_key_derivation_length] = state->cur_input.change;
    sign_path[state->our_key_derivation_length + 1] = state->cur_input.address_index;

    int sign_path_len = state->our_key_derivation_length + 2;

    uint8_t sig[64];
    size_t sig_len;

    bool error = false;
    BEGIN_TRY {
        TRY {
            crypto_derive_private_key(&private_key, chain_code, sign_path, sign_path_len);
            crypto_tr_tweak_seckey(seckey);

            unsigned int err = cx_ecschnorr_sign_no_throw(&private_key,
                                                          CX_ECSCHNORR_BIP0340 | CX_RND_TRNG,
                                                          CX_SHA256,
                                                          state->sighash,
                                                          32,
                                                          sig,
                                                          &sig_len);
            if (err != CX_OK) {
                error = true;
            }
        }
        CATCH_ALL {
            error = true;
        }
        FINALLY {
            explicit_bzero(&private_key, sizeof(private_key));
        }
    }
    END_TRY;

    if (error) {
        // unexpected error when signing
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    if (sig_len != 64) {
        PRINTF("SIG LEN: %d\n", sig_len);
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    // yield signature
    uint8_t cmd = CCMD_YIELD;
    dc->add_to_response(&cmd, 1);
    uint8_t input_index = (uint8_t) state->cur_input_index;
    dc->add_to_response(&input_index, 1);
    dc->add_to_response(&sig, sizeof(sig));

    // only append the sighash type byte if it is non-zero
    uint8_t sighash_byte = (uint8_t) (state->cur_input.sighash_type & 0xFF);
    if (sighash_byte != 0x00) {
        // only add the sighash byte if not 0
        dc->add_to_response(&sighash_byte, 1);
    }
    dc->finalize_response(SW_INTERRUPTED_EXECUTION);

    if (dc->process_interruption(dc) < 0) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    ++state->cur_input_index;
    dc->next(sign_process_input_map);
}

static void finalize(dispatcher_context_t *dc) {
    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    SEND_SW(dc, SW_OK);
}