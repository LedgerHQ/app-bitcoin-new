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
#include "../common/write.h"

#include "../constants.h"
#include "../types.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"

#include "client_commands.h"

#include "lib/policy.h"
#include "sign_psbt.h"


// Pre-approval
static void ui_action_validate_wallet_authorized(dispatcher_context_t *dc, bool accept);

// Input validation
static void process_input_map(dispatcher_context_t *dc);
static void process_global_tx_for_input(dispatcher_context_t *dc);
static void receive_global_tx_info_for_input(dispatcher_context_t *dc);
static void request_non_witness_utxo(dispatcher_context_t *dc);
static void receive_non_witness_utxo(dispatcher_context_t *dc);
static void check_input_owned(dispatcher_context_t *dc);

// Output validation
static void verify_outputs_init(dispatcher_context_t *dc);
static void process_output_map(dispatcher_context_t *dc);
static void process_global_tx_for_output(dispatcher_context_t *dc);
static void receive_global_tx_info_for_output(dispatcher_context_t *dc);
static void check_output_owned(dispatcher_context_t *dc);


// Signing process (all)
static void sign_init(dispatcher_context_t *dc);
static void sign_process_input_map(dispatcher_context_t *dc);
static void request_non_witness_utxo_for_signing(dispatcher_context_t *dc);
static void receive_non_witness_utxo_for_signing(dispatcher_context_t *dc);


// Legacy signing (P2PKH and P2SH)
static void sign_legacy(dispatcher_context_t *dc);
static void sign_legacy_first_pass_completed(dispatcher_context_t *dc);

static void sign_legacy_validate_redeemScript(dispatcher_context_t *dc);

static void sign_legacy_start_second_pass(dispatcher_context_t *dc);

static void compute_sighash_and_sign_legacy(dispatcher_context_t *dc);


// Segwit signing (P2WPKH and P2WSH)
static void sign_segwit(dispatcher_context_t *dc);
static void sign_segwit_tx_parsed(dispatcher_context_t *dc);

// End point end return
static void finalize(dispatcher_context_t *dc);


/*
Current assumptions during signing:
- exactly one of the keys in the wallet is internal
- all the keys in the wallet have a wildcard (that is, they end with '**')
*/


void PRINTF_BIP32_PATH(const uint32_t *path, size_t path_len) {
    PRINTF("m");
    for (unsigned int i = 0; i < path_len; i++) {
        PRINTF("/%d", path[i] & 0x7FFFFFFF);
        if (path[i] & 0x80000000) {
            PRINTF("'");
        }
    }
    PRINTF("\n");
}

/**
 * Validates the input, initializes the hash context and starts accumulating the wallet header in it.
 */
void handler_sign_psbt(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dc
) {
    (void)lc;

    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    if (p1 != 0 || p2 != 0) {
        SEND_SW(dc, SW_WRONG_P1P2);
        return;
    }

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        SEND_SW(dc, SW_SECURITY_STATUS_NOT_SATISFIED);
        return;
    }

    if (!buffer_read_varint(&dc->read_buffer, &state->global_map.size)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    if (state->global_map.size > 252) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }


    if (!buffer_read_bytes(&dc->read_buffer, state->global_map.keys_root, 20)
        || !buffer_read_bytes(&dc->read_buffer, state->global_map.values_root, 20))
    {
        LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }


    uint64_t n_inputs;
    if (   !buffer_read_varint(&dc->read_buffer, &n_inputs)
        || !buffer_read_bytes(&dc->read_buffer, state->inputs_root, 20))
    {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    if (n_inputs > MAX_N_INPUTS_CAN_SIGN) {
        // TODO: remove this limitation
        PRINTF("At most %d inputs are supported", MAX_N_INPUTS_CAN_SIGN);
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    state->n_inputs = (size_t)n_inputs;


    uint64_t n_outputs;
    if (   !buffer_read_varint(&dc->read_buffer, &n_outputs)
        || !buffer_read_bytes(&dc->read_buffer, state->outputs_root, 20))
    {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    if (n_outputs > MAX_N_OUTPUTS_CAN_SIGN) {
        // TODO: remove this limitation
        PRINTF("At most %d outputs are supported", MAX_N_OUTPUTS_CAN_SIGN);
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    state->n_outputs = (size_t)n_outputs;

    uint8_t wallet_id[32];
    uint8_t wallet_sig_len;
    uint8_t wallet_sig[MAX_DER_SIG_LEN];
    if (   !buffer_read_bytes(&dc->read_buffer, wallet_id, 32)
        || !buffer_read_u8(&dc->read_buffer, &wallet_sig_len)
        || !buffer_read_bytes(&dc->read_buffer, wallet_sig, wallet_sig_len))
    {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    if (wallet_sig_len != 0) {
        PRINTF("Signature length: %d\n", wallet_sig_len);
        // Verify signature
        if (!crypto_verify_sha256_hash(wallet_id, wallet_sig, wallet_sig_len)) {
            SEND_SW(dc, SW_SIGNATURE_FAIL);
            return;
        }
    } else {
        // TODO: verify that the wallet is a canonical one that does not require signature
    }

    if ((read_policy_map_wallet(&dc->read_buffer, &state->wallet_header)) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    buffer_t policy_map_buffer = buffer_create(&state->wallet_header.policy_map, state->wallet_header.policy_map_len);

    if (parse_policy_map(&policy_map_buffer, state->wallet_policy_map_bytes, sizeof(state->wallet_policy_map_bytes)) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    state->inputs_total_value = 0;
    state->internal_inputs_total_value = 0;
    memset(state->internal_inputs, 0, sizeof state->internal_inputs);

    // Get the master's key fingerprint
    uint8_t master_pub_key[33];
    uint32_t bip32_path[] = {};
    crypto_get_compressed_pubkey_at_path(bip32_path, 0, master_pub_key, NULL);
    state->master_key_fingerprint = crypto_get_key_fingerprint(master_pub_key);

    // Check integrity of the global map
    if (call_check_merkle_tree_sorted(dc, state->global_map.keys_root, (size_t)state->global_map.size) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
    } else {
        // TODO: check if wallet is canonical, skip wallet authorization if so

        dc->pause();
        ui_authorize_wallet_spend(dc,
                                  state->wallet_header.name,
                                  ui_action_validate_wallet_authorized);
    }
}

static void ui_action_validate_wallet_authorized(dispatcher_context_t *dc, bool accept) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    if (!accept) {
        SEND_SW(dc, SW_DENY);
        return;
    }

    state->cur_input_index = 0;
    dc->next(process_input_map);
    dc->run();
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
        } else if (key_type == PSBT_IN_REDEEM_SCRIPT) {
            state->cur_input.has_redeemScript = true;
        } else if (key_type == PSBT_IN_SIGHASH_TYPE) {
            state->cur_input.has_sighash_type = true;
        } else if (key_type == PSBT_IN_BIP32_DERIVATION && !state->cur_input.has_bip32_derivation) {
            // The first time that we encounter a PSBT_IN_SIGHASH_TYPE key, we store the pubkey
            state->cur_input.has_bip32_derivation = true;

            if (   !buffer_read_bytes(data, state->cur_input.bip32_derivation_pubkey, 33) // read pubkey
                || buffer_can_read(data, 1) // ...but should not be able to read more
            )
            {
                state->cur_input.unexpected_pubkey_error = true;
            }
        }
    }
}


static void process_input_map(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    if (state->cur_input_index >= state->n_inputs) {
        // all inputs already processed
        dc->next(verify_outputs_init);
        return;
    }

    // Reset cur_input struct
    memset(&state->cur_input, 0, sizeof(state->cur_input));

    int res = call_get_merkleized_map_with_callback(dc,
                                                    state->inputs_root,
                                                    state->n_inputs,
                                                    state->cur_input_index,
                                                    make_callback(state, (dispatcher_callback_t)input_keys_callback),
                                                    &state->cur_input.map);
    if (res < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    if (state->cur_input.unexpected_pubkey_error) {
        PRINTF("Unexpected pubkey length"); // only compressed pubkeys are supported
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }


    dc->next(process_global_tx_for_input);
}

static void process_global_tx_for_input(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    cx_sha256_init(&state->hash_context);

    state->tmp[0] = PSBT_GLOBAL_UNSIGNED_TX;
    call_psbt_parse_rawtx(dc,
                          &state->subcontext.psbt_parse_rawtx,
                          receive_global_tx_info_for_input,
                          &state->hash_context,
                          &state->global_map,
                          state->tmp,
                          1,
                          PARSEMODE_TXID,
                          state->cur_input_index,
                          -1, // output index, not used
                          0  // ignored
                          );
}

static void receive_global_tx_info_for_input(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // Keep track of the input's prevout hash and index
    memcpy(state->cur_input.prevout_hash, state->subcontext.psbt_parse_rawtx.program_state.compute_txid.prevout_hash, 32);
    state->cur_input.prevout_n = state->subcontext.psbt_parse_rawtx.program_state.compute_txid.prevout_n;

    // cache to prevent having to fetch it again later. TODO: should be removed after rewrite
    state->prevouts_n[state->cur_input_index] = state->cur_input.prevout_n;

    state->nLocktime = state->subcontext.psbt_parse_rawtx.program_state.compute_txid.nLocktime;
    state->outputs_total_value = state->subcontext.psbt_parse_rawtx.program_state.compute_txid.outputs_total_value;

    // TODO: remove debug info
    PRINTF("Prevout hash for input %d: ", state->cur_input_index);
    for (int i = 0; i < 32; i++) PRINTF("%02x", state->cur_input.prevout_hash[i]);
    PRINTF("\n");

    if (state->n_inputs != state->subcontext.psbt_parse_rawtx.n_inputs) {
        PRINTF("Mismatching n_inputs.");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    if (state->n_outputs != state->subcontext.psbt_parse_rawtx.n_outputs) {
        PRINTF("Mismatching n_outputs.");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    dc->next(request_non_witness_utxo);
}



static void request_non_witness_utxo(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);
    state->tmp[0] = PSBT_IN_NON_WITNESS_UTXO;

    cx_sha256_init(&state->hash_context);

    call_psbt_parse_rawtx(dc,
                          &state->subcontext.psbt_parse_rawtx,
                          receive_non_witness_utxo,
                          &state->hash_context,
                          &state->cur_input.map,
                          state->tmp,
                          1,
                          PARSEMODE_TXID,
                          -1,
                          state->cur_input.prevout_n,
                          0 // IGNORED
                          );
}

static void receive_non_witness_utxo(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    uint8_t txhash[32];

    crypto_hash_digest(&state->hash_context.header, txhash, 32);
    cx_hash_sha256(txhash, 32, txhash, 32);

    if (memcmp(txhash, state->cur_input.prevout_hash, 32) != 0) {
        PRINTF("Prevout hash did not match non-witness-utxo transaction hash\n");

        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    uint64_t prevout_value = state->subcontext.psbt_parse_rawtx.program_state.compute_txid.vout_value;

    state->inputs_total_value += prevout_value;

    state->cur_input.prevout_amount = prevout_value;

    state->cur_input.prevout_scriptpubkey_len = state->subcontext.psbt_parse_rawtx.program_state.compute_txid.vout_scriptpubkey_len;

    if (state->cur_input.prevout_scriptpubkey_len > MAX_PREVOUT_SCRIPTPUBKEY_LEN) {
        PRINTF("Prevout's scriptPubKey too long: %d\n", state->cur_input.prevout_scriptpubkey_len);
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    memcpy(state->cur_input.prevout_scriptpubkey,
           state->subcontext.psbt_parse_rawtx.program_state.compute_txid.vout_scriptpubkey,
           state->cur_input.prevout_scriptpubkey_len);

    dc->next(check_input_owned);
}

// TODO: this is wrong for mixed transaction were only some inputs are internal
static void check_input_owned(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // get path, obtain change and address_index,
    uint8_t key[1+33];
    key[0] = PSBT_IN_BIP32_DERIVATION;
    memcpy(key + 1, state->cur_input.bip32_derivation_pubkey, 33);

    uint8_t fpt_der[4 + 4*MAX_BIP32_PATH_STEPS];

    int len = call_get_merkleized_map_value(dc, &state->cur_input.map,
                                            key,
                                            sizeof(key),
                                            fpt_der,
                                            sizeof(fpt_der));

    // there must be at least 2 derivation steps (change and address_index),
    // so at least 12 bytes (the first 4 bytes are for the key's master fingerprint)
    if (len < 12 || len % 4 != 0) {
        PRINTF("Invalid PSBT_IN_BIP32_DERIVATION length: %d\n", len);
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // we interpret the final 8 bytes as change and address_index
    uint32_t change = read_u32_le(fpt_der, len - 8);
    uint32_t address_index = read_u32_le(fpt_der, len - 4);

    PRINTF("Change and address_index for input %d: %d, %d\n", state->cur_input_index, change, address_index);

    // TODO: derive wallet's scriptPubKey, check if it matches the expected one
    uint8_t wallet_script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    buffer_t wallet_script_buf = buffer_create(wallet_script, sizeof(wallet_script));

    int wallet_script_len = call_get_wallet_script(dc,
                                                   &state->wallet_policy_map,
                                                   state->wallet_header.keys_info_merkle_root,
                                                   state->wallet_header.n_keys,
                                                   change,
                                                   address_index,
                                                   &wallet_script_buf,
                                                   NULL);
    if (wallet_script_len < 0) {
        PRINTF("Failed to get wallet script\n");
        SEND_SW(dc, SW_BAD_STATE); // shouldn't happen
    }

    PRINTF("Computed script: ");
    for (int i = 0; i < wallet_script_len; i++)
        PRINTF("%02X", wallet_script[i]);
    PRINTF("\n");

    PRINTF("Expected script: ");
    for (int i = 0; i < state->cur_input.prevout_scriptpubkey_len; i++)
        PRINTF("%02X", state->cur_input.prevout_scriptpubkey[i]);
    PRINTF("\n");

    if (   wallet_script_len == state->cur_input.prevout_scriptpubkey_len
        && memcmp(wallet_script, state->cur_input.prevout_scriptpubkey, wallet_script_len) == 0)
    {
        PRINTF("Input %d is internal\n", state->cur_input_index);

        state->internal_inputs[state->cur_input_index] = 1;
        state->internal_inputs_total_value += state->cur_input.prevout_amount;
    } else {
        PRINTF("Input %d is external\n", state->cur_input_index);
    }


    ++state->cur_input_index;
    dc->next(process_input_map);
}

/** OUTPUTS VERIFICATION FLOW
 *
 *  For each output, check if it's a change address.
 *  Show each output that is not a change address to the user for verification.
 */

// TODO

// entry point for the outputs verification flow
static void verify_outputs_init(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // TODO: remove
    PRINTF("######## TOTAL INPUTS VALUE: %llu\n", state->inputs_total_value);
    // TODO: remove
    PRINTF("######## INTERNAL INPUTS VALUE: %llu\n", state->internal_inputs_total_value);

    state->outputs_total_value = 0;
    state->internal_outputs_total_value = 0;

    memset(state->internal_outputs, 0, sizeof state->internal_outputs);
    state->cur_output_index = 0;
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
            // The first time that we encounter a PSBT_IN_SIGHASH_TYPE key, we store the pubkey
            state->cur_output.has_bip32_derivation = true;

            if (   !buffer_read_bytes(data, state->cur_output.bip32_derivation_pubkey, 33) // read pubkey
                || buffer_can_read(data, 1) // ...but should not be able to read more
            )
            {
                state->cur_output.unexpected_pubkey_error = true;
            }
        }
    }
}

static void process_output_map(dispatcher_context_t *dc){
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    if (state->cur_output_index >= state->n_outputs) {
        // all inputs already processed
        dc->next(sign_init);
        return;
    }

    memset(&state->cur_output, 0, sizeof(state->cur_output));

    int res = call_get_merkleized_map_with_callback(dc,
                                                    state->outputs_root,
                                                    state->n_outputs,
                                                    state->cur_output_index,
                                                    make_callback(state, (dispatcher_callback_t)output_keys_callback),
                                                    &state->cur_output.map);
    if (res < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    if (state->cur_output.unexpected_pubkey_error) {
        PRINTF("Unexpected pubkey length"); // only compressed pubkeys are supported
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    dc->next(process_global_tx_for_output);
}

static void process_global_tx_for_output(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    cx_sha256_init(&state->hash_context); // TODO: redundant

    state->tmp[0] = PSBT_GLOBAL_UNSIGNED_TX;
    call_psbt_parse_rawtx(dc,
                          &state->subcontext.psbt_parse_rawtx,
                          receive_global_tx_info_for_output,
                          &state->hash_context,
                          &state->global_map,
                          state->tmp,
                          1,
                          PARSEMODE_TXID,
                          -1, // unused
                          state->cur_output_index, // output index, not used
                          0  // ignored
                          );
}

static void receive_global_tx_info_for_output(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // Keep track of the output's scriptpubkey
    int scriptpubkey_len = state->subcontext.psbt_parse_rawtx.program_state.compute_txid.vout_scriptpubkey_len;
    state->cur_output.scriptpubkey_len = scriptpubkey_len;
    memcpy(state->cur_output.scriptpubkey, state->subcontext.psbt_parse_rawtx.program_state.compute_txid.vout_scriptpubkey, scriptpubkey_len);

    uint64_t value = state->subcontext.psbt_parse_rawtx.program_state.compute_txid.vout_value;
    state->cur_output.value = value;
    state->outputs_total_value = value;

    PRINTF("######## OUTPUT %d VALUE: %llu\n", state->cur_output_index, value);

    dc->next(check_output_owned);
}

// TODO: lots of duplication with check_input_owned; refactor
static void check_output_owned(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // get path, obtain change and address_index,
    uint8_t key[1+33];
    key[0] = PSBT_OUT_BIP32_DERIVATION;
    memcpy(key + 1, state->cur_output.bip32_derivation_pubkey, 33);

    uint8_t fpt_der[4 + 4*MAX_BIP32_PATH_STEPS];

    int len = call_get_merkleized_map_value(dc, &state->cur_output.map,
                                            key,
                                            sizeof(key),
                                            fpt_der,
                                            sizeof(fpt_der));

    if (len > 0) {
        // there must be at least 2 derivation steps (change and address_index),
        // so at least 12 bytes (the first 4 bytes are for the key's master fingerprint)
        if (len < 12 || len % 4 != 0) {
            PRINTF("Invalid PSBT_OUT_BIP32_DERIVATION length: %d\n", len);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        // we interpret the final 8 bytes as change and address_index
        uint32_t change = read_u32_le(fpt_der, len - 8);
        uint32_t address_index = read_u32_le(fpt_der, len - 4);

        PRINTF("Change and address_index for output %d: %d, %d\n", state->cur_input_index, change, address_index);

        // TODO: derive wallet's scriptPubKey, check if it matches the expected one
        uint8_t wallet_script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
        buffer_t wallet_script_buf = buffer_create(wallet_script, sizeof(wallet_script));

        int wallet_script_len = call_get_wallet_script(dc,
                                                    &state->wallet_policy_map,
                                                    state->wallet_header.keys_info_merkle_root,
                                                    state->wallet_header.n_keys,
                                                    change,
                                                    address_index,
                                                    &wallet_script_buf,
                                                    NULL);
        if (wallet_script_len < 0) {
            PRINTF("Failed to get wallet script for output\n");
            SEND_SW(dc, SW_BAD_STATE); // shouldn't happen
        }

        PRINTF("Computed script: ");
        for (int i = 0; i < wallet_script_len; i++)
            PRINTF("%02X", wallet_script[i]);
        PRINTF("\n");

        PRINTF("Expected script: ");
        for (int i = 0; i < state->cur_output.scriptpubkey_len; i++)
            PRINTF("%02X", state->cur_output.scriptpubkey[i]);
        PRINTF("\n");

        if (   wallet_script_len == state->cur_output.scriptpubkey_len
            && memcmp(wallet_script, state->cur_output.scriptpubkey, wallet_script_len) == 0)
        {
            PRINTF("Output %d is internal\n", state->cur_output_index);

            state->internal_outputs[state->cur_output_index] = 1;
            state->internal_outputs_total_value += state->cur_output.value;
        } else {
            PRINTF("Output %d is external\n", state->cur_output_index);
        }
    } else {
        PRINTF("Output %d is external\n", state->cur_output_index);
    }

    ++state->cur_output_index;
    dc->next(process_output_map);
}


/** SIGNING FLOW
 *
 * Iterate over all inputs. For each input that should be signed, compute and sign sighash.
 */


// entry point for the signing flow
static void sign_init(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // find and parse our registered key info in the wallet
    bool our_key_found = false;
    for (unsigned int i = 0; i < state->wallet_header.n_keys; i++) {
        uint8_t key_info_str[MAX_POLICY_KEY_INFO_LEN];

        int key_info_len = call_get_merkle_leaf_element(dc,
                                                        state->wallet_header.keys_info_merkle_root,
                                                        state->wallet_header.n_keys,
                                                        i,
                                                        key_info_str,
                                                        sizeof(key_info_str));

        if (key_info_len < 0) {
            SEND_SW(dc, SW_BAD_STATE); // should never happen
            return;
        }

        // Make a sub-buffer for the pubkey info
        buffer_t key_info_buffer = buffer_create(key_info_str, key_info_len);

        if (parse_policy_map_key_info(&key_info_buffer, &state->our_key_info) == -1) {
            SEND_SW(dc, SW_BAD_STATE); // should never happen
            return;
        }

        uint32_t fpr = read_u32_be(state->our_key_info.master_key_fingerprint, 0);
        if (fpr == state->master_key_fingerprint) {
            // TODO: could be a collision, we should verify that we can generate the xpub here
            our_key_found = true;
            break;
        }
    }

    if (!our_key_found) {
        PRINTF("Couldn't find internal key\n");
        SEND_SW(dc, SW_BAD_STATE); // should never happen if we only register wallets with an internal key
        return;
    }

    state->cur_input_index = 0;
    dc->next(sign_process_input_map);
}


static void sign_process_input_map(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // skip external inputs
    while (state->cur_input_index < state->n_inputs && !state->internal_inputs[state->cur_input_index]) {
        ++state->cur_input_index;
    }

    if (state->cur_input_index >= state->n_inputs) {
        // all inputs already processed
        dc->next(finalize);
        return;
    }

    // Reset cur_input struct
    memset(&state->cur_input, 0, sizeof(state->cur_input));

    int res = call_get_merkleized_map_with_callback(dc,
                                                    state->inputs_root,
                                                    state->n_inputs,
                                                    state->cur_input_index,
                                                    make_callback(state, (dispatcher_callback_t)input_keys_callback),
                                                    &state->cur_input.map);
    if (res < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    if (!state->cur_input.has_sighash_type) {
        state->cur_input.sighash_type = SIGHASH_ALL;
    } else {
        // Get sighash type
        uint8_t result[4];
        if (4 != call_get_merkleized_map_value(dc, &state->cur_input.map,
                                               (uint8_t []){ PSBT_IN_SIGHASH_TYPE },
                                               1,
                                               result,
                                               sizeof(result)))
        {
            PRINTF("Malformed PSBT_IN_SIGHASH_TYPE for input %d\n", state->cur_input_index);

            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        state->cur_input.sighash_type = read_u32_le(result, 0);
    }

    // TODO: add support for other sighash flags
    if (state->cur_input.sighash_type != SIGHASH_ALL) {
        SEND_SW(dc, SW_INCORRECT_DATA); // TODO: more specific SW
        return;
    }

    // TODO: get and validate signing path
    // get path, obtain change and address_index,
    uint8_t key[1+33];
    key[0] = PSBT_IN_BIP32_DERIVATION;
    memcpy(key + 1, state->cur_input.bip32_derivation_pubkey, 33);

    uint8_t fpt_der[4 + 4*MAX_BIP32_PATH_STEPS];

    int len = call_get_merkleized_map_value(dc, &state->cur_input.map,
                                            key,
                                            sizeof(key),
                                            fpt_der,
                                            sizeof(fpt_der));

    // there must be at least 2 derivation steps (change and address_index),
    // so at least 12 bytes (the first 4 bytes are for the key's master fingerprint)
    if (len < 12 || len % 4 != 0) {
        PRINTF("Invalid PSBT_IN_BIP32_DERIVATION length: %d\n", len);
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // we interpret the final 8 bytes as change and address_index
    state->cur_input.change = read_u32_le(fpt_der, len - 8);
    state->cur_input.address_index = read_u32_le(fpt_der, len - 4);


    dc->next(request_non_witness_utxo_for_signing);
}


// TODO: duplicate of the input flow, but we need to read the prevout value
//       make sure this is gone after migrating to PSBTv2
static void request_non_witness_utxo_for_signing(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);
    state->tmp[0] = PSBT_IN_NON_WITNESS_UTXO;

    cx_sha256_init(&state->hash_context);

    call_psbt_parse_rawtx(dc,
                          &state->subcontext.psbt_parse_rawtx,
                          receive_non_witness_utxo_for_signing,
                          &state->hash_context,
                          &state->cur_input.map,
                          state->tmp,
                          1,
                          PARSEMODE_TXID,
                          -1,
                          state->prevouts_n[state->cur_input_index],
                          0 // IGNORED
                          );
}

static void receive_non_witness_utxo_for_signing(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    state->cur_input.prevout_amount = state->subcontext.psbt_parse_rawtx.program_state.compute_txid.vout_value;

    // Sign as segwit input iff it has a witness utxo
    if (!state->cur_input.has_witnessUtxo) {
        dc->next(sign_legacy);
    } else {
        dc->next(sign_segwit);
    }
}

static void sign_legacy(dispatcher_context_t *dc) {
    // sign legacy P2PKH or P2SH

    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // sign_non_witness(non_witness_utxo.vout[psbt.tx.input_[i].prevout.n].scriptPubKey, i)

    cx_sha256_init(&state->hash_context);

    state->tmp[0] = PSBT_GLOBAL_UNSIGNED_TX;
    call_psbt_parse_rawtx(dc,
                          &state->subcontext.psbt_parse_rawtx,
                          sign_legacy_first_pass_completed,
                          &state->hash_context,
                          &state->global_map,
                          state->tmp,
                          1,
                          PARSEMODE_LEGACY_PASS1,
                          state->cur_input_index,
                          -1, // output index, not used
                          state->cur_input.sighash_type);
}



static void sign_legacy_first_pass_completed(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);


    // TODO: for legacy, we need the prevout_scriptpubkey from the non_witness_utxo.
    //       therefore, we need to process the non_witness_utxo again
    //       BROKEN: currently using cur_input.prevout_scriptpubkey without initializing it.

    if (!state->cur_input.has_redeemScript) {
        // P2PKH, the script_code is the prevout's scriptPubKey
        crypto_hash_update_varint(&state->hash_context.header, state->cur_input.prevout_scriptpubkey_len);
        crypto_hash_update(&state->hash_context.header,
                           state->cur_input.prevout_scriptpubkey,
                           state->cur_input.prevout_scriptpubkey_len);
        dc->next(sign_legacy_start_second_pass);
    } else {
        // P2SH, the script_code is the redeemScript
        state->tmp[0] = PSBT_IN_SIGHASH_TYPE;
        call_psbt_process_redeemScript(dc, &state->subcontext.psbt_process_redeemScript, sign_legacy_validate_redeemScript,
                                       &state->hash_context,
                                       &state->cur_input.map,
                                       state->tmp,
                                       1);
    }
}

static void sign_legacy_validate_redeemScript(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // TODO: P2SH still untested.

    if (state->cur_input.prevout_scriptpubkey_len != 2 + 20 + 1) {
        PRINTF("P2SH's scriptPubKey should be exactly 23 bytes\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    if (memcmp(state->cur_input.prevout_scriptpubkey, state->subcontext.psbt_process_redeemScript.p2sh_script, 23) != 0) {
        PRINTF("redeemScript does not match prevout's scriptPubKey\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    dc->next(sign_legacy_start_second_pass);
}


static void sign_legacy_start_second_pass(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    state->tmp[0] = PSBT_GLOBAL_UNSIGNED_TX;
    call_psbt_parse_rawtx(dc,
                          &state->subcontext.psbt_parse_rawtx,
                          compute_sighash_and_sign_legacy,
                          &state->hash_context,
                          &state->global_map,
                          state->tmp,
                          1,
                          PARSEMODE_LEGACY_PASS2,
                          state->cur_input_index,
                          -1, // output index, not used
                          state->cur_input.sighash_type
                          );
}


static void compute_sighash_and_sign_legacy(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    uint8_t sighash[32];

    //compute sighash
    crypto_hash_digest(&state->hash_context.header, sighash, 32);
    cx_hash_sha256(sighash, 32, sighash, 32);

    // TODO: remove
    PRINTF("sighash: ");
    for (int i = 0; i < 32; i++)
        PRINTF("%02x", sighash[i]);
    PRINTF("\n");


    cx_ecfp_private_key_t private_key = {0};
    uint8_t chain_code[32] = {0};
    uint32_t info = 0;

    // TODO: should check the signing pubkey ant path matches in the PSBT
    uint32_t sign_path[MAX_BIP32_PATH_STEPS];
    for (unsigned int i = 0; i < state->our_key_info.master_key_derivation_len; i++) {
        sign_path[i] = state->our_key_info.master_key_derivation[i];
    }
    sign_path[state->our_key_info.master_key_derivation_len] = state->cur_input.change;
    sign_path[state->our_key_info.master_key_derivation_len+1] = state->cur_input.address_index;

    // TODO: refactor the signing code elsewhere
    int sign_path_len = state->our_key_info.master_key_derivation_len + 2;

    PRINTF("Signing path for input %d: ", state->cur_input_index); // TODO: remove
    PRINTF_BIP32_PATH(sign_path, sign_path_len);

    crypto_derive_private_key(&private_key, chain_code, sign_path, sign_path_len);

    uint8_t sig[MAX_DER_SIG_LEN];

    int sig_len = 0;
    BEGIN_TRY {
        TRY {
            sig_len = cx_ecdsa_sign(&private_key,
                                    CX_RND_RFC6979,
                                    CX_SHA256,
                                    sighash,
                                    32,
                                    sig,
                                    MAX_DER_SIG_LEN,
                                    &info);
        }
        CATCH_OTHER(e) {
            return;
        }
        FINALLY {
            explicit_bzero(&private_key, sizeof(private_key));
        }
    }
    END_TRY;



    // TODO: send signature for this input
    PRINTF("######## signature for input %d: ", state->cur_input_index);
    for (int i = 0; i < sig_len; i++)
        PRINTF("%02x", sig[i]);
    PRINTF("\n");

    // yield signature
    uint8_t cmd = CCMD_YIELD;
    dc->add_to_response(&cmd, 1);
    uint8_t input_index = (uint8_t)state->cur_input_index;
    dc->add_to_response(&input_index, 1);
    dc->add_to_response(&sig, sig_len);
    uint8_t sighash_byte = (uint8_t)(state->cur_input.sighash_type & 0xFF);
    dc->add_to_response(&sighash_byte, 1);
    dc->finalize_response(SW_INTERRUPTED_EXECUTION);

    if (dc->process_interruption(dc) < 0) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    ++state->cur_input_index;
    dc->next(sign_process_input_map);
}



static void sign_segwit(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    cx_sha256_init(&state->hash_context);

    memset(&state->subcontext, 0, sizeof(state->subcontext));
    state->tmp[0] = PSBT_GLOBAL_UNSIGNED_TX;
    call_psbt_parse_rawtx(dc,
                          &state->subcontext.psbt_parse_rawtx,
                          sign_segwit_tx_parsed,
                          NULL,
                          &state->global_map,
                          state->tmp,
                          1,
                          PARSEMODE_SEGWIT_V0,
                          state->cur_input_index,
                          -1, // output index, not used
                          state->cur_input.sighash_type);
}


static void sign_segwit_tx_parsed(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // Keep track of the input's prevout hash and index
    memcpy(state->cur_input.prevout_hash, state->subcontext.psbt_parse_rawtx.program_state.compute_sighash_segwit_v0.prevout_hash, 32);
    state->cur_input.prevout_n = state->subcontext.psbt_parse_rawtx.program_state.compute_sighash_segwit_v0.prevout_n;
    state->cur_input.prevout_nSequence = state->subcontext.psbt_parse_rawtx.program_state.compute_sighash_segwit_v0.prevout_nSequence;

    uint8_t script[64]; // TODO: check correct length
    int script_len;

    uint8_t raw_witnessUtxo[8 + 1 + 63]; // TODO: check correct maximum length

    int wit_utxo_len = call_get_merkleized_map_value(dc,
                                                     &state->cur_input.map,
                                                     (uint8_t []){ PSBT_IN_WITNESS_UTXO },
                                                     1,
                                                     raw_witnessUtxo,
                                                     sizeof(raw_witnessUtxo));
    if (wit_utxo_len < 0) {
        PRINTF("Error fetching witness utxo\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // TODO: remove debug prints
    PRINTF("Witness utxo for input %d: ", state->cur_input_index);
    for (int i = 0; i < wit_utxo_len; i++)
        PRINTF("%02x", raw_witnessUtxo[i]);
    PRINTF("\n");

    int wit_utxo_scriptPubkey_len = raw_witnessUtxo[8];

    if (wit_utxo_len != 8 + 1 + wit_utxo_scriptPubkey_len) {
        PRINTF("Length mismatch for witness utxo's scriptPubKey\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    uint8_t *wit_utxo_scriptPubkey = raw_witnessUtxo + 9;

    if (state->cur_input.has_redeemScript) {
        // Get redeemScript
        uint8_t redeemScript[64];

        int redeemScript_length = call_get_merkleized_map_value(dc,
                                                                 &state->cur_input.map,
                                                                 (uint8_t []){ PSBT_IN_REDEEM_SCRIPT },
                                                                 1,
                                                                 redeemScript,
                                                                 sizeof(redeemScript));
        if (redeemScript_length < 0) {
            PRINTF("Error fetching redeem script\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        // TODO: remove debug prints
        PRINTF("Redeem script for input %d: ", state->cur_input_index);
        for (int i = 0; i < redeemScript_length; i++)
            PRINTF("%02x", redeemScript);
        PRINTF("\n");

        uint8_t p2sh_redeemscript[2 + 20 + 1];
        p2sh_redeemscript[0] = 0xa9;
        p2sh_redeemscript[1] = 0x14;
        crypto_hash160(redeemScript, redeemScript_length, p2sh_redeemscript + 2);
        p2sh_redeemscript[22] = 0x87;

        if (wit_utxo_scriptPubkey_len != 23 || memcmp(wit_utxo_scriptPubkey, p2sh_redeemscript, 23) != 0) {
            PRINTF("witnessUtxo's scriptPubKey does not match redeemScript\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        memcpy(script, redeemScript, redeemScript_length);
        script_len = redeemScript_length;
    } else {
        memcpy(script, wit_utxo_scriptPubkey, wit_utxo_scriptPubkey_len);
        script_len = wit_utxo_scriptPubkey_len;
    }

    // Compute sighash

    cx_sha256_init(&state->hash_context);

    uint8_t tmp[8];

    // nVersion
    PRINTF("SIGHASH: nVersion: %d\n", state->subcontext.psbt_parse_rawtx.program_state.compute_sighash_segwit_v0.nVersion);
    write_u32_le(tmp, 0, state->subcontext.psbt_parse_rawtx.program_state.compute_sighash_segwit_v0.nVersion);
    crypto_hash_update(&state->hash_context.header, tmp, 4);

    // hashPrevouts
    PRINTF("SIGHASH: hashPrevouts: ");
    for (int i = 0; i < 32; i++) PRINTF("%02X", state->subcontext.psbt_parse_rawtx.program_state.compute_sighash_segwit_v0.hashPrevouts[i]);
    PRINTF("\n");
    crypto_hash_update(&state->hash_context.header,
                       state->subcontext.psbt_parse_rawtx.program_state.compute_sighash_segwit_v0.hashPrevouts,
                       32);

    // hashSequence
    PRINTF("SIGHASH: hashSequence: ");
    for (int i = 0; i < 32; i++) PRINTF("%02X", state->subcontext.psbt_parse_rawtx.program_state.compute_sighash_segwit_v0.hashSequence[i]);
    PRINTF("\n");
    crypto_hash_update(&state->hash_context.header,
                       state->subcontext.psbt_parse_rawtx.program_state.compute_sighash_segwit_v0.hashSequence,
                       32);

    // outpoint (32-byte prevout hash, 4-byte index)
    PRINTF("SIGHASH: outpoint: ");
    for (int i = 0; i < 32; i++) PRINTF("%02X", state->cur_input.prevout_hash[i]);
    PRINTF(" - %d\n", state->cur_input.prevout_n);
    crypto_hash_update(&state->hash_context.header, state->cur_input.prevout_hash, 32);
    write_u32_le(tmp, 0, state->cur_input.prevout_n);
    crypto_hash_update(&state->hash_context.header, tmp, 4);

    // scriptCode
    if (is_p2wpkh(script, script_len)) {
        PRINTF("P2WPKH spend\n"); // TODO: remove
        // P2WPKH(script[2:22])
        crypto_hash_update_u32(&state->hash_context.header, 0x1976a914);
        crypto_hash_update(&state->hash_context.header, script + 2, 20);
        crypto_hash_update_u16(&state->hash_context.header, 0x88ac);

        PRINTF("SIGHASH: scriptcode: ");
        PRINTF("1976a914");
        for (int i = 0; i < 20; i++) PRINTF("%02X", script[2 + i]);
        PRINTF("88ac\n");
    } else if (is_p2wsh(script, script_len)) {
        PRINTF("P2WSH spend\n"); // TODO: remove
        // P2WSH

        uint8_t witnessScript[128]; // TODO: we need to support arbitrary length witnessScripts

        int witnessScript_len = call_get_merkleized_map_value(dc,
                                                              &state->cur_input.map,
                                                              (uint8_t []){ PSBT_IN_WITNESS_SCRIPT },
                                                              1,
                                                              witnessScript,
                                                              sizeof(witnessScript));

        if (witnessScript_len < 0) {
            PRINTF("Error fetching witnessScript\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        uint8_t witnessScript_hash[32];
        cx_hash_sha256(witnessScript, witnessScript_len, witnessScript_hash, 32);

        // check that script == P2WSH(witnessScript), add witnessScript to hash
        if (script_len != 2+32
            || script[0] != 0x00
            || script[1] != 0x20
            || memcmp(script + 2, witnessScript_hash, 32) != 0
        ) {
            PRINTF("Mismatching witnessScript\n");

            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        PRINTF("SIGHASH: witnessScript: ");
        for (int i = 0; i < witnessScript_len; i++) PRINTF("%02X", witnessScript[i]);
        PRINTF("\n");

        // add witnessScript to hash
        crypto_hash_update(&state->hash_context.header, witnessScript, witnessScript_len);
    } else {
        PRINTF("Invalid or unsupported script in segwit transaction\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // value
    PRINTF("SIGHASH: value: %llu\n", state->cur_input.prevout_amount);
    write_u64_le(tmp, 0, state->cur_input.prevout_amount);
    crypto_hash_update(&state->hash_context.header, tmp, 8);

    // nSequence
    PRINTF("SIGHASH: nSequence: %d\n", state->cur_input.prevout_nSequence);
    write_u32_le(tmp, 0, state->cur_input.prevout_nSequence);
    crypto_hash_update(&state->hash_context.header, tmp, 4);

    // hashOutputs
    PRINTF("SIGHASH: hashOutputs: ");
    for (int i = 0; i < 32; i++) PRINTF("%02X", state->subcontext.psbt_parse_rawtx.program_state.compute_sighash_segwit_v0.hashOutputs[i]);
    PRINTF("\n");
    crypto_hash_update(&state->hash_context.header,
                       state->subcontext.psbt_parse_rawtx.program_state.compute_sighash_segwit_v0.hashOutputs,
                       32);

    // nLocktime
    PRINTF("SIGHASH: nLocktime: %d\n", state->nLocktime);
    write_u32_le(tmp, 0, state->nLocktime);
    crypto_hash_update(&state->hash_context.header, tmp, 4);

    // sighash type
    PRINTF("SIGHASH: sighashtype: %d\n", state->cur_input.sighash_type);
    write_u32_le(tmp, 0, state->cur_input.sighash_type);
    crypto_hash_update(&state->hash_context.header, tmp, 4);

    uint8_t sighash[32];

    //compute sighash
    crypto_hash_digest(&state->hash_context.header, sighash, 32);
    cx_hash_sha256(sighash, 32, sighash, 32);

    // TODO: remove
    PRINTF("sighash: ");
    for (int i = 0; i < 32; i++)
        PRINTF("%02x", sighash[i]);
    PRINTF("\n");

    // TODO: actually sign input

    cx_ecfp_private_key_t private_key = {0};
    uint8_t chain_code[32] = {0};
    uint32_t info = 0;


    // TODO: should check the signing pubkey ant path matches in the PSBT
    // TODO: duplicated code with the legacy path
    uint32_t sign_path[MAX_BIP32_PATH_STEPS];
    for (unsigned int i = 0; i < state->our_key_info.master_key_derivation_len; i++) {
        sign_path[i] = state->our_key_info.master_key_derivation[i];
    }
    sign_path[state->our_key_info.master_key_derivation_len] = state->cur_input.change;
    sign_path[state->our_key_info.master_key_derivation_len + 1] = state->cur_input.address_index;

    // TODO: refactor the signing code elsewhere
    int sign_path_len = state->our_key_info.master_key_derivation_len + 2;

    PRINTF("Signing path for input %d: ", state->cur_input_index); // TODO: remove
    PRINTF_BIP32_PATH(sign_path, sign_path_len);

    crypto_derive_private_key(&private_key, chain_code, sign_path, sign_path_len);

    uint8_t sig[MAX_DER_SIG_LEN];

    int sig_len = 0;
    BEGIN_TRY {
        TRY {
            sig_len = cx_ecdsa_sign(&private_key,
                                    CX_RND_RFC6979,
                                    CX_SHA256,
                                    sighash,
                                    32,
                                    sig,
                                    MAX_DER_SIG_LEN,
                                    &info);
        }
        CATCH_OTHER(e) {
            return;
        }
        FINALLY {
            explicit_bzero(&private_key, sizeof(private_key));
        }
    }
    END_TRY;

    // TODO: send signture for this input
    PRINTF("######## signature for input %d: ", state->cur_input_index);
    for (int i = 0; i < sig_len; i++)
        PRINTF("%02x", sig[i]);
    PRINTF("\n");


    // yield signature
    uint8_t cmd = CCMD_YIELD;
    dc->add_to_response(&cmd, 1);
    uint8_t input_index = (uint8_t)state->cur_input_index;
    dc->add_to_response(&input_index, 1);
    dc->add_to_response(&sig, sig_len);
    uint8_t sighash_byte = (uint8_t)(state->cur_input.sighash_type & 0xFF);
    dc->add_to_response(&sighash_byte, 1);
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