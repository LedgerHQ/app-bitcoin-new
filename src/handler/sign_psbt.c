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

#include "lib_standard_app/crypto_helpers.h"

#include "../boilerplate/dispatcher.h"
#include "../boilerplate/sw.h"
#include "../common/bitvector.h"
#include "../common/merkle.h"
#include "../common/psbt.h"
#include "../common/read.h"
#include "../common/script.h"
#include "../common/varint.h"
#include "../common/wallet.h"
#include "../common/write.h"

#include "../commands.h"
#include "../constants.h"
#include "../crypto.h"
#include "../error_codes.h"
#include "../ui/display.h"
#include "../ui/menu.h"

#include "client_commands.h"

#include "lib/policy.h"
#include "lib/check_merkle_tree_sorted.h"
#include "lib/get_preimage.h"
#include "lib/get_merkleized_map.h"
#include "lib/get_merkleized_map_value.h"
#include "lib/get_merkle_leaf_element.h"
#include "lib/psbt_parse_rawtx.h"

#include "handlers.h"

#include "sign_psbt/sign_psbt_cache.h"
#include "sign_psbt/compare_wallet_script_at_path.h"
#include "sign_psbt/extract_bip32_derivation.h"
#include "sign_psbt/update_hashes_with_map_value.h"

#include "../swap/swap_globals.h"
#include "../swap/handle_swap_sign_transaction.h"
#include "../musig/musig.h"
#include "../musig/musig_sessions.h"

// common info that applies to either the current input or the current output
typedef struct {
    merkleized_map_commitment_t map;

    bool unexpected_pubkey_error;  // Set to true if the pubkey in the keydata of
                                   // PSBT_{IN,OUT}_BIP32_DERIVATION or
                                   // PSBT_{IN,OUT}_TAP_BIP32_DERIVATION is not the correct length.

    bool key_expression_found;  // Set to true if the input/output info in the psbt was correctly
                                // matched with the current key expression in the signing flow

    bool is_change;
    int address_index;

    // For an output, its scriptPubKey
    // for an input, the prevout's scriptPubKey (either from the non-witness-utxo, or from the
    // witness-utxo)

    uint8_t scriptPubKey[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
    size_t scriptPubKey_len;
} in_out_info_t;

typedef struct {
    in_out_info_t in_out;
    bool has_witnessUtxo;
    bool has_nonWitnessUtxo;
    bool has_redeemScript;
    bool has_sighash_type;

    uint64_t prevout_amount;  // the value of the prevout of the current input

    // we no longer need the script when we compute the taptree hash right before a taproot key-path
    // spending; therefore, we reuse the same memory
    union {
        // the script used when signing, either from the witness utxo or the redeem script
        uint8_t script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
        uint8_t taptree_hash[32];
    };

    size_t script_len;

    uint32_t sighash_type;
} input_info_t;

typedef struct {
    in_out_info_t in_out;
    uint64_t value;
} output_info_t;

typedef struct {
    policy_node_keyexpr_t *key_expression_ptr;
    int cur_index;
    uint32_t fingerprint;

    // info about the internal key of this key expression
    // used at signing time to derive the correct key
    uint32_t key_derivation[MAX_BIP32_PATH_STEPS];
    uint8_t key_derivation_length;

    // same as key_derivation_length for internal key
    // expressions; 0 for musig, as the key derivation in
    // the PSBT use the aggregate key as the root
    // used to identify the correct change/address_index from the psbt
    uint8_t psbt_root_key_derivation_length;

    // the root pubkey of this key expression
    serialized_extended_pubkey_t pubkey;
    // the pubkey of the internal key of this key expression.
    // same as `pubkey` for simple key expressions, but it's the actual
    // internal key for musig key expressions
    serialized_extended_pubkey_t internal_pubkey;

    bool is_tapscript;         // true if signing with a BIP342 tapleaf script path spend
    uint8_t tapleaf_hash[32];  // only used for tapscripts
} keyexpr_info_t;

// Cache for partial hashes during segwit signing (avoid quadratic hashing for segwit transactions)
typedef struct {
    uint8_t sha_prevouts[32];
    uint8_t sha_amounts[32];
    uint8_t sha_scriptpubkeys[32];
    uint8_t sha_sequences[32];
    uint8_t sha_outputs[32];
} segwit_hashes_t;

// We cache the first 2 external outputs; that's needed for the swap checks
// Moreover, this helps the code for the simplified UX for transactions that
// have a single external output.
#define N_CACHED_EXTERNAL_OUTPUTS 2

typedef struct {
    uint32_t master_key_fingerprint;
    uint32_t tx_version;
    uint32_t locktime;

    unsigned int n_inputs;
    uint8_t inputs_root[32];  // merkle root of the vector of input maps commitments
    unsigned int n_outputs;
    uint8_t outputs_root[32];  // merkle root of the vector of output maps commitments

    uint64_t inputs_total_amount;

    policy_map_wallet_header_t wallet_header;

    unsigned int n_external_inputs;
    unsigned int n_external_outputs;

    // aggregate info on outputs
    struct {
        uint64_t total_amount;         // amount of all the outputs (external + change)
        uint64_t change_total_amount;  // total amount of all change outputs
        int n_change;                  // count of outputs compatible with change outputs
        size_t output_script_lengths[N_CACHED_EXTERNAL_OUTPUTS];
        uint8_t output_scripts[N_CACHED_EXTERNAL_OUTPUTS][MAX_OUTPUT_SCRIPTPUBKEY_LEN];
        uint64_t output_amounts[N_CACHED_EXTERNAL_OUTPUTS];
    } outputs;

    bool is_wallet_default;

    uint8_t protocol_version;

    __attribute__((aligned(4))) uint8_t wallet_policy_map_bytes[MAX_WALLET_POLICY_BYTES];
    policy_node_t *wallet_policy_map;

    tx_ux_warning_t warnings;

} sign_psbt_state_t;

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
// Updates the hash_context with the output of given index
// returns -1 on error. 0 on success.
static int hash_output_n(dispatcher_context_t *dc,
                         sign_psbt_state_t *st,
                         cx_hash_t *hash_context,
                         unsigned int index) {
    if (index >= st->n_outputs) {
        return -1;
    }

    // get this output's map
    merkleized_map_commitment_t ith_map;

    int res = call_get_merkleized_map(dc, st->outputs_root, st->n_outputs, index, &ith_map);
    if (res < 0) {
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
        return -1;
    }

    crypto_hash_update(hash_context, amount_raw, 8);

    // get output's scriptPubKey

    uint8_t out_script[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
    int out_script_len = call_get_merkleized_map_value(dc,
                                                       &ith_map,
                                                       (uint8_t[]){PSBT_OUT_SCRIPT},
                                                       1,
                                                       out_script,
                                                       sizeof(out_script));
    if (out_script_len == -1) {
        return -1;
    }

    crypto_hash_update_varint(hash_context, out_script_len);
    crypto_hash_update(hash_context, out_script, out_script_len);
    return 0;
}

// Updates the hash_context with the network serialization of all the outputs
// returns -1 on error. 0 on success.
static int hash_outputs(dispatcher_context_t *dc, sign_psbt_state_t *st, cx_hash_t *hash_context) {
    for (unsigned int i = 0; i < st->n_outputs; i++) {
        if (hash_output_n(dc, st, hash_context, i)) {
            return -1;
        }
    }
    return 0;
}

/*
 Convenience function to get the amount and scriptpubkey from the non-witness-utxo of a certain
 input in a PSBTv2.
 If expected_prevout_hash is not NULL, the function fails if the txid computed from the
 non-witness-utxo does not match the one pointed by expected_prevout_hash. Returns -1 on failure, 0
 on success.
*/
static int __attribute__((noinline)) get_amount_scriptpubkey_from_psbt_nonwitness(
    dispatcher_context_t *dc,
    const merkleized_map_commitment_t *input_map,
    uint64_t *amount,
    uint8_t scriptPubKey[static MAX_PREVOUT_SCRIPTPUBKEY_LEN],
    size_t *scriptPubKey_len,
    const uint8_t *expected_prevout_hash) {
    // If there is no witness-utxo, it must be the case that this is a legacy input.
    // In this case, we can only retrieve the prevout amount and scriptPubKey by parsing
    // the non-witness-utxo

    // Read the prevout index
    uint32_t prevout_n;
    if (4 != call_get_merkleized_map_value_u32_le(dc,
                                                  input_map,
                                                  (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                                  1,
                                                  &prevout_n)) {
        return -1;
    }

    txid_parser_outputs_t parser_outputs;
    // request non-witness utxo, and get the prevout's value and scriptpubkey
    int res = call_psbt_parse_rawtx(dc,
                                    input_map,
                                    (uint8_t[]){PSBT_IN_NON_WITNESS_UTXO},
                                    1,
                                    prevout_n,
                                    &parser_outputs);
    if (res < 0) {
        PRINTF("Parsing rawtx failed\n");
        return -1;
    }

    // if expected_prevout_hash is given, check that it matches the txid obtained from the parser
    if (expected_prevout_hash != NULL &&
        memcmp(parser_outputs.txid, expected_prevout_hash, 32) != 0) {
        PRINTF("Prevout hash did not match non-witness-utxo transaction hash\n");

        return -1;
    }

    *amount = parser_outputs.vout_value;
    *scriptPubKey_len = parser_outputs.vout_scriptpubkey_len;
    memcpy(scriptPubKey, parser_outputs.vout_scriptpubkey, parser_outputs.vout_scriptpubkey_len);

    return 0;
}

/*
 Convenience function to get the amount and scriptpubkey from the witness-utxo of a certain input in
 a PSBTv2.
 Returns -1 on failure, 0 on success.
*/
static int __attribute__((noinline))
get_amount_scriptpubkey_from_psbt_witness(dispatcher_context_t *dc,
                                          const merkleized_map_commitment_t *input_map,
                                          uint64_t *amount,
                                          uint8_t scriptPubKey[static MAX_PREVOUT_SCRIPTPUBKEY_LEN],
                                          size_t *scriptPubKey_len) {
    uint8_t raw_witnessUtxo[8 + 1 + MAX_PREVOUT_SCRIPTPUBKEY_LEN];

    int wit_utxo_len = call_get_merkleized_map_value(dc,
                                                     input_map,
                                                     (uint8_t[]){PSBT_IN_WITNESS_UTXO},
                                                     1,
                                                     raw_witnessUtxo,
                                                     sizeof(raw_witnessUtxo));

    if (wit_utxo_len < 0) {
        return -1;
    }
    int wit_utxo_scriptPubkey_len = raw_witnessUtxo[8];

    if (wit_utxo_len != 8 + 1 + wit_utxo_scriptPubkey_len) {
        PRINTF("Length mismatch for witness utxo's scriptPubKey\n");
        return -1;
    }

    uint8_t *wit_utxo_scriptPubkey = raw_witnessUtxo + 9;
    uint64_t wit_utxo_prevout_amount = read_u64_le(&raw_witnessUtxo[0], 0);

    *amount = wit_utxo_prevout_amount;
    *scriptPubKey_len = wit_utxo_scriptPubkey_len;
    memcpy(scriptPubKey, wit_utxo_scriptPubkey, wit_utxo_scriptPubkey_len);
    return 0;
}

/*
 Convenience function to get the amount and scriptpubkey of a certain input in a PSBTv2.
 It first tries to obtain it from the witness-utxo field; in case of failure, it then obtains it
 from the non-witness-utxo.
 Returns -1 on failure, 0 on success.
*/
static int get_amount_scriptpubkey_from_psbt(
    dispatcher_context_t *dc,
    const merkleized_map_commitment_t *input_map,
    uint64_t *amount,
    uint8_t scriptPubKey[static MAX_PREVOUT_SCRIPTPUBKEY_LEN],
    size_t *scriptPubKey_len) {
    int ret = get_amount_scriptpubkey_from_psbt_witness(dc,
                                                        input_map,
                                                        amount,
                                                        scriptPubKey,
                                                        scriptPubKey_len);
    if (ret >= 0) {
        return ret;
    }

    return get_amount_scriptpubkey_from_psbt_nonwitness(dc,
                                                        input_map,
                                                        amount,
                                                        scriptPubKey,
                                                        scriptPubKey_len,
                                                        NULL);
}

// Convenience function to share common logic when processing all the
// PSBT_{IN|OUT}_{TAP}?_BIP32_DERIVATION fields.
static int read_change_and_index_from_psbt_bip32_derivation(
    dispatcher_context_t *dc,
    keyexpr_info_t *keyexpr_info,
    in_out_info_t *in_out,
    sign_psbt_cache_t *sign_psbt_cache,
    int psbt_key_type,
    buffer_t *data,
    const merkleized_map_commitment_t *map_commitment,
    int index) {
    uint8_t bip32_derivation_pubkey[33];

    bool is_tap = psbt_key_type == PSBT_IN_TAP_BIP32_DERIVATION ||
                  psbt_key_type == PSBT_OUT_TAP_BIP32_DERIVATION;
    int key_len = is_tap ? 32 : 33;

    if (!buffer_read_bytes(data,
                           bip32_derivation_pubkey,
                           key_len)  // read compressed pubkey or x-only pubkey
        || buffer_can_read(data, 1)  // ...but should not be able to read more
    ) {
        PRINTF("Unexpected pubkey length\n");
        in_out->unexpected_pubkey_error = true;
        return -1;
    }

    // get the corresponding value in the values Merkle tree,
    // then fetch the bip32 path from the field
    uint32_t fpt_der[1 + MAX_BIP32_PATH_STEPS];

    int der_len = extract_bip32_derivation(dc,
                                           psbt_key_type,
                                           map_commitment->values_root,
                                           map_commitment->size,
                                           index,
                                           fpt_der);
    if (der_len < 0) {
        PRINTF("Failed to read BIP32_DERIVATION\n");
        return -1;
    }

    if (der_len < 2 || der_len > MAX_BIP32_PATH_STEPS) {
        PRINTF("BIP32_DERIVATION path too long\n");
        return -1;
    }

    // if this derivation path matches the internal key expression,
    // we use it to detect whether the current input is change or not,
    // and store its address index
    if (fpt_der[0] == keyexpr_info->fingerprint &&
        der_len == keyexpr_info->psbt_root_key_derivation_length + 2) {
        for (int i = 0; i < keyexpr_info->psbt_root_key_derivation_length; i++) {
            if (keyexpr_info->key_derivation[i] != fpt_der[1 + i]) {
                return 0;
            }
        }

        uint32_t change_step = fpt_der[1 + der_len - 2];
        uint32_t addr_index = fpt_der[1 + der_len - 1];

        // check if the 'change' derivation step is indeed coherent with key expression
        if (change_step == keyexpr_info->key_expression_ptr->num_first) {
            in_out->is_change = false;
            in_out->address_index = addr_index;
        } else if (change_step == keyexpr_info->key_expression_ptr->num_second) {
            in_out->is_change = true;
            in_out->address_index = addr_index;
        } else {
            return 0;
        }

        // TODO: safe to remove this check? It should be, since we later re-derive
        //       the script independently.
        // // check that we can indeed derive the same key from the current key expression
        // serialized_extended_pubkey_t pubkey;
        // if (0 > derive_first_step_for_pubkey(&keyexpr_info->pubkey,
        //                                      keyexpr_info->key_expression_ptr,
        //                                      sign_psbt_cache,
        //                                      in_out->is_change,
        //                                      &pubkey))
        //     return -1;
        // if (0 > bip32_CKDpub(&pubkey, addr_index, &pubkey, NULL)) return -1;

        // int pk_offset = is_tap ? 1 : 0;
        // if (memcmp(pubkey.compressed_pubkey + pk_offset, bip32_derivation_pubkey, key_len) != 0)
        // {
        //     return 0;
        // }

        in_out->key_expression_found = true;
        return 1;
    }
    return 0;
}

/**
 * Verifies if a certain input/output is internal (that is, controlled by the wallet being used for
 * signing). This uses the state of sign_psbt and is not meant as a general-purpose function;
 * rather, it avoids some substantial code duplication and removes complexity from sign_psbt.
 *
 * @return 1 if the given input/output is internal; 0 if external; -1 on error.
 */
static int is_in_out_internal(dispatcher_context_t *dispatcher_context,
                              const sign_psbt_state_t *state,
                              sign_psbt_cache_t *sign_psbt_cache,
                              const in_out_info_t *in_out_info,
                              bool is_input) {
    // If we did not find any info about the pubkey associated to the key expression we're
    // considering, then it's external
    if (!in_out_info->key_expression_found) {
        return 0;
    }

    if (!is_input && in_out_info->is_change != 1) {
        // unlike for inputs, we only consider outputs internal if they are on the change path
        return 0;
    }

    return compare_wallet_script_at_path(dispatcher_context,
                                         sign_psbt_cache,
                                         in_out_info->is_change,
                                         in_out_info->address_index,
                                         state->wallet_policy_map,
                                         state->wallet_header.version,
                                         state->wallet_header.keys_info_merkle_root,
                                         state->wallet_header.n_keys,
                                         in_out_info->scriptPubKey,
                                         in_out_info->scriptPubKey_len);
}

static bool __attribute__((noinline))
init_global_state(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    merkleized_map_commitment_t global_map;
    if (!buffer_read_varint(&dc->read_buffer, &global_map.size)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return false;
    }

    if (!buffer_read_bytes(&dc->read_buffer, global_map.keys_root, 32) ||
        !buffer_read_bytes(&dc->read_buffer, global_map.values_root, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return false;
    }

    // we already know n_inputs and n_outputs, so we skip reading from the global map

    uint64_t n_inputs_u64;
    if (!buffer_read_varint(&dc->read_buffer, &n_inputs_u64) ||
        !buffer_read_bytes(&dc->read_buffer, st->inputs_root, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return false;
    }

    if (n_inputs_u64 > MAX_N_INPUTS_CAN_SIGN) {
        PRINTF("At most %d inputs are supported\n", MAX_N_INPUTS_CAN_SIGN);
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return false;
    }
    st->n_inputs = (unsigned int) n_inputs_u64;

    uint64_t n_outputs_u64;
    if (!buffer_read_varint(&dc->read_buffer, &n_outputs_u64) ||
        !buffer_read_bytes(&dc->read_buffer, st->outputs_root, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return false;
    }
    st->n_outputs = (unsigned int) n_outputs_u64;

    uint8_t wallet_hmac[32];
    uint8_t wallet_id[32];
    if (!buffer_read_bytes(&dc->read_buffer, wallet_id, 32) ||
        !buffer_read_bytes(&dc->read_buffer, wallet_hmac, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return false;
    }

    {  // process global map
        // Check integrity of the global map
        if (call_check_merkle_tree_sorted(dc, global_map.keys_root, (size_t) global_map.size) < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t raw_result[9];  // max size for a varint
        int result_len;

        // Read tx version
        result_len = call_get_merkleized_map_value(dc,
                                                   &global_map,
                                                   (uint8_t[]){PSBT_GLOBAL_TX_VERSION},
                                                   1,
                                                   raw_result,
                                                   sizeof(raw_result));
        if (result_len != 4) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        st->tx_version = read_u32_le(raw_result, 0);

        // Read fallback locktime.
        // Unlike BIP-0370 recommendation, we use the fallback locktime as-is, ignoring each input's
        // preferred height/block locktime. If that's relevant, the client must set the fallback
        // locktime to the appropriate value before calling sign_psbt.
        result_len = call_get_merkleized_map_value(dc,
                                                   &global_map,
                                                   (uint8_t[]){PSBT_GLOBAL_FALLBACK_LOCKTIME},
                                                   1,
                                                   raw_result,
                                                   sizeof(raw_result));
        if (result_len == -1) {
            st->locktime = 0;
        } else if (result_len != 4) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        } else {
            st->locktime = read_u32_le(raw_result, 0);
        }
    }

    uint8_t hmac_or =
        0;  // the binary OR of all the hmac bytes (so == 0 iff the hmac is identically 0)
    for (int i = 0; i < 32; i++) {
        hmac_or = hmac_or | wallet_hmac[i];
    }

    if (hmac_or != 0) {
        // Verify hmac
        if (!check_wallet_hmac(wallet_id, wallet_hmac)) {
            PRINTF("Incorrect hmac\n");
            SEND_SW(dc, SW_SIGNATURE_FAIL);
            return false;
        }

        st->is_wallet_default = false;
    } else {
        st->is_wallet_default = true;
    }

    {
        // Fetch the serialized wallet policy from the client
        uint8_t serialized_wallet_policy[MAX_WALLET_POLICY_SERIALIZED_LENGTH];
        int serialized_wallet_policy_len = call_get_preimage(dc,
                                                             wallet_id,
                                                             serialized_wallet_policy,
                                                             sizeof(serialized_wallet_policy));
        if (serialized_wallet_policy_len < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        buffer_t serialized_wallet_policy_buf =
            buffer_create(serialized_wallet_policy, serialized_wallet_policy_len);

        uint8_t policy_map_descriptor[MAX_DESCRIPTOR_TEMPLATE_LENGTH];

        int desc_temp_len = read_and_parse_wallet_policy(dc,
                                                         &serialized_wallet_policy_buf,
                                                         &st->wallet_header,
                                                         policy_map_descriptor,
                                                         st->wallet_policy_map_bytes,
                                                         MAX_WALLET_POLICY_BYTES);
        if (desc_temp_len < 0) {
            PRINTF("Failed to read or parse wallet policy");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        st->wallet_policy_map = (policy_node_t *) st->wallet_policy_map_bytes;

        if (st->is_wallet_default) {
            // No hmac, verify that the policy is indeed a default one
            if (!is_wallet_policy_standard(dc, &st->wallet_header, st->wallet_policy_map)) {
                PRINTF("Non-standard policy, and no hmac provided\n");
                SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_MISSING_HMAC_FOR_NONDEFAULT_POLICY);
                return false;
            }

            if (st->wallet_header.name_len != 0) {
                PRINTF("Name must be zero-length for a standard wallet policy\n");
                SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_NO_NAME_FOR_DEFAULT_POLICY);
                return false;
            }

            // unlike in get_wallet_address, we do not check if the address_index is small:
            // if funds were already sent there, there is no point in preventing to spend them.
        }
    }

    st->master_key_fingerprint = crypto_get_master_key_fingerprint();
    return true;
}

static bool __attribute__((noinline)) get_and_verify_key_info(dispatcher_context_t *dc,
                                                              sign_psbt_state_t *st,
                                                              uint16_t key_index,
                                                              keyexpr_info_t *keyexpr_info) {
    policy_map_key_info_t key_info;
    uint8_t key_info_str[MAX_POLICY_KEY_INFO_LEN];

    int key_info_len = call_get_merkle_leaf_element(dc,
                                                    st->wallet_header.keys_info_merkle_root,
                                                    st->wallet_header.n_keys,
                                                    key_index,
                                                    key_info_str,
                                                    sizeof(key_info_str));
    if (key_info_len < 0) {
        return false;  // should never happen
    }

    // Make a sub-buffer for the pubkey info
    buffer_t key_info_buffer = buffer_create(key_info_str, key_info_len);

    if (parse_policy_map_key_info(&key_info_buffer, &key_info, st->wallet_header.version) == -1) {
        return false;  // should never happen
    }

    keyexpr_info->key_derivation_length = key_info.master_key_derivation_len;
    for (int i = 0; i < key_info.master_key_derivation_len; i++) {
        keyexpr_info->key_derivation[i] = key_info.master_key_derivation[i];
    }

    keyexpr_info->fingerprint = read_u32_be(key_info.master_key_fingerprint, 0);

    memcpy(&keyexpr_info->pubkey, &key_info.ext_pubkey, sizeof(serialized_extended_pubkey_t));

    // the rest of the function verifies if the key is indeed internal, if it has our fingerprint
    uint32_t fpr = read_u32_be(key_info.master_key_fingerprint, 0);
    if (fpr != st->master_key_fingerprint) {
        return false;
    }

    // it could be a collision on the fingerprint; we verify that we can actually generate
    // the same pubkey
    serialized_extended_pubkey_t derived_pubkey;
    if (0 > get_extended_pubkey_at_path(key_info.master_key_derivation,
                                        key_info.master_key_derivation_len,
                                        BIP32_PUBKEY_VERSION,
                                        &derived_pubkey)) {
        return false;
    }

    if (memcmp(&key_info.ext_pubkey, &derived_pubkey, sizeof(derived_pubkey)) != 0) {
        return false;
    }

    return true;
}

static bool fill_keyexpr_info_if_internal(dispatcher_context_t *dc,
                                          sign_psbt_state_t *st,
                                          keyexpr_info_t *keyexpr_info) {
    keyexpr_info_t tmp_keyexpr_info;
    // preserve the fields that are already computed outside of this function
    memcpy(&tmp_keyexpr_info, keyexpr_info, sizeof(keyexpr_info_t));

    if (keyexpr_info->key_expression_ptr->type == KEY_EXPRESSION_NORMAL) {
        bool result = get_and_verify_key_info(dc,
                                              st,
                                              keyexpr_info->key_expression_ptr->k.key_index,
                                              &tmp_keyexpr_info);
        if (result) {
            memcpy(keyexpr_info, &tmp_keyexpr_info, sizeof(keyexpr_info_t));
            memcpy(&keyexpr_info->internal_pubkey,
                   &keyexpr_info->pubkey,
                   sizeof(serialized_extended_pubkey_t));
            keyexpr_info->psbt_root_key_derivation_length = keyexpr_info->key_derivation_length;
        }
        return result;
    } else if (keyexpr_info->key_expression_ptr->type == KEY_EXPRESSION_MUSIG) {
        // iterate through the keys of the musig() placeholder to find if a key is internal
        musig_aggr_key_info_t *musig_info =
            r_musig_aggr_key_info(&keyexpr_info->key_expression_ptr->m.musig_info);
        uint16_t *key_indexes = r_uint16(&musig_info->key_indexes);

        bool has_internal_key = false;

        // collect the keys of the musig, and fill the info related to the internal key (if any)
        uint8_t keys[MAX_PUBKEYS_PER_MUSIG][33];
        for (int idx_in_musig = 0; idx_in_musig < musig_info->n; idx_in_musig++) {
            if (get_and_verify_key_info(dc, st, key_indexes[idx_in_musig], &tmp_keyexpr_info)) {
                memcpy(keyexpr_info->key_derivation,
                       tmp_keyexpr_info.key_derivation,
                       sizeof(tmp_keyexpr_info.key_derivation));
                keyexpr_info->key_derivation_length = tmp_keyexpr_info.key_derivation_length;

                // keep track of the actual internal key of this key expression
                memcpy(&keyexpr_info->internal_pubkey,
                       &tmp_keyexpr_info.pubkey,
                       sizeof(serialized_extended_pubkey_t));

                has_internal_key = true;
            }

            memcpy(keys[idx_in_musig], tmp_keyexpr_info.pubkey.compressed_pubkey, 33);
        }

        if (has_internal_key) {
            keyexpr_info->psbt_root_key_derivation_length = 0;

            // sort the keys in ascending order using bubble sort
            for (int i = 0; i < musig_info->n; i++) {
                for (int j = 0; j < musig_info->n - 1; j++) {
                    if (memcmp(keys[j], keys[j + 1], sizeof(plain_pk_t)) > 0) {
                        uint8_t tmp[sizeof(plain_pk_t)];
                        memcpy(tmp, keys[j], sizeof(plain_pk_t));
                        memcpy(keys[j], keys[j + 1], sizeof(plain_pk_t));
                        memcpy(keys[j + 1], tmp, sizeof(plain_pk_t));
                    }
                }
            }

            musig_keyagg_context_t musig_ctx;
            musig_key_agg(keys, musig_info->n, &musig_ctx);

            // compute the aggregated extended pubkey
            memset(&keyexpr_info->pubkey, 0, sizeof(keyexpr_info->pubkey));
            write_u32_be(keyexpr_info->pubkey.version, 0, BIP32_PUBKEY_VERSION);

            keyexpr_info->pubkey.compressed_pubkey[0] = (musig_ctx.Q.y[31] % 2 == 0) ? 2 : 3;
            memcpy(&keyexpr_info->pubkey.compressed_pubkey[1],
                   musig_ctx.Q.x,
                   sizeof(musig_ctx.Q.x));
            memcpy(&keyexpr_info->pubkey.chain_code,
                   BIP_MUSIG_CHAINCODE,
                   sizeof(BIP_MUSIG_CHAINCODE));

            keyexpr_info->fingerprint =
                crypto_get_key_fingerprint(keyexpr_info->pubkey.compressed_pubkey);
        }

        return has_internal_key;  // no internal key found in musig placeholder
    } else {
        LEDGER_ASSERT(false, "Unreachable code");
        return false;
    }
}

// finds the first key expression that corresponds to an internal key
static bool find_first_internal_keyexpr(dispatcher_context_t *dc,
                                        sign_psbt_state_t *st,
                                        keyexpr_info_t *keyexpr_info) {
    keyexpr_info->cur_index = 0;

    // find and parse our registered key info in the wallet
    while (true) {
        int n_key_expressions = get_keyexpr_by_index(st->wallet_policy_map,
                                                     keyexpr_info->cur_index,
                                                     NULL,
                                                     &keyexpr_info->key_expression_ptr);
        if (n_key_expressions < 0) {
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            return false;
        }

        if (keyexpr_info->cur_index >= n_key_expressions) {
            // all keys have been processed
            break;
        }

        if (fill_keyexpr_info_if_internal(dc, st, keyexpr_info)) {
            return true;
        }

        // Not an internal key, move on
        ++keyexpr_info->cur_index;
    }

    PRINTF("No internal key found in wallet policy");
    SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_WALLET_POLICY_HAS_NO_INTERNAL_KEY);
    return false;
}

typedef struct {
    keyexpr_info_t *keyexpr_info;
    input_info_t *input;
    sign_psbt_cache_t *sign_psbt_cache;
} input_keys_callback_data_t;

/**
 * Callback to process all the keys of the current input map.
 * Keeps track if the current input has a witness_utxo and/or a redeemScript.
 */
static void input_keys_callback(dispatcher_context_t *dc,
                                input_keys_callback_data_t *callback_data,
                                const merkleized_map_commitment_t *map_commitment,
                                int i,
                                buffer_t *data) {
    size_t data_len = data->size - data->offset;
    if (data_len >= 1) {
        uint8_t key_type;
        buffer_read_u8(data, &key_type);
        if (key_type == PSBT_IN_WITNESS_UTXO) {
            callback_data->input->has_witnessUtxo = true;
        } else if (key_type == PSBT_IN_NON_WITNESS_UTXO) {
            callback_data->input->has_nonWitnessUtxo = true;
        } else if (key_type == PSBT_IN_REDEEM_SCRIPT) {
            callback_data->input->has_redeemScript = true;
        } else if (key_type == PSBT_IN_SIGHASH_TYPE) {
            callback_data->input->has_sighash_type = true;
        } else if ((key_type == PSBT_IN_BIP32_DERIVATION ||
                    key_type == PSBT_IN_TAP_BIP32_DERIVATION) &&
                   !callback_data->input->in_out.key_expression_found) {
            if (0 > read_change_and_index_from_psbt_bip32_derivation(dc,
                                                                     callback_data->keyexpr_info,
                                                                     &callback_data->input->in_out,
                                                                     callback_data->sign_psbt_cache,
                                                                     key_type,
                                                                     data,
                                                                     map_commitment,
                                                                     i)) {
                callback_data->input->in_out.unexpected_pubkey_error = true;
            }
        }
    }
}

static bool __attribute__((noinline))
preprocess_inputs(dispatcher_context_t *dc,
                  sign_psbt_state_t *st,
                  sign_psbt_cache_t *sign_psbt_cache,
                  uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    memset(internal_inputs, 0, BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN));

    keyexpr_info_t keyexpr_info;
    memset(&keyexpr_info, 0, sizeof(keyexpr_info));

    if (!find_first_internal_keyexpr(dc, st, &keyexpr_info)) return false;

    // process each input
    for (unsigned int cur_input_index = 0; cur_input_index < st->n_inputs; cur_input_index++) {
        input_info_t input;
        memset(&input, 0, sizeof(input));

        input_keys_callback_data_t callback_data = {.input = &input,
                                                    .keyexpr_info = &keyexpr_info,
                                                    .sign_psbt_cache = sign_psbt_cache};
        int res = call_get_merkleized_map_with_callback(
            dc,
            (void *) &callback_data,
            st->inputs_root,
            st->n_inputs,
            cur_input_index,
            (merkle_tree_elements_callback_t) input_keys_callback,
            &input.in_out.map);
        if (res < 0) {
            PRINTF("Failed to process input map\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        if (input.in_out.unexpected_pubkey_error) {
            PRINTF("Unexpected pubkey length\n");  // only compressed pubkeys are supported
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        // either witness utxo or non-witness utxo (or both) must be present.
        if (!input.has_nonWitnessUtxo && !input.has_witnessUtxo) {
            PRINTF("No witness utxo nor non-witness utxo present in input.\n");
            SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_MISSING_NONWITNESSUTXO_AND_WITNESSUTXO);
            return false;
        }

        // validate non-witness utxo (if present) and witness utxo (if present)

        if (input.has_nonWitnessUtxo) {
            uint8_t prevout_hash[32];

            // check if the prevout_hash of the transaction matches the computed one from the
            // non-witness utxo
            if (0 > call_get_merkleized_map_value(dc,
                                                  &input.in_out.map,
                                                  (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                  1,
                                                  prevout_hash,
                                                  sizeof(prevout_hash))) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            // request non-witness utxo, and get the prevout's value and scriptpubkey
            // Also checks that the recomputed transaction hash matches with prevout_hash.
            if (0 > get_amount_scriptpubkey_from_psbt_nonwitness(dc,
                                                                 &input.in_out.map,
                                                                 &input.prevout_amount,
                                                                 input.in_out.scriptPubKey,
                                                                 &input.in_out.scriptPubKey_len,
                                                                 prevout_hash)) {
                SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_NONWITNESSUTXO_CHECK_FAILED);
                return false;
            }

            st->inputs_total_amount += input.prevout_amount;
        }

        if (input.has_witnessUtxo) {
            size_t wit_utxo_scriptPubkey_len;
            uint8_t wit_utxo_scriptPubkey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
            uint64_t wit_utxo_prevout_amount;

            if (0 > get_amount_scriptpubkey_from_psbt_witness(dc,
                                                              &input.in_out.map,
                                                              &wit_utxo_prevout_amount,
                                                              wit_utxo_scriptPubkey,
                                                              &wit_utxo_scriptPubkey_len)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            };

            if (input.has_nonWitnessUtxo) {
                // we already know the scriptPubKey, but we double check that it matches
                if (input.in_out.scriptPubKey_len != wit_utxo_scriptPubkey_len ||
                    memcmp(input.in_out.scriptPubKey,
                           wit_utxo_scriptPubkey,
                           wit_utxo_scriptPubkey_len) != 0 ||
                    input.prevout_amount != wit_utxo_prevout_amount) {
                    PRINTF(
                        "scriptPubKey or amount in non-witness utxo doesn't match with witness "
                        "utxo\n");
                    SEND_SW_EC(dc,
                               SW_INCORRECT_DATA,
                               EC_SIGN_PSBT_NONWITNESSUTXO_AND_WITNESSUTXO_MISMATCH);
                    return false;
                }
            } else {
                // we extract the scriptPubKey and prevout amount from the witness utxo
                st->inputs_total_amount += wit_utxo_prevout_amount;

                input.prevout_amount = wit_utxo_prevout_amount;
                input.in_out.scriptPubKey_len = wit_utxo_scriptPubkey_len;
                memcpy(input.in_out.scriptPubKey, wit_utxo_scriptPubkey, wit_utxo_scriptPubkey_len);
            }
        }

        // check if the input is internal; if not, continue

        int is_internal = is_in_out_internal(dc, st, sign_psbt_cache, &input.in_out, true);
        if (is_internal < 0) {
            PRINTF("Error checking if input %d is internal\n", cur_input_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        } else if (is_internal == 0) {
            ++st->n_external_inputs;

            PRINTF("INPUT %d is external\n", cur_input_index);
            continue;
        }

        bitvector_set(internal_inputs, cur_input_index, 1);

        int segwit_version = get_policy_segwit_version(st->wallet_policy_map);

        // For legacy inputs, the non-witness utxo must be present
        // and the witness utxo must be absent.
        // (This assumption is later relied on when signing).
        if (segwit_version == -1) {
            if (!input.has_nonWitnessUtxo || input.has_witnessUtxo) {
                PRINTF("Legacy inputs must have the non-witness utxo, but no witness utxo.\n");
                SEND_SW_EC(
                    dc,
                    SW_INCORRECT_DATA,
                    EC_SIGN_PSBT_MISSING_NONWITNESSUTXO_OR_UNEXPECTED_WITNESSUTXO_FOR_LEGACY);
                return false;
            }
        }

        // For segwitv0 inputs, the non-witness utxo _should_ be present; we show a warning
        // to the user otherwise, but we continue nonetheless on approval
        if (segwit_version == 0 && !input.has_nonWitnessUtxo) {
            PRINTF("Non-witness utxo missing for segwitv0 input. Will show a warning.\n");
            st->warnings.missing_nonwitnessutxo = true;
        }

        // For all segwit transactions, the witness utxo must be present
        if (segwit_version >= 0 && !input.has_witnessUtxo) {
            PRINTF("Witness utxo missing for segwit input\n");
            SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_MISSING_WITNESSUTXO_FOR_SEGWIT);
            return false;
        }

        // If any of the internal inputs has a sighash type that is not SIGHASH_DEFAULT or
        // SIGHASH_ALL, we show a warning

        if (!input.has_sighash_type) {
            continue;
        }

        // get the sighash_type
        if (4 != call_get_merkleized_map_value_u32_le(dc,
                                                      &input.in_out.map,
                                                      (uint8_t[]){PSBT_IN_SIGHASH_TYPE},
                                                      1,
                                                      &input.sighash_type)) {
            PRINTF("Malformed PSBT_IN_SIGHASH_TYPE for input %d\n", cur_input_index);

            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        if (((segwit_version > 0) && (input.sighash_type == SIGHASH_DEFAULT)) ||
            (input.sighash_type == SIGHASH_ALL)) {
            PRINTF("Sighash type is SIGHASH_DEFAULT or SIGHASH_ALL\n");

        } else if ((segwit_version >= 0) &&
                   ((input.sighash_type == SIGHASH_NONE) ||
                    (input.sighash_type == SIGHASH_SINGLE) ||
                    (input.sighash_type == (SIGHASH_ANYONECANPAY | SIGHASH_ALL)) ||
                    (input.sighash_type == (SIGHASH_ANYONECANPAY | SIGHASH_NONE)) ||
                    (input.sighash_type == (SIGHASH_ANYONECANPAY | SIGHASH_SINGLE)))) {
            PRINTF("Sighash type is non-default, will show a warning.\n");
            st->warnings.non_default_sighash = true;
        } else {
            PRINTF("Unsupported sighash\n");
            SEND_SW(dc, SW_NOT_SUPPORTED);
            return false;
        }

        if (((input.sighash_type & SIGHASH_SINGLE) == SIGHASH_SINGLE) &&
            (cur_input_index >= st->n_outputs)) {
            PRINTF("SIGHASH_SINGLE with input idx >= n_output is not allowed \n");
            SEND_SW_EC(dc, SW_NOT_SUPPORTED, EC_SIGN_PSBT_UNALLOWED_SIGHASH_SINGLE);
            return false;
        }
    }

    if (st->n_external_inputs == st->n_inputs) {
        // no internal inputs, nothing to sign
        PRINTF("No internal inputs. Aborting\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    return true;
}

typedef struct {
    keyexpr_info_t *keyexpr_info;
    output_info_t *output;
    sign_psbt_cache_t *sign_psbt_cache;
} output_keys_callback_data_t;

/**
 * Callback to process all the keys of the current input map.
 * Keeps track if the current input has a witness_utxo and/or a redeemScript.
 */
static void output_keys_callback(dispatcher_context_t *dc,
                                 output_keys_callback_data_t *callback_data,
                                 const merkleized_map_commitment_t *map_commitment,
                                 int i,
                                 buffer_t *data) {
    size_t data_len = data->size - data->offset;
    if (data_len >= 1) {
        uint8_t key_type;
        buffer_read_u8(data, &key_type);

        if ((key_type == PSBT_OUT_BIP32_DERIVATION || key_type == PSBT_OUT_TAP_BIP32_DERIVATION) &&
            !callback_data->output->in_out.key_expression_found) {
            if (0 > read_change_and_index_from_psbt_bip32_derivation(dc,
                                                                     callback_data->keyexpr_info,
                                                                     &callback_data->output->in_out,
                                                                     callback_data->sign_psbt_cache,
                                                                     key_type,
                                                                     data,
                                                                     map_commitment,
                                                                     i)) {
                callback_data->output->in_out.unexpected_pubkey_error = true;
            }
        }
    }
}

static bool __attribute__((noinline))
preprocess_outputs(dispatcher_context_t *dc,
                   sign_psbt_state_t *st,
                   sign_psbt_cache_t *sign_psbt_cache,
                   uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]) {
    /** OUTPUTS VERIFICATION FLOW
     *
     *  For each output, check if it's internal (that is, a change address).
     *  Also computes the total amount of change outputs, and the total of all outputs.
     */

    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    keyexpr_info_t keyexpr_info;
    memset(&keyexpr_info, 0, sizeof(keyexpr_info));

    if (!find_first_internal_keyexpr(dc, st, &keyexpr_info)) return false;

    memset(&st->outputs, 0, sizeof(st->outputs));

    // the counter used when showing outputs to the user, which ignores change outputs
    // (0-indexed here, although the UX starts with 1)
    int external_outputs_count = 0;

    for (unsigned int cur_output_index = 0; cur_output_index < st->n_outputs; cur_output_index++) {
        output_info_t output;
        memset(&output, 0, sizeof(output));

        output_keys_callback_data_t callback_data = {.output = &output,
                                                     .keyexpr_info = &keyexpr_info,
                                                     .sign_psbt_cache = sign_psbt_cache};
        int res = call_get_merkleized_map_with_callback(
            dc,
            (void *) &callback_data,
            st->outputs_root,
            st->n_outputs,
            cur_output_index,
            (merkle_tree_elements_callback_t) output_keys_callback,
            &output.in_out.map);

        if (res < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        if (output.in_out.unexpected_pubkey_error) {
            PRINTF("Unexpected pubkey length\n");  // only compressed pubkeys are supported
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        // Read output amount
        uint8_t raw_result[8];

        // Read the output's amount
        int result_len = call_get_merkleized_map_value(dc,
                                                       &output.in_out.map,
                                                       (uint8_t[]){PSBT_OUT_AMOUNT},
                                                       1,
                                                       raw_result,
                                                       sizeof(raw_result));
        if (result_len != 8) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint64_t value = read_u64_le(raw_result, 0);

        output.value = value;
        st->outputs.total_amount += value;

        // Read the output's scriptPubKey
        result_len = call_get_merkleized_map_value(dc,
                                                   &output.in_out.map,
                                                   (uint8_t[]){PSBT_OUT_SCRIPT},
                                                   1,
                                                   output.in_out.scriptPubKey,
                                                   sizeof(output.in_out.scriptPubKey));

        if (result_len == -1 || result_len > (int) sizeof(output.in_out.scriptPubKey)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        output.in_out.scriptPubKey_len = result_len;

        int is_internal = is_in_out_internal(dc, st, sign_psbt_cache, &output.in_out, false);

        if (is_internal < 0) {
            PRINTF("Error checking if output %d is internal\n", cur_output_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        } else if (is_internal == 0) {
            // external output, user needs to validate
            bitvector_set(internal_outputs, cur_output_index, 0);

            // cache external output scripts
            if (external_outputs_count < N_CACHED_EXTERNAL_OUTPUTS) {
                st->outputs.output_script_lengths[external_outputs_count] =
                    output.in_out.scriptPubKey_len;
                memcpy(st->outputs.output_scripts[external_outputs_count],
                       output.in_out.scriptPubKey,
                       output.in_out.scriptPubKey_len);
                st->outputs.output_amounts[external_outputs_count] = value;
            }

            ++external_outputs_count;
        } else {
            // valid change address, nothing to show to the user

            bitvector_set(internal_outputs, cur_output_index, 1);

            st->outputs.change_total_amount += output.value;
            ++st->outputs.n_change;
        }
    }

    st->n_external_outputs = external_outputs_count;

    if (st->inputs_total_amount < st->outputs.total_amount) {
        PRINTF("Negative fee is invalid\n");
        // negative fee transaction is invalid
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    if (st->outputs.n_change > 10) {
        // As the information regarding change outputs is aggregated, we want to prevent the user
        // from unknowingly signing a transaction that sends the change to too many outputs
        // (possibly economically not worth spending).
        PRINTF("Too many change outputs: %d\n", st->outputs.n_change);
        SEND_SW_EC(dc, SW_NOT_SUPPORTED, EC_SIGN_PSBT_TOO_MANY_CHANGE_OUTPUTS);
        return false;
    }

    return true;
}

static bool __attribute__((noinline))
execute_swap_checks(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // Swap feature: check that wallet policy is a default one
    if (!st->is_wallet_default) {
        PRINTF("Must be a default wallet policy for swap feature\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_METHOD_NONDEFAULT_POLICY);
        finalize_exchange_sign_transaction(false);
    }

    // No external inputs allowed
    if (st->n_external_inputs > 0) {
        PRINTF("External inputs not allowed in swap transactions\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_METHOD_EXTERNAL_INPUTS);
        finalize_exchange_sign_transaction(false);
    }

    if (st->warnings.missing_nonwitnessutxo || st->warnings.non_default_sighash) {
        // Do not allow transactions with missing non-witness utxos or non-default sighash flags
        PRINTF(
            "Missing non-witness utxo or non-default sighash flags are not allowed during swaps\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_METHOD_MISSING_NONWITNESSUTXO);
        finalize_exchange_sign_transaction(false);
    }

    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;

    // The index of the swap destination address in the cache of external outputs.
    // NB: this is _not_ the output index in the transaction, as change outputs are skipped.
    int swap_dest_idx = -1;

    if (G_swap_state.mode == SWAP_MODE_STANDARD) {
        swap_dest_idx = 0;

        // There must be only one external output
        if (st->n_external_outputs != 1) {
            PRINTF("Standard swap transaction must have exactly 1 external output\n");
            SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_METHOD_WRONG_N_OF_OUTPUTS);
            finalize_exchange_sign_transaction(false);
        }
    } else if (G_swap_state.mode == SWAP_MODE_CROSSCHAIN) {
        // There must be exactly 2 external outputs; the first is the OP_RETURN

        swap_dest_idx = 1;

        if (st->n_external_outputs != 2) {
            PRINTF("Cross-chain swap transaction must have exactly 2 external outputs\n");
            SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_METHOD_WRONG_N_OF_OUTPUTS);
            finalize_exchange_sign_transaction(false);
        }

        uint8_t *opreturn_script = st->outputs.output_scripts[0];
        size_t opreturn_script_len = st->outputs.output_script_lengths[0];
        size_t opreturn_amount = st->outputs.output_amounts[0];
        if (opreturn_script_len < 4 || opreturn_script[0] != OP_RETURN) {
            PRINTF("The first output must be OP_RETURN <data> for a cross-chain swap\n");
            SEND_SW_EC(dc,
                       SW_FAIL_SWAP,
                       EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD_INVALID_FIRST_OUTPUT);
            finalize_exchange_sign_transaction(false);
        }

        uint8_t second_byte = opreturn_script[1];
        size_t push_opcode_size;  // the length of the push opcode (1 or 2 bytes)
        size_t data_size;         // the length of the actual data embedded in the OP_RETURN output
        if (2 <= second_byte && second_byte <= 75) {
            push_opcode_size = 1;
            data_size = second_byte;
        } else if (second_byte == OP_PUSHDATA1) {
            // pushing more than 75 bytes requires using OP_PUSHDATA1 <len>
            // insted of a single-byte opcode
            push_opcode_size = 2;
            data_size = opreturn_script[2];
        } else {
            // there are other valid OP_RETURN Scripts that we never expect here,
            // so we don't bother parsing.
            PRINTF("Unsupported or invalid OP_RETURN Script in cross-chain swap\n");
            SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD);
            finalize_exchange_sign_transaction(false);
        }

        // Make sure there is a singla data push
        if (opreturn_script_len != 1 + push_opcode_size + data_size) {
            PRINTF("Invalid OP_RETURN Script length in cross-chain swap\n");
            SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD);
            finalize_exchange_sign_transaction(false);
        }

        // Make sure the output's value is 0
        if (opreturn_amount != 0) {
            PRINTF("OP_RETURN with non-zero value during cross-chain swap\n");
            SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD_NONZERO_AMOUNT);
            finalize_exchange_sign_transaction(false);
        }

        // verify the hash in the data payload is the expected one
        uint8_t expected_payin_hash[32];
        cx_hash_sha256(&opreturn_script[1 + push_opcode_size], data_size, expected_payin_hash, 32);
        if (memcmp(G_swap_state.payin_extra_id + 1,
                   expected_payin_hash,
                   sizeof(expected_payin_hash)) != 0) {
            PRINTF("Mismatching payin hash in cross-chain swap\n");
            SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_CROSSCHAIN_WRONG_HASH);
            finalize_exchange_sign_transaction(false);
        }
    } else if (G_swap_state.mode == SWAP_MODE_ERROR) {
        // an error was detected in handle_swap_sign_transaction.c::copy_transaction_parameters
        // special case only to improve error reporting in debug mode
        PRINTF("Invalid parameters for swap feature\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_GENERIC_COPY_TRANSACTION_PARAMETERS_FAILED);
        finalize_exchange_sign_transaction(false);
    } else {
        PRINTF("Unknown swap mode: %d\n", G_swap_state.mode);
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_GENERIC_UNKNOWN_MODE);
        finalize_exchange_sign_transaction(false);
    }

    LEDGER_ASSERT(0 <= swap_dest_idx && swap_dest_idx < N_CACHED_EXTERNAL_OUTPUTS,
                  "External output index out of range for swap\n");

    // Check that total amount and fees are as expected
    if (fee != G_swap_state.fees) {
        PRINTF("Mismatching fee for swap\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_FEES);
        finalize_exchange_sign_transaction(false);
    }

    uint64_t spent_amount = st->outputs.total_amount - st->outputs.change_total_amount;
    if (spent_amount != G_swap_state.amount) {
        PRINTF("Mismatching spent amount for swap\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_AMOUNT);
        finalize_exchange_sign_transaction(false);
    }

    // Compute this output's address
    char output_description[MAX_OUTPUT_SCRIPT_DESC_SIZE];

    if (!format_script(st->outputs.output_scripts[swap_dest_idx],
                       st->outputs.output_script_lengths[swap_dest_idx],
                       output_description)) {
        PRINTF("Invalid or unsupported script for external output\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_METHOD_WRONG_UNSUPPORTED_OUTPUT);
        finalize_exchange_sign_transaction(false);
    }

    char output_description_len = strlen(output_description);

    // Check that the external output's address matches the request from app-exchange
    int swap_addr_len = strlen(G_swap_state.destination_address);
    if (swap_addr_len != output_description_len ||
        0 !=
            strncmp(G_swap_state.destination_address, output_description, output_description_len)) {
        // address did not match
        PRINTF("Mismatching address for swap\n");
        PRINTF("Expected: ");
        for (int i = 0; i < swap_addr_len; i++) {
            PRINTF("%c", G_swap_state.destination_address[i]);
        }
        PRINTF("\n");
        PRINTF("Found: ");
        for (int i = 0; i < output_description_len; i++) {
            PRINTF("%c", output_description[i]);
        }
        PRINTF("\n");
        SEND_SW_EC(dc, SW_FAIL_SWAP, EC_SWAP_ERROR_WRONG_DESTINATION);
        finalize_exchange_sign_transaction(false);
    }

    return true;
}

static bool __attribute__((noinline))
display_output(dispatcher_context_t *dc,
               sign_psbt_state_t *st,
               int cur_output_index,
               int external_outputs_count,
               const uint8_t out_scriptPubKey[static MAX_OUTPUT_SCRIPTPUBKEY_LEN],
               size_t out_scriptPubKey_len,
               uint64_t out_amount) {
    (void) cur_output_index;

    // show this output's address
    char output_description[MAX_OUTPUT_SCRIPT_DESC_SIZE];

    if (!format_script(out_scriptPubKey, out_scriptPubKey_len, output_description)) {
        PRINTF("Invalid or unsupported script for output %d\n", cur_output_index);
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return false;
    }

    // Show address to the user
    if (!ui_validate_output(dc,
                            external_outputs_count,
                            st->n_external_outputs,
                            output_description,
                            COIN_COINID_SHORT,
                            out_amount)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }
    return true;
}

static bool get_output_script_and_amount(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    size_t output_index,
    uint8_t out_scriptPubKey[static MAX_OUTPUT_SCRIPTPUBKEY_LEN],
    size_t *out_scriptPubKey_len,
    uint64_t *out_amount) {
    if (out_scriptPubKey == NULL || out_amount == NULL) {
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    merkleized_map_commitment_t map;

    // TODO: This might be too slow, as it checks the integrity of the map;
    //       Refactor so that the map key ordering is checked all at the beginning of sign_psbt.
    int res = call_get_merkleized_map(dc, st->outputs_root, st->n_outputs, output_index, &map);

    if (res < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    // Read output amount
    uint8_t raw_result[8];

    // Read the output's amount
    int result_len = call_get_merkleized_map_value(dc,
                                                   &map,
                                                   (uint8_t[]){PSBT_OUT_AMOUNT},
                                                   1,
                                                   raw_result,
                                                   sizeof(raw_result));
    if (result_len != 8) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t value = read_u64_le(raw_result, 0);
    *out_amount = value;

    // Read the output's scriptPubKey
    result_len = call_get_merkleized_map_value(dc,
                                               &map,
                                               (uint8_t[]){PSBT_OUT_SCRIPT},
                                               1,
                                               out_scriptPubKey,
                                               MAX_OUTPUT_SCRIPTPUBKEY_LEN);

    if (result_len == -1 || result_len > MAX_OUTPUT_SCRIPTPUBKEY_LEN) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    *out_scriptPubKey_len = result_len;

    return true;
}

static bool __attribute__((noinline)) display_external_outputs(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]) {
    /**
     *  Display all the non-change outputs
     */

    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // the counter used when showing outputs to the user, which ignores change outputs
    // (0-indexed here, although the UX starts with 1)
    int external_outputs_count = 0;

    for (unsigned int cur_output_index = 0; cur_output_index < st->n_outputs; cur_output_index++) {
        if (!bitvector_get(internal_outputs, cur_output_index)) {
            // external output, user needs to validate
            uint8_t out_scriptPubKey[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
            size_t out_scriptPubKey_len;
            uint64_t out_amount;

            if (external_outputs_count < N_CACHED_EXTERNAL_OUTPUTS) {
                // we have the output cached, no need to fetch it again
                out_scriptPubKey_len = st->outputs.output_script_lengths[external_outputs_count];
                memcpy(out_scriptPubKey,
                       st->outputs.output_scripts[external_outputs_count],
                       out_scriptPubKey_len);
                out_amount = st->outputs.output_amounts[external_outputs_count];
            } else if (!get_output_script_and_amount(dc,
                                                     st,
                                                     cur_output_index,
                                                     out_scriptPubKey,
                                                     &out_scriptPubKey_len,
                                                     &out_amount)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            ++external_outputs_count;

            // displays the output. It fails if the output is invalid or not supported
            if (!display_output(dc,
                                st,
                                cur_output_index,
                                external_outputs_count,
                                out_scriptPubKey,
                                out_scriptPubKey_len,
                                out_amount)) {
                return false;
            }
        }
    }

    return true;
}

static bool __attribute__((noinline))
display_warnings(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    // If there are external inputs, it is unsafe to sign, therefore we warn the user
    if (st->n_external_inputs > 0 && !ui_warn_external_inputs(dc)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }

    // If any segwitv0 input is missing the non-witness-utxo, we warn the user and ask for
    // confirmation
    if (st->warnings.missing_nonwitnessutxo && !ui_warn_unverified_segwit_inputs(dc)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }

    // If any input has non-default sighash, we warn the user
    if (st->warnings.non_default_sighash && !ui_warn_nondefault_sighash(dc)) {
        SEND_SW(dc, SW_DENY);
        return false;
    }

    return true;
}

static bool __attribute__((noinline)) display_transaction(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;

    /** INPUT VERIFICATION ALERTS
     *
     * Show warnings and allow users to abort in any of the following conditions:
     * - pre-taproot transaction with unverified inputs (missing non-witness-utxo)
     * - external inputs
     * - non-default sighash types
     */

    // if the value of fees is 10% or more of the amount, and it's more than 100000
    st->warnings.high_fee = 10 * fee >= st->inputs_total_amount && st->inputs_total_amount > 100000;

#ifdef HAVE_NBGL
    if (st->n_external_outputs == 0 || st->n_external_outputs == 1) {
        // A simplified flow for most transactions: show everything in a single screen if there is
        // exactly 0 (self-transfer) or 1 external output to show to the user

        bool is_self_transfer = st->n_external_outputs == 0;

        // show this output's address
        char output_description[MAX_OUTPUT_SCRIPT_DESC_SIZE];

        if (!is_self_transfer) {
            if (!format_script(st->outputs.output_scripts[0],
                               st->outputs.output_script_lengths[0],
                               output_description)) {
                PRINTF("Invalid or unsupported script for external output\n");
                SEND_SW(dc, SW_NOT_SUPPORTED);
                return false;
            }
        }

        /** TRANSACTION CONFIRMATION
         *
         *  Show transaction amount, destination and fees, ask for final confirmation
         */
        if (!ui_validate_transaction_simplified(
                dc,
                COIN_COINID_SHORT,
                st->is_wallet_default ? NULL : st->wallet_header.name,
                is_self_transfer ? 0 : st->outputs.output_amounts[0],
                is_self_transfer ? NULL : output_description,
                st->warnings,
                fee)) {
            SEND_SW(dc, SW_DENY);
            return false;
        }
    }
#else
    if (st->n_external_outputs == 0) {
        // self-transfer: all the outputs are going to change addresses.
        // No output to show, the user only needs to validate the fees.

        if (!display_warnings(dc, st)) {
            return false;
        }

        if (st->warnings.high_fee && !ui_warn_high_fee(dc)) {
            SEND_SW(dc, SW_DENY);
            return false;
        }

        if (!ui_validate_transaction(dc, COIN_COINID_SHORT, fee, true)) {
            SEND_SW(dc, SW_DENY);
            return false;
        }
    }
#endif
    else {
        // Transactions with more than one external output; show one output per page,
        // using the streaming NBGL API.

#ifdef HAVE_NBGL
        // On NBGL devices, show the pre-approval screen
        // "Review transaction to send Bitcoin"
        if (!ui_transaction_prompt(dc)) {
            SEND_SW(dc, SW_DENY);
            return false;
        }
#endif
        // If it's not a default wallet policy, ask the user for confirmation, and abort if they
        // deny
        if (!st->is_wallet_default && !ui_authorize_wallet_spend(dc, st->wallet_header.name)) {
            SEND_SW(dc, SW_DENY);
            return false;
        }

        if (!display_warnings(dc, st)) {
            return false;
        }

        /** OUTPUTS CONFIRMATION
         *
         *  Display each non-change output, and transaction fees, and acquire user confirmation,
         */
        if (!display_external_outputs(dc, st, internal_outputs)) return false;

        if (st->warnings.high_fee && !ui_warn_high_fee(dc)) {
            SEND_SW(dc, SW_DENY);
            return false;
        }

        /** TRANSACTION CONFIRMATION
         *
         *  Show summary info to the user (transaction fees), ask for final confirmation
         */
        // Show final user validation UI
        if (!ui_validate_transaction(dc, COIN_COINID_SHORT, fee, false)) {
            SEND_SW(dc, SW_DENY);
            return false;
        }
    }

    return true;
}

static bool __attribute__((noinline)) compute_sighash_legacy(dispatcher_context_t *dc,
                                                             sign_psbt_state_t *st,
                                                             input_info_t *input,
                                                             unsigned int cur_input_index,
                                                             uint8_t sighash[static 32]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    cx_sha256_t sighash_context;
    cx_sha256_init(&sighash_context);

    uint8_t tmp[4];
    write_u32_le(tmp, 0, st->tx_version);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    crypto_hash_update_varint(&sighash_context.header, st->n_inputs);

    for (unsigned int i = 0; i < st->n_inputs; i++) {
        // get this input's map
        merkleized_map_commitment_t ith_map;

        if (i != cur_input_index) {
            int res = call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, i, &ith_map);
            if (res < 0) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
        } else {
            // Avoid requesting the same map unnecessarily
            // (might be removed once a caching mechanism is implemented)
            memcpy(&ith_map, &input->in_out.map, sizeof(input->in_out.map));
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
            return false;
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
            return false;
        }

        crypto_hash_update(&sighash_context.header, ith_prevout_n_raw, 4);

        if (i != cur_input_index) {
            // empty scriptcode
            crypto_hash_update_u8(&sighash_context.header, 0x00);
        } else {
            if (!input->has_redeemScript) {
                // P2PKH, the script_code is the prevout's scriptPubKey
                crypto_hash_update_varint(&sighash_context.header, input->in_out.scriptPubKey_len);
                crypto_hash_update(&sighash_context.header,
                                   input->in_out.scriptPubKey,
                                   input->in_out.scriptPubKey_len);
            } else {
                // P2SH, the script_code is the redeemScript

                // update sighash_context with the length-prefixed redeem script
                int redeemScript_len =
                    update_hashes_with_map_value(dc,
                                                 &input->in_out.map,
                                                 (uint8_t[]){PSBT_IN_REDEEM_SCRIPT},
                                                 1,
                                                 NULL,
                                                 &sighash_context.header);

                if (redeemScript_len < 0) {
                    PRINTF("Error fetching redeemScript\n");
                    SEND_SW(dc, SW_INCORRECT_DATA);
                    return false;
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
    crypto_hash_update_varint(&sighash_context.header, st->n_outputs);
    if (hash_outputs(dc, st, &sighash_context.header) == -1) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    // nLocktime
    write_u32_le(tmp, 0, st->locktime);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // hash type
    write_u32_le(tmp, 0, input->sighash_type);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // compute sighash
    crypto_hash_digest(&sighash_context.header, sighash, 32);
    cx_hash_sha256(sighash, 32, sighash, 32);

    return true;
}

static bool __attribute__((noinline)) compute_sighash_segwitv0(dispatcher_context_t *dc,
                                                               sign_psbt_state_t *st,
                                                               segwit_hashes_t *hashes,
                                                               input_info_t *input,
                                                               unsigned int cur_input_index,
                                                               uint8_t sighash[static 32]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    cx_sha256_t sighash_context;
    cx_sha256_init(&sighash_context);

    uint8_t tmp[8];
    uint8_t sighash_byte = (uint8_t) (input->sighash_type & 0xFF);

    // nVersion
    write_u32_le(tmp, 0, st->tx_version);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    {
        uint8_t dbl_hash[32];

        memset(dbl_hash, 0, 32);
        // add to hash: hashPrevouts = sha256(sha_prevouts)
        if (!(sighash_byte & SIGHASH_ANYONECANPAY)) {
            cx_hash_sha256(hashes->sha_prevouts, 32, dbl_hash, 32);
        }

        crypto_hash_update(&sighash_context.header, dbl_hash, 32);

        memset(dbl_hash, 0, 32);
        // add to hash: hashSequence sha256(sha_sequences)
        if (!(sighash_byte & SIGHASH_ANYONECANPAY) && (sighash_byte & 0x1f) != SIGHASH_SINGLE &&
            (sighash_byte & 0x1f) != SIGHASH_NONE) {
            cx_hash_sha256(hashes->sha_sequences, 32, dbl_hash, 32);
        }
        crypto_hash_update(&sighash_context.header, dbl_hash, 32);
    }

    {
        // outpoint (32-byte prevout hash, 4-byte index)

        // get prevout hash and output index for the current input
        uint8_t prevout_hash[32];
        if (32 != call_get_merkleized_map_value(dc,
                                                &input->in_out.map,
                                                (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                1,
                                                prevout_hash,
                                                32)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        crypto_hash_update(&sighash_context.header, prevout_hash, 32);

        uint8_t prevout_n_raw[4];
        if (4 != call_get_merkleized_map_value(dc,
                                               &input->in_out.map,
                                               (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                               1,
                                               prevout_n_raw,
                                               4)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        crypto_hash_update(&sighash_context.header, prevout_n_raw, 4);
    }

    // scriptCode
    if (is_p2wpkh(input->script, input->script_len)) {
        // P2WPKH(script[2:22])
        crypto_hash_update_u32(&sighash_context.header, 0x1976a914);
        crypto_hash_update(&sighash_context.header, input->script + 2, 20);
        crypto_hash_update_u16(&sighash_context.header, 0x88ac);
    } else if (is_p2wsh(input->script, input->script_len)) {
        // P2WSH

        // update sighash_context.header with the length-prefixed witnessScript,
        // and also compute sha256(witnessScript)
        cx_sha256_t witnessScript_hash_context;
        cx_sha256_init(&witnessScript_hash_context);

        int witnessScript_len = update_hashes_with_map_value(dc,
                                                             &input->in_out.map,
                                                             (uint8_t[]){PSBT_IN_WITNESS_SCRIPT},
                                                             1,
                                                             &witnessScript_hash_context.header,
                                                             &sighash_context.header);

        if (witnessScript_len < 0) {
            PRINTF("Error fetching witnessScript\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t witnessScript_hash[32];
        crypto_hash_digest(&witnessScript_hash_context.header, witnessScript_hash, 32);

        // check that script == P2WSH(witnessScript)
        if (input->script_len != 2 + 32 || input->script[0] != 0x00 || input->script[1] != 0x20 ||
            memcmp(input->script + 2, witnessScript_hash, 32) != 0) {
            PRINTF("Mismatching witnessScript\n");

            SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_MISMATCHING_WITNESS_SCRIPT);
            return false;
        }
    } else {
        PRINTF("Invalid or unsupported script in segwit transaction\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    {
        // input value, taken from the WITNESS_UTXO field
        uint8_t witness_utxo[8 + 1 + MAX_PREVOUT_SCRIPTPUBKEY_LEN];

        int witness_utxo_len = call_get_merkleized_map_value(dc,
                                                             &input->in_out.map,
                                                             (uint8_t[]){PSBT_IN_WITNESS_UTXO},
                                                             1,
                                                             witness_utxo,
                                                             sizeof(witness_utxo));
        if (witness_utxo_len < 8) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        crypto_hash_update(&sighash_context.header,
                           witness_utxo,
                           8);  // only the first 8 bytes (amount)
    }

    // nSequence
    {
        uint8_t nSequence_raw[4];
        if (4 != call_get_merkleized_map_value(dc,
                                               &input->in_out.map,
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
        memset(hashOutputs, 0, 32);

        if ((sighash_byte & 0x1f) != SIGHASH_SINGLE && (sighash_byte & 0x1f) != SIGHASH_NONE) {
            cx_hash_sha256(hashes->sha_outputs, 32, hashOutputs, 32);

        } else if ((sighash_byte & 0x1f) == SIGHASH_SINGLE && cur_input_index < st->n_outputs) {
            cx_sha256_t sha_output_context;
            cx_sha256_init(&sha_output_context);
            if (hash_output_n(dc, st, &sha_output_context.header, cur_input_index) == -1) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
            crypto_hash_digest(&sha_output_context.header, hashOutputs, 32);
            cx_hash_sha256(hashOutputs, 32, hashOutputs, 32);
        }
        crypto_hash_update(&sighash_context.header, hashOutputs, 32);
    }

    // nLocktime
    write_u32_le(tmp, 0, st->locktime);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // sighash type
    write_u32_le(tmp, 0, input->sighash_type);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // compute sighash
    crypto_hash_digest(&sighash_context.header, sighash, 32);
    cx_hash_sha256(sighash, 32, sighash, 32);

    return true;
}

static bool __attribute__((noinline)) compute_sighash_segwitv1(dispatcher_context_t *dc,
                                                               sign_psbt_state_t *st,
                                                               segwit_hashes_t *hashes,
                                                               input_info_t *input,
                                                               unsigned int cur_input_index,
                                                               keyexpr_info_t *keyexpr_info,
                                                               uint8_t sighash[static 32]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    cx_sha256_t sighash_context;
    crypto_tr_tagged_hash_init(&sighash_context, BIP0341_sighash_tag, sizeof(BIP0341_sighash_tag));
    // the first 0x00 byte is not part of SigMsg
    crypto_hash_update_u8(&sighash_context.header, 0x00);

    uint8_t tmp[MAX(32, 8 + 1 + MAX_PREVOUT_SCRIPTPUBKEY_LEN)];

    // hash type
    uint8_t sighash_byte = (uint8_t) (input->sighash_type & 0xFF);
    crypto_hash_update_u8(&sighash_context.header, sighash_byte);

    // nVersion
    write_u32_le(tmp, 0, st->tx_version);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // nLocktime
    write_u32_le(tmp, 0, st->locktime);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    if ((sighash_byte & 0x80) != SIGHASH_ANYONECANPAY) {
        crypto_hash_update(&sighash_context.header, hashes->sha_prevouts, 32);
        crypto_hash_update(&sighash_context.header, hashes->sha_amounts, 32);
        crypto_hash_update(&sighash_context.header, hashes->sha_scriptpubkeys, 32);
        crypto_hash_update(&sighash_context.header, hashes->sha_sequences, 32);
    }

    if ((sighash_byte & 3) != SIGHASH_NONE && (sighash_byte & 3) != SIGHASH_SINGLE) {
        crypto_hash_update(&sighash_context.header, hashes->sha_outputs, 32);
    }

    // ext_flag
    uint8_t ext_flag = keyexpr_info->is_tapscript ? 1 : 0;
    // annex is not supported
    const uint8_t annex_present = 0;
    uint8_t spend_type = ext_flag * 2 + annex_present;
    crypto_hash_update_u8(&sighash_context.header, spend_type);

    if ((sighash_byte & 0x80) == SIGHASH_ANYONECANPAY) {
        // outpoint (hash)
        if (32 != call_get_merkleized_map_value(dc,
                                                &input->in_out.map,
                                                (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                1,
                                                tmp,
                                                32)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        crypto_hash_update(&sighash_context.header, tmp, 32);

        // outpoint (output index)
        if (4 != call_get_merkleized_map_value(dc,
                                               &input->in_out.map,
                                               (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                               1,
                                               tmp,
                                               4)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        crypto_hash_update(&sighash_context.header, tmp, 4);

        if (8 > call_get_merkleized_map_value(dc,
                                              &input->in_out.map,
                                              (uint8_t[]){PSBT_IN_WITNESS_UTXO},
                                              1,
                                              tmp,
                                              8 + 1 + MAX_PREVOUT_SCRIPTPUBKEY_LEN)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        // amount
        crypto_hash_update(&sighash_context.header, tmp, 8);

        // scriptPubKey
        crypto_hash_update_varint(&sighash_context.header, input->in_out.scriptPubKey_len);

        crypto_hash_update(&sighash_context.header,
                           input->in_out.scriptPubKey,
                           input->in_out.scriptPubKey_len);

        // nSequence
        if (4 != call_get_merkleized_map_value(dc,
                                               &input->in_out.map,
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
        write_u32_le(tmp, 0, cur_input_index);
        crypto_hash_update(&sighash_context.header, tmp, 4);
    }

    // no annex

    if ((sighash_byte & 3) == SIGHASH_SINGLE) {
        // compute sha_output
        cx_sha256_t sha_output_context;
        cx_sha256_init(&sha_output_context);

        if (hash_output_n(dc, st, &sha_output_context.header, cur_input_index) == -1) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        crypto_hash_digest(&sha_output_context.header, tmp, 32);

        crypto_hash_update(&sighash_context.header, tmp, 32);
    }

    if (keyexpr_info->is_tapscript) {
        // If spending a tapscript, append the Common Signature Message Extension per BIP-0342
        crypto_hash_update(&sighash_context.header, keyexpr_info->tapleaf_hash, 32);
        crypto_hash_update_u8(&sighash_context.header, 0x00);         // key_version
        crypto_hash_update_u32(&sighash_context.header, 0xffffffff);  // no OP_CODESEPARATOR
    }

    crypto_hash_digest(&sighash_context.header, sighash, 32);

    return true;
}

static bool __attribute__((noinline)) yield_signature(dispatcher_context_t *dc,
                                                      sign_psbt_state_t *st,
                                                      unsigned int cur_input_index,
                                                      uint8_t *pubkey,
                                                      uint8_t pubkey_len,
                                                      uint8_t *tapleaf_hash,
                                                      uint8_t *sig,
                                                      size_t sig_len) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // yield signature
    uint8_t cmd = CCMD_YIELD;
    dc->add_to_response(&cmd, 1);

    uint8_t buf[9];
    int input_index_varint_len = varint_write(buf, 0, cur_input_index);
    dc->add_to_response(&buf, input_index_varint_len);

    // for tapscript signatures, we concatenate the (x-only) pubkey with the tapleaf hash
    uint8_t augm_pubkey_len = pubkey_len + (tapleaf_hash != NULL ? 32 : 0);

    // the pubkey is not output in version 0 of the protocol
    if (st->protocol_version >= 1) {
        dc->add_to_response(&augm_pubkey_len, 1);
        dc->add_to_response(pubkey, pubkey_len);

        if (tapleaf_hash != NULL) {
            dc->add_to_response(tapleaf_hash, 32);
        }
    }

    dc->add_to_response(sig, sig_len);

    dc->finalize_response(SW_INTERRUPTED_EXECUTION);

    if (dc->process_interruption(dc) < 0) {
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }
    return true;
}

static bool __attribute__((noinline)) sign_sighash_ecdsa_and_yield(dispatcher_context_t *dc,
                                                                   sign_psbt_state_t *st,
                                                                   keyexpr_info_t *keyexpr_info,
                                                                   input_info_t *input,
                                                                   unsigned int cur_input_index,
                                                                   uint8_t sighash[static 32]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    uint32_t sign_path[MAX_BIP32_PATH_STEPS];
    for (int i = 0; i < keyexpr_info->key_derivation_length; i++) {
        sign_path[i] = keyexpr_info->key_derivation[i];
    }
    sign_path[keyexpr_info->key_derivation_length] =
        input->in_out.is_change ? keyexpr_info->key_expression_ptr->num_second
                                : keyexpr_info->key_expression_ptr->num_first;
    sign_path[keyexpr_info->key_derivation_length + 1] = input->in_out.address_index;

    int sign_path_len = keyexpr_info->key_derivation_length + 2;

    uint8_t sig[MAX_DER_SIG_LEN + 1];  // extra byte for the appended sighash-type

    uint8_t pubkey[33];

    int sig_len = crypto_ecdsa_sign_sha256_hash_with_key(sign_path,
                                                         sign_path_len,
                                                         sighash,
                                                         pubkey,
                                                         sig,
                                                         NULL);
    if (sig_len < 0) {
        // unexpected error when signing
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    // append the sighash type byte
    uint8_t sighash_byte = (uint8_t) (input->sighash_type & 0xFF);
    sig[sig_len++] = sighash_byte;

    if (!yield_signature(dc, st, cur_input_index, pubkey, 33, NULL, sig, sig_len)) return false;

    return true;
}

static bool __attribute__((noinline)) sign_sighash_schnorr_and_yield(dispatcher_context_t *dc,
                                                                     sign_psbt_state_t *st,
                                                                     keyexpr_info_t *keyexpr_info,
                                                                     input_info_t *input,
                                                                     unsigned int cur_input_index,
                                                                     uint8_t sighash[static 32]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    if (st->wallet_policy_map->type != TOKEN_TR) {
        SEND_SW(dc, SW_BAD_STATE);  // should never happen
        return false;
    }

    uint8_t sig[64 + 1];  // extra byte for the appended sighash-type, possibly
    size_t sig_len = 0;

    cx_ecfp_public_key_t pubkey_tweaked;  // Pubkey corresponding to the key used for signing

    uint8_t *tapleaf_hash = NULL;

    bool error = false;
    cx_ecfp_private_key_t private_key = {0};

    // IMPORTANT: Since we do not use any syscall that might throw an exception, it is safe to avoid
    // using the TRY/CATCH block to ensure zeroing sensitive data.

    do {  // block executed once, only to allow safely breaking out on error

        uint8_t *seckey =
            private_key.d;  // convenience alias (entirely within the private_key struct)

        uint32_t sign_path[MAX_BIP32_PATH_STEPS];

        for (int i = 0; i < keyexpr_info->key_derivation_length; i++) {
            sign_path[i] = keyexpr_info->key_derivation[i];
        }
        sign_path[keyexpr_info->key_derivation_length] =
            input->in_out.is_change ? keyexpr_info->key_expression_ptr->num_second
                                    : keyexpr_info->key_expression_ptr->num_first;
        sign_path[keyexpr_info->key_derivation_length + 1] = input->in_out.address_index;

        int sign_path_len = keyexpr_info->key_derivation_length + 2;

        if (bip32_derive_init_privkey_256(CX_CURVE_256K1,
                                          sign_path,
                                          sign_path_len,
                                          &private_key,
                                          NULL) != CX_OK) {
            error = true;
            break;
        }

        policy_node_tr_t *policy = (policy_node_tr_t *) st->wallet_policy_map;

        if (!keyexpr_info->is_tapscript) {
            if (isnull_policy_node_tree(&policy->tree)) {
                // tweak as specified in BIP-86 and BIP-386
                crypto_tr_tweak_seckey(seckey, (uint8_t[]){}, 0, seckey);
            } else {
                // tweak with the taptree hash, per BIP-341
                // The taptree hash is computed in sign_transaction_input in order to
                // reduce stack usage.
                crypto_tr_tweak_seckey(seckey, input->taptree_hash, 32, seckey);
            }
        } else {
            // tapscript, we need to yield the tapleaf hash together with the pubkey
            tapleaf_hash = keyexpr_info->tapleaf_hash;
        }

        // generate corresponding public key
        unsigned int err =
            cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, &pubkey_tweaked, &private_key, 1);
        if (err != CX_OK) {
            error = true;
            break;
        }

        err = cx_ecschnorr_sign_no_throw(&private_key,
                                         CX_ECSCHNORR_BIP0340 | CX_RND_TRNG,
                                         CX_SHA256,
                                         sighash,
                                         32,
                                         sig,
                                         &sig_len);
        if (err != CX_OK) {
            error = true;
        }
    } while (false);

    explicit_bzero(&private_key, sizeof(private_key));

    if (error) {
        // unexpected error when signing
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    if (sig_len != 64) {
        PRINTF("SIG LEN: %d\n", sig_len);
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    // only append the sighash type byte if it is non-zero
    uint8_t sighash_byte = (uint8_t) (input->sighash_type & 0xFF);
    if (sighash_byte != 0x00) {
        // only add the sighash byte if not 0
        sig[sig_len++] = sighash_byte;
    }

    if (!yield_signature(dc,
                         st,
                         cur_input_index,
                         pubkey_tweaked.W + 1,  // x-only pubkey, hence take only the x-coordinate
                         32,
                         tapleaf_hash,
                         sig,
                         sig_len))
        return false;

    return true;
}

static bool __attribute__((noinline)) yield_musig_data(dispatcher_context_t *dc,
                                                       sign_psbt_state_t *st,
                                                       unsigned int cur_input_index,
                                                       const uint8_t *data,
                                                       size_t data_len,
                                                       uint32_t tag,
                                                       const uint8_t participant_pk[static 33],
                                                       const uint8_t aggregate_pubkey[static 33],
                                                       const uint8_t *tapleaf_hash) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    if (st->protocol_version == 0) {
        // Only support version 1 of the protocol
        return false;
    }

    // bytes:     1       5       varint     data_len         33               33         0 or 32
    //        CMD_YIELD <tag> <input_index>   <data>    <participant_pk> <aggregate_pubkey>
    //        <leaf_hash>

    // Yield signature
    uint8_t cmd = CCMD_YIELD;
    dc->add_to_response(&cmd, 1);

    uint8_t buf[9];

    // Add tag
    int tag_varint_len = varint_write(buf, 0, tag);
    dc->add_to_response(buf, tag_varint_len);

    // Add input index
    int input_index_varint_len = varint_write(buf, 0, cur_input_index);
    dc->add_to_response(buf, input_index_varint_len);

    // Add data (pubnonce or partial signature)
    dc->add_to_response(data, data_len);

    // Add participant public key
    dc->add_to_response(participant_pk, 33);

    // Add aggregate public key
    dc->add_to_response(aggregate_pubkey, 33);

    // Add tapleaf hash if provided
    if (tapleaf_hash != NULL) {
        dc->add_to_response(tapleaf_hash, 32);
    }

    dc->finalize_response(SW_INTERRUPTED_EXECUTION);

    if (dc->process_interruption(dc) < 0) {
        return false;
    }
    return true;
}

static bool yield_musig_pubnonce(dispatcher_context_t *dc,
                                 sign_psbt_state_t *st,
                                 unsigned int cur_input_index,
                                 const musig_pubnonce_t *pubnonce,
                                 const uint8_t participant_pk[static 33],
                                 const uint8_t aggregate_pubkey[static 33],
                                 const uint8_t *tapleaf_hash) {
    return yield_musig_data(dc,
                            st,
                            cur_input_index,
                            (const uint8_t *) pubnonce,
                            sizeof(musig_pubnonce_t),
                            CCMD_YIELD_MUSIG_PUBNONCE_TAG,
                            participant_pk,
                            aggregate_pubkey,
                            tapleaf_hash);
}

static bool yield_musig_partial_signature(dispatcher_context_t *dc,
                                          sign_psbt_state_t *st,
                                          unsigned int cur_input_index,
                                          const uint8_t psig[static 32],
                                          const uint8_t participant_pk[static 33],
                                          const uint8_t aggregate_pubkey[static 33],
                                          const uint8_t *tapleaf_hash) {
    return yield_musig_data(dc,
                            st,
                            cur_input_index,
                            psig,
                            32,
                            CCMD_YIELD_MUSIG_PARTIALSIGNATURE_TAG,
                            participant_pk,
                            aggregate_pubkey,
                            tapleaf_hash);
}

static bool __attribute__((noinline)) sign_sighash_musig_and_yield(dispatcher_context_t *dc,
                                                                   sign_psbt_state_t *st,
                                                                   keyexpr_info_t *keyexpr_info,
                                                                   input_info_t *input,
                                                                   unsigned int cur_input_index,
                                                                   uint8_t sighash[static 32]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    if (st->wallet_policy_map->type != TOKEN_TR) {
        SEND_SW(dc, SW_BAD_STATE);  // should never happen
        return false;
    }

    const policy_node_tr_t *tr_policy = (policy_node_tr_t *) st->wallet_policy_map;

    // plan:
    // 1) compute aggregate pubkey
    // 2) compute musig2 tweaks
    // 3) compute taproot tweak (if keypath spend)
    // if my pubnonce is in the psbt:
    //        5) generate and yield pubnonce
    //    else:
    //        6) generate and yield partial signature

    // 1) compute aggregate pubkey

    // TODO: we should compute the aggregate pubkey just once for the placeholder, instead of
    // repeating for each input
    wallet_derivation_info_t wdi = {.n_keys = st->wallet_header.n_keys,
                                    .wallet_version = st->wallet_header.version,
                                    .keys_merkle_root = st->wallet_header.keys_info_merkle_root,
                                    .change = input->in_out.is_change,
                                    .address_index = input->in_out.address_index};

    // TODO: code duplication with policy.c::get_derived_pubkey; worth extracting a common method?

    serialized_extended_pubkey_t ext_pubkey;

    const policy_node_keyexpr_t *key_expr = keyexpr_info->key_expression_ptr;
    musig_aggr_key_info_t *musig_info = r_musig_aggr_key_info(&key_expr->m.musig_info);
    uint16_t *key_indexes = r_uint16(&musig_info->key_indexes);
    plain_pk_t keys[MAX_PUBKEYS_PER_MUSIG];
    for (int i = 0; i < musig_info->n; i++) {
        // we use ext_pubkey as a temporary variable; will overwrite later
        if (0 > get_extended_pubkey(dc, &wdi, key_indexes[i], &ext_pubkey)) {
            return -1;
        }
        memcpy(keys[i], ext_pubkey.compressed_pubkey, sizeof(ext_pubkey.compressed_pubkey));
    }

    // sort the keys in ascending order using bubble sort
    for (int i = 0; i < musig_info->n; i++) {
        for (int j = 0; j < musig_info->n - 1; j++) {
            if (memcmp(keys[j], keys[j + 1], sizeof(plain_pk_t)) > 0) {
                uint8_t tmp[sizeof(plain_pk_t)];
                memcpy(tmp, keys[j], sizeof(plain_pk_t));
                memcpy(keys[j], keys[j + 1], sizeof(plain_pk_t));
                memcpy(keys[j + 1], tmp, sizeof(plain_pk_t));
            }
        }
    }

    musig_keyagg_context_t musig_ctx;
    musig_key_agg(keys, musig_info->n, &musig_ctx);

    // compute the aggregated extended pubkey
    memset(&ext_pubkey, 0, sizeof(ext_pubkey));
    write_u32_be(ext_pubkey.version, 0, BIP32_PUBKEY_VERSION);

    ext_pubkey.compressed_pubkey[0] = (musig_ctx.Q.y[31] % 2 == 0) ? 2 : 3;
    memcpy(&ext_pubkey.compressed_pubkey[1], musig_ctx.Q.x, sizeof(musig_ctx.Q.x));
    memcpy(&ext_pubkey.chain_code, BIP_MUSIG_CHAINCODE, sizeof(BIP_MUSIG_CHAINCODE));

    // 2) compute musig2 tweaks
    // We always have exactly 2 BIP32 tweaks in wallet policies; if the musig is in the keypath
    // spend, we also have an x-only taptweak with the taproot tree hash (or BIP-86/BIP-386 style if
    // there is no taproot tree).

    uint32_t change_step = input->in_out.is_change ? keyexpr_info->key_expression_ptr->num_second
                                                   : keyexpr_info->key_expression_ptr->num_first;
    uint32_t addr_index_step = input->in_out.address_index;

    // in wallet policies, we always have at least two bip32-tweaks, and we might have
    // one x-only tweak per BIP-0341 (if spending from the keypath).
    uint8_t tweaks[3][32];
    uint8_t *tweaks_ptrs[3] = {tweaks[0], tweaks[1], tweaks[2]};
    bool is_xonly[] = {false, false, true};
    size_t n_tweaks = 2;  // might be changed to 3 below

    serialized_extended_pubkey_t agg_key_tweaked;
    if (0 > bip32_CKDpub(&ext_pubkey, change_step, &agg_key_tweaked, tweaks[0])) {
        SEND_SW(dc, SW_BAD_STATE);  // should never happen
        return false;
    }
    if (0 > bip32_CKDpub(&agg_key_tweaked, addr_index_step, &agg_key_tweaked, tweaks[1])) {
        SEND_SW(dc, SW_BAD_STATE);  // should never happen
        return false;
    }

    // 3) compute taproot tweak (if keypath spend)
    memset(tweaks[2], 0, 32);
    if (!keyexpr_info->is_tapscript) {
        n_tweaks = 3;

        crypto_tr_tagged_hash(
            BIP0341_taptweak_tag,
            sizeof(BIP0341_taptweak_tag),
            agg_key_tweaked.compressed_pubkey + 1,  // xonly key, after BIP-32 tweaks
            32,
            input->taptree_hash,
            // BIP-86 compliant tweak if there's no taptree, otherwise use the taptree hash
            isnull_policy_node_tree(&tr_policy->tree) ? 0 : 32,
            tweaks[2]);

        // also apply the taptweak to agg_key_tweaked

        uint8_t parity = 0;
        crypto_tr_tweak_pubkey(agg_key_tweaked.compressed_pubkey + 1,
                               input->taptree_hash,
                               isnull_policy_node_tree(&tr_policy->tree) ? 0 : 32,
                               &parity,
                               agg_key_tweaked.compressed_pubkey + 1);
        agg_key_tweaked.compressed_pubkey[0] = 0x02 + parity;
    }

    // we will no longer use the other fields of the extended pubkey, so we zero them for sanity
    memset(agg_key_tweaked.chain_code, 0, sizeof(agg_key_tweaked.chain_code));
    memset(agg_key_tweaked.child_number, 0, sizeof(agg_key_tweaked.child_number));
    agg_key_tweaked.depth = 0;
    memset(agg_key_tweaked.parent_fingerprint, 0, sizeof(agg_key_tweaked.parent_fingerprint));
    memset(agg_key_tweaked.version, 0, sizeof(agg_key_tweaked.version));

    // Compute musig_my_psbt_id. It is the psbt key that this signer uses to find pubnonces and
    // partial signatures (PSBT_IN_MUSIG2_PUB_NONCE and PSBT_IN_MUSIG2_PARTIAL_SIG fields). The
    // length is either 33+33 (keypath spend), or 33+33+32 bytes (tapscript spend). It's the
    // concatenation of:
    // - the 33-byte compressed pubkey of this participant
    // - the 33-byte aggregate compressed pubkey (after all the tweaks)
    // - (tapscript only) the 32-byte tapleaf hash
    uint8_t musig_my_psbt_id_key[1 + 33 + 33 + 32];
    musig_my_psbt_id_key[0] = PSBT_IN_MUSIG2_PUB_NONCE;

    uint8_t *musig_my_psbt_id = musig_my_psbt_id_key + 1;
    size_t psbt_id_len = keyexpr_info->is_tapscript ? 33 + 33 + 32 : 33 + 33;
    memcpy(musig_my_psbt_id, keyexpr_info->internal_pubkey.compressed_pubkey, 33);
    memcpy(musig_my_psbt_id + 33, agg_key_tweaked.compressed_pubkey, 33);
    if (keyexpr_info->is_tapscript) {
        memcpy(musig_my_psbt_id + 33 + 33, keyexpr_info->tapleaf_hash, 32);
    }

    // compute psbt session id
    uint8_t psbt_session_id[32];
    // TODO: for now we use simply a hash that depends on the keys of the wallet policy; this is not
    // good enough. It should be a hash that depends on:
    // - the wallet policy id
    // - the tx being signed
    // - the input index
    // - the index of the placeholder we're signing for
    memcpy(psbt_session_id, st->wallet_header.keys_info_merkle_root, sizeof(psbt_session_id));

    // 4) check if my pubnonce is in the psbt
    musig_pubnonce_t my_pubnonce;
    if (sizeof(musig_pubnonce_t) != call_get_merkleized_map_value(dc,
                                                                  &input->in_out.map,
                                                                  musig_my_psbt_id_key,
                                                                  1 + psbt_id_len,
                                                                  my_pubnonce.raw,
                                                                  sizeof(musig_pubnonce_t))) {
        // 5) generate and yield pubnonce

        // if an existing session for psbt_session_id exists, delete it
        if (musigsession_pop(psbt_session_id, NULL)) {
            // We wouldn't expect this: probably the client sent the same psbt for
            // round 1 twice, without adding the pubnonces to the psbt after the first round.
            // We delete the old session and start a fresh one, but we print a
            // warning if in debug mode.
            PRINTF("Session with the same id already existing\n");
        }

        musig_session_t psbt_session;
        memcpy(psbt_session.id, psbt_session_id, sizeof(psbt_session_id));

        // TODO: the "session" should be initialized once for all the (inputs, placeholder) pairs;
        // this is wrong!
        musigsession_init_randomness(&psbt_session);

        uint8_t rand_i_j[32];
        compute_rand_i_j(psbt_session.rand_root,
                         cur_input_index,
                         keyexpr_info->cur_index,
                         rand_i_j);

        musig_secnonce_t secnonce;
        musig_pubnonce_t pubnonce;
        if (0 > musig_nonce_gen(rand_i_j,
                                keyexpr_info->internal_pubkey.compressed_pubkey,
                                agg_key_tweaked.compressed_pubkey + 1,
                                &secnonce,
                                &pubnonce)) {
            PRINTF("MuSig2 nonce generation failed\n");
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            return false;
        }

        if (!yield_musig_pubnonce(dc,
                                  st,
                                  cur_input_index,
                                  &pubnonce,
                                  keyexpr_info->internal_pubkey.compressed_pubkey,
                                  agg_key_tweaked.compressed_pubkey,
                                  keyexpr_info->is_tapscript ? keyexpr_info->tapleaf_hash : NULL)) {
            PRINTF("Failed yielding MuSig2 pubnonce\n");
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            return false;
        }

        // TODO: wrong if we have multiple inputs!
        musigsession_store(psbt_session_id, &psbt_session);
    } else {
        // 6) generate and yield partial signature
        musig_session_t psbt_session;
        // get and delete the musig session from permanent storage
        if (!musigsession_pop(psbt_session_id, &psbt_session)) {
            // The PSBT contains a partial nonce, but we do not have the corresponding psbt session
            // in storage. Either it was deleted, or the pubnonces were not real. Either way, we
            // cannot continue.
            PRINTF("Missing MuSig2 session\n");
            SEND_SW(dc, SW_BAD_STATE);
            return false;
        }

        musig_pubnonce_t nonces[MAX_PUBKEYS_PER_MUSIG];

        for (int i = 0; i < musig_info->n; i++) {
            uint8_t musig_ith_psbt_id_key[1 + 33 + 33 + 32];
            uint8_t *musig_ith_psbt_id = musig_ith_psbt_id_key + 1;
            // copy from musig_my_psbt_id_key, but replace the corresponding pubkey
            memcpy(musig_ith_psbt_id_key, musig_my_psbt_id_key, sizeof(musig_my_psbt_id_key));
            memcpy(musig_ith_psbt_id, keys[i], sizeof(plain_pk_t));

            // TODO: could avoid fetching again our own pubnonce
            if (sizeof(musig_pubnonce_t) !=
                call_get_merkleized_map_value(dc,
                                              &input->in_out.map,
                                              musig_ith_psbt_id_key,
                                              1 + psbt_id_len,
                                              nonces[i].raw,
                                              sizeof(musig_pubnonce_t))) {
                PRINTF("Missing or incorrect pubnonce for a MuSig2 cosigner\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
        }

        // compute aggregate nonce
        musig_pubnonce_t aggnonce;
        int res = musig_nonce_agg(nonces, musig_info->n, &aggnonce);
        if (res < 0) {
            PRINTF("Musig aggregation failed; disruptive signer has index %d\n", -res);
            SEND_SW(dc, SW_INCORRECT_DATA);
        }

        // recompute secnonce from psbt_session randomness
        uint8_t rand_i_j[32];
        compute_rand_i_j(psbt_session.rand_root,
                         cur_input_index,
                         keyexpr_info->cur_index,
                         rand_i_j);

        musig_secnonce_t secnonce;
        musig_pubnonce_t pubnonce;

        if (0 > musig_nonce_gen(rand_i_j,
                                keyexpr_info->internal_pubkey.compressed_pubkey,
                                agg_key_tweaked.compressed_pubkey + 1,
                                &secnonce,
                                &pubnonce)) {
            PRINTF("MuSig2 nonce generation failed\n");
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            return false;
        }

        // derive secret key

        cx_ecfp_private_key_t private_key = {0};
        uint8_t psig[32];
        bool err = false;
        do {  // block executed once, only to allow safely breaking out on error

            // derive secret key
            uint32_t sign_path[MAX_BIP32_PATH_STEPS];

            for (int i = 0; i < keyexpr_info->key_derivation_length; i++) {
                sign_path[i] = keyexpr_info->key_derivation[i];
            }
            int sign_path_len = keyexpr_info->key_derivation_length;

            if (bip32_derive_init_privkey_256(CX_CURVE_256K1,
                                              sign_path,
                                              sign_path_len,
                                              &private_key,
                                              NULL) != CX_OK) {
                err = true;
                break;
            }

            // Create partial signature
            musig_session_context_t musig_session_context = {.aggnonce = &aggnonce,
                                                             .n_keys = musig_info->n,
                                                             .pubkeys = keys,
                                                             .n_tweaks = n_tweaks,
                                                             .tweaks = tweaks_ptrs,
                                                             .is_xonly = is_xonly,
                                                             .msg = sighash,
                                                             .msg_len = 32};

            if (0 > musig_sign(&secnonce, private_key.d, &musig_session_context, psig)) {
                PRINTF("Musig2 signature failed\n");
                err = true;
                break;
            }
        } while (false);

        explicit_bzero(&private_key, sizeof(private_key));

        if (err) {
            PRINTF("Partial signature generation failed\n");
            return false;
        }

        if (!yield_musig_partial_signature(
                dc,
                st,
                cur_input_index,
                psig,
                keyexpr_info->internal_pubkey.compressed_pubkey,
                agg_key_tweaked.compressed_pubkey,
                keyexpr_info->is_tapscript ? keyexpr_info->tapleaf_hash : NULL)) {
            PRINTF("Failed yielding MuSig2 partial signature\n");
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            return false;
        }
    }

    return true;
}

static bool __attribute__((noinline))
compute_segwit_hashes(dispatcher_context_t *dc, sign_psbt_state_t *st, segwit_hashes_t *hashes) {
    {
        // compute sha_prevouts and sha_sequences
        cx_sha256_t sha_prevouts_context, sha_sequences_context;

        // compute hashPrevouts and hashSequence
        cx_sha256_init(&sha_prevouts_context);
        cx_sha256_init(&sha_sequences_context);

        for (unsigned int i = 0; i < st->n_inputs; i++) {
            // get this input's map
            merkleized_map_commitment_t ith_map;

            int res = call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, i, &ith_map);
            if (res < 0) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
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
                return false;
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
                return false;
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

        crypto_hash_digest(&sha_prevouts_context.header, hashes->sha_prevouts, 32);
        crypto_hash_digest(&sha_sequences_context.header, hashes->sha_sequences, 32);
    }

    {
        // compute sha_outputs
        cx_sha256_t sha_outputs_context;
        cx_sha256_init(&sha_outputs_context);

        if (hash_outputs(dc, st, &sha_outputs_context.header) == -1) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        crypto_hash_digest(&sha_outputs_context.header, hashes->sha_outputs, 32);
    }

    {
        // compute sha_amounts and sha_scriptpubkeys
        // TODO: could be skipped if there are no segwitv1 inputs to sign

        cx_sha256_t sha_amounts_context, sha_scriptpubkeys_context;

        cx_sha256_init(&sha_amounts_context);
        cx_sha256_init(&sha_scriptpubkeys_context);

        for (unsigned int i = 0; i < st->n_inputs; i++) {
            // get this input's map
            merkleized_map_commitment_t ith_map;

            int res = call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, i, &ith_map);
            if (res < 0) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            uint64_t in_amount;
            uint8_t in_scriptPubKey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
            size_t in_scriptPubKey_len;

            if (0 > get_amount_scriptpubkey_from_psbt(dc,
                                                      &ith_map,
                                                      &in_amount,
                                                      in_scriptPubKey,
                                                      &in_scriptPubKey_len)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            uint8_t in_amount_le[8];
            write_u64_le(in_amount_le, 0, in_amount);
            crypto_hash_update(&sha_amounts_context.header, in_amount_le, 8);

            crypto_hash_update_varint(&sha_scriptpubkeys_context.header, in_scriptPubKey_len);
            crypto_hash_update(&sha_scriptpubkeys_context.header,
                               in_scriptPubKey,
                               in_scriptPubKey_len);
        }

        crypto_hash_digest(&sha_amounts_context.header, hashes->sha_amounts, 32);
        crypto_hash_digest(&sha_scriptpubkeys_context.header, hashes->sha_scriptpubkeys, 32);
    }

    return true;
}

static bool __attribute__((noinline)) sign_transaction_input(dispatcher_context_t *dc,
                                                             sign_psbt_state_t *st,
                                                             sign_psbt_cache_t *sign_psbt_cache,
                                                             segwit_hashes_t *hashes,
                                                             keyexpr_info_t *keyexpr_info,
                                                             input_info_t *input,
                                                             unsigned int cur_input_index) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // if the psbt does not specify the sighash flag for this input, the default
    // changes depending on the type of spend; therefore, we set it later.
    if (input->has_sighash_type) {
        // Get sighash type
        if (4 != call_get_merkleized_map_value_u32_le(dc,
                                                      &input->in_out.map,
                                                      (uint8_t[]){PSBT_IN_SIGHASH_TYPE},
                                                      1,
                                                      &input->sighash_type)) {
            PRINTF("Malformed PSBT_IN_SIGHASH_TYPE for input %d\n", cur_input_index);

            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    // Sign as segwit input iff it has a witness utxo
    if (!input->has_witnessUtxo) {
        LEDGER_ASSERT(keyexpr_info->key_expression_ptr->type == KEY_EXPRESSION_NORMAL,
                      "Only plain key expressions are valid for legacy inputs");
        // sign legacy P2PKH or P2SH

        // sign_non_witness(non_witness_utxo.vout[psbt.tx.input_[i].prevout.n].scriptPubKey, i)

        uint64_t tmp;  // unused
        if (0 > get_amount_scriptpubkey_from_psbt_nonwitness(dc,
                                                             &input->in_out.map,
                                                             &tmp,
                                                             input->in_out.scriptPubKey,
                                                             &input->in_out.scriptPubKey_len,
                                                             NULL)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        if (!input->has_sighash_type) {
            // legacy input default to SIGHASH_ALL
            input->sighash_type = SIGHASH_ALL;
        }

        uint8_t sighash[32];
        if (!compute_sighash_legacy(dc, st, input, cur_input_index, sighash)) return false;

        if (!sign_sighash_ecdsa_and_yield(dc, st, keyexpr_info, input, cur_input_index, sighash))
            return false;
    } else {
        {
            uint64_t amount;
            if (0 > get_amount_scriptpubkey_from_psbt_witness(dc,
                                                              &input->in_out.map,
                                                              &amount,
                                                              input->in_out.scriptPubKey,
                                                              &input->in_out.scriptPubKey_len)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            if (input->has_redeemScript) {
                // Get redeemScript
                // The redeemScript cannot be longer than standard scriptPubKeys for
                // wrapped segwit transactions that we support
                uint8_t redeemScript[MAX_PREVOUT_SCRIPTPUBKEY_LEN];

                int redeemScript_length =
                    call_get_merkleized_map_value(dc,
                                                  &input->in_out.map,
                                                  (uint8_t[]){PSBT_IN_REDEEM_SCRIPT},
                                                  1,
                                                  redeemScript,
                                                  sizeof(redeemScript));
                if (redeemScript_length < 0) {
                    PRINTF("Error fetching redeem script\n");
                    SEND_SW(dc, SW_INCORRECT_DATA);
                    return false;
                }

                uint8_t p2sh_redeemscript[2 + 20 + 1];
                p2sh_redeemscript[0] = 0xa9;
                p2sh_redeemscript[1] = 0x14;
                crypto_hash160(redeemScript, redeemScript_length, p2sh_redeemscript + 2);
                p2sh_redeemscript[22] = 0x87;

                if (input->in_out.scriptPubKey_len != 23 ||
                    memcmp(input->in_out.scriptPubKey, p2sh_redeemscript, 23) != 0) {
                    PRINTF("witnessUtxo's scriptPubKey does not match redeemScript\n");
                    SEND_SW_EC(dc, SW_INCORRECT_DATA, EC_SIGN_PSBT_MISMATCHING_REDEEM_SCRIPT);
                    return false;
                }

                input->script_len = redeemScript_length;
                memcpy(input->script, redeemScript, redeemScript_length);
            } else {
                input->script_len = input->in_out.scriptPubKey_len;
                memcpy(input->script, input->in_out.scriptPubKey, input->in_out.scriptPubKey_len);
            }
        }

        int segwit_version = get_policy_segwit_version(st->wallet_policy_map);
        uint8_t sighash[32];
        if (segwit_version == 0) {
            LEDGER_ASSERT(keyexpr_info->key_expression_ptr->type == KEY_EXPRESSION_NORMAL,
                          "Only plain key expressions are valid for SegwitV0 inputs");
            if (!input->has_sighash_type) {
                // segwitv0 inputs default to SIGHASH_ALL
                input->sighash_type = SIGHASH_ALL;
            }

            if (!compute_sighash_segwitv0(dc, st, hashes, input, cur_input_index, sighash))
                return false;

            if (!sign_sighash_ecdsa_and_yield(dc,
                                              st,
                                              keyexpr_info,
                                              input,
                                              cur_input_index,
                                              sighash))
                return false;
        } else if (segwit_version == 1) {
            if (!input->has_sighash_type) {
                // segwitv0 inputs default to SIGHASH_DEFAULT
                input->sighash_type = SIGHASH_DEFAULT;
            }

            if (!compute_sighash_segwitv1(dc,
                                          st,
                                          hashes,
                                          input,
                                          cur_input_index,
                                          keyexpr_info,
                                          sighash))
                return false;

            policy_node_tr_t *policy = (policy_node_tr_t *) st->wallet_policy_map;
            if (!keyexpr_info->is_tapscript && !isnull_policy_node_tree(&policy->tree)) {
                // keypath spend, we compute the taptree hash so that we find it ready
                // later in sign_sighash_schnorr_and_yield (which has less available stack).
                if (0 > compute_taptree_hash(
                            dc,
                            &(wallet_derivation_info_t){
                                .address_index = input->in_out.address_index,
                                .change = input->in_out.is_change ? 1 : 0,
                                .keys_merkle_root = st->wallet_header.keys_info_merkle_root,
                                .n_keys = st->wallet_header.n_keys,
                                .wallet_version = st->wallet_header.version,
                                .sign_psbt_cache = sign_psbt_cache},
                            r_policy_node_tree(&policy->tree),
                            input->taptree_hash)) {
                    PRINTF("Error while computing taptree hash\n");
                    SEND_SW(dc, SW_BAD_STATE);
                    return false;
                }
            }

            if (keyexpr_info->key_expression_ptr->type == KEY_EXPRESSION_NORMAL) {
                if (!sign_sighash_schnorr_and_yield(dc,
                                                    st,
                                                    keyexpr_info,
                                                    input,
                                                    cur_input_index,
                                                    sighash))
                    return false;
            } else if (keyexpr_info->key_expression_ptr->type == KEY_EXPRESSION_MUSIG) {
                if (!sign_sighash_musig_and_yield(dc,
                                                  st,
                                                  keyexpr_info,
                                                  input,
                                                  cur_input_index,
                                                  sighash))
                    return false;
            } else {
                LEDGER_ASSERT(false, "Unreachable");
            }

        } else {
            SEND_SW(dc, SW_BAD_STATE);  // can't happen
            return false;
        }
    }
    return true;
}

static bool __attribute__((noinline))
fill_taproot_keyexpr_info(dispatcher_context_t *dc,
                          sign_psbt_state_t *st,
                          const input_info_t *input,
                          const policy_node_t *tapleaf_ptr,
                          keyexpr_info_t *keyexpr_info,
                          sign_psbt_cache_t *sign_psbt_cache) {
    cx_sha256_t hash_context;
    crypto_tr_tapleaf_hash_init(&hash_context);

    wallet_derivation_info_t wdi = {.wallet_version = st->wallet_header.version,
                                    .keys_merkle_root = st->wallet_header.keys_info_merkle_root,
                                    .n_keys = st->wallet_header.n_keys,
                                    .change = input->in_out.is_change,
                                    .address_index = input->in_out.address_index,
                                    .sign_psbt_cache = sign_psbt_cache};

    // we compute the tapscript once just to compute its length
    // this avoids having to store it
    int tapscript_len =
        get_wallet_internal_script_hash(dc, tapleaf_ptr, &wdi, WRAPPED_SCRIPT_TYPE_TAPSCRIPT, NULL);
    if (tapscript_len < 0) {
        PRINTF("Failed to compute tapleaf script\n");
        return false;
    }

    crypto_hash_update_u8(&hash_context.header, 0xC0);
    crypto_hash_update_varint(&hash_context.header, tapscript_len);

    // we compute it again to get add the actual script code to the hash computation
    if (0 > get_wallet_internal_script_hash(dc,
                                            tapleaf_ptr,
                                            &wdi,
                                            WRAPPED_SCRIPT_TYPE_TAPSCRIPT,
                                            &hash_context.header)) {
        return false;  // should never happen!
    }
    crypto_hash_digest(&hash_context.header, keyexpr_info->tapleaf_hash, 32);

    return true;
}

static bool __attribute__((noinline))
sign_transaction(dispatcher_context_t *dc,
                 sign_psbt_state_t *st,
                 sign_psbt_cache_t *sign_psbt_cache,
                 const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    int key_expression_index = 0;

    segwit_hashes_t hashes;

    // compute all the tx-wide hashes
    // while this is redundant for legacy transactions, we do it here in order to
    // avoid doing it in places that have more stack limitations
    if (!compute_segwit_hashes(dc, st, &hashes)) {
        // we do not send a status word, since compute_segwit_hashes already does it on failure
        return false;
    }

    // Iterate over all the key expressions that correspond to keys owned by us
    while (true) {
        keyexpr_info_t keyexpr_info;
        memset(&keyexpr_info, 0, sizeof(keyexpr_info));

        const policy_node_t *tapleaf_ptr = NULL;
        int n_key_expressions = get_keyexpr_by_index(st->wallet_policy_map,
                                                     key_expression_index,
                                                     &tapleaf_ptr,
                                                     &keyexpr_info.key_expression_ptr);

        if (n_key_expressions < 0) {
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            return false;
        }

        if (key_expression_index >= n_key_expressions) {
            // all key expressions were processed
            break;
        }

        if (tapleaf_ptr != NULL) {
            // get_keyexpr_by_index returns the pointer to the tapleaf only if the key being
            // spent is indeed in a tapleaf
            keyexpr_info.is_tapscript = true;
        }

        if (fill_keyexpr_info_if_internal(dc, st, &keyexpr_info) == true) {
            for (unsigned int i = 0; i < st->n_inputs; i++)
                if (bitvector_get(internal_inputs, i)) {
                    input_info_t input;
                    memset(&input, 0, sizeof(input));

                    input_keys_callback_data_t callback_data = {.input = &input,
                                                                .keyexpr_info = &keyexpr_info};
                    int res = call_get_merkleized_map_with_callback(
                        dc,
                        (void *) &callback_data,
                        st->inputs_root,
                        st->n_inputs,
                        i,
                        (merkle_tree_elements_callback_t) input_keys_callback,
                        &input.in_out.map);
                    if (res < 0) {
                        SEND_SW(dc, SW_INCORRECT_DATA);
                        return false;
                    }

                    if (tapleaf_ptr != NULL && !fill_taproot_keyexpr_info(dc,
                                                                          st,
                                                                          &input,
                                                                          tapleaf_ptr,
                                                                          &keyexpr_info,
                                                                          sign_psbt_cache)) {
                        return false;
                    }

                    if (!sign_transaction_input(dc,
                                                st,
                                                sign_psbt_cache,
                                                &hashes,
                                                &keyexpr_info,
                                                &input,
                                                i)) {
                        // we do not send a status word, since sign_transaction_input
                        // already does it on failure
                        return false;
                    }
                }
        }

        ++key_expression_index;
    }

    return true;
}

void handler_sign_psbt(dispatcher_context_t *dc, uint8_t protocol_version) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    sign_psbt_state_t st;
    memset(&st, 0, sizeof(st));

    st.protocol_version = protocol_version;

    // read APDU inputs, intialize global state and read global PSBT map
    if (!init_global_state(dc, &st)) return;

    sign_psbt_cache_t cache;
    init_sign_psbt_cache(&cache);

    // bitmap to keep track of which inputs are internal
    uint8_t internal_inputs[BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)];
    memset(internal_inputs, 0, sizeof(internal_inputs));

    // bitmap to keep track of which inputs are internal
    uint8_t internal_outputs[BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)];
    memset(internal_outputs, 0, sizeof(internal_outputs));

    /** Inputs verification flow
     *
     *  Go though all the inputs:
     *  - verify the non_witness_utxo
     *  - compute value spent
     *  - detect internal inputs that should be signed, and if there are external inputs or unusual
     * sighashes
     */
    if (!preprocess_inputs(dc, &st, &cache, internal_inputs)) return;

    /** OUTPUTS VERIFICATION FLOW
     *
     *  For each output, check if it's a change address.
     *  Check if it's an acceptable output.
     */
    if (!preprocess_outputs(dc, &st, &cache, internal_outputs)) return;

    if (G_swap_state.called_from_swap) {
        /** SWAP CHECKS
         *
         *  If called from the exchange app, perform the necessary additional checks.
         */

        // During swaps, the user approval was already obtained in the exchange app
        if (!execute_swap_checks(dc, &st)) return;
    } else {
        /** TRANSACTION CONFIRMATION
         *
         *  Display each non-change output, and transaction fees, and acquire user confirmation,
         */
        if (!display_transaction(dc, &st, internal_outputs)) return;
    }

    // Signing always takes some time, so we rather not wait before showing the spinner
    io_show_processing_screen();

    /** SIGNING FLOW
     *
     * For each internal key expression, and for each internal input, sign using the
     * appropriate algorithm.
     */
    int sign_result = sign_transaction(dc, &st, &cache, internal_inputs);

    if (!G_swap_state.called_from_swap) {
        ui_post_processing_confirm_transaction(dc, sign_result);
    }

    if (!sign_result) {
        return;
    }

    // Only if called from swap, the app should terminate after sending the response
    if (G_swap_state.called_from_swap) {
        G_swap_state.should_exit = true;
    }

    SEND_SW(dc, SW_OK);
}
