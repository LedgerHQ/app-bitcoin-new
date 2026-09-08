/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2025, 2026 Ledger SAS.
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

#pragma once

/* Local headers */
#include "dispatcher.h"
#include "sign_psbt.h"

// These functions are used to extract the amount and scriptPubKey of an input from the witness-utxo
// or the non-witness-utxo of a PSBTv2.

/*
 Gets the amount and scriptpubkey of output prevout_n of the non-witness-utxo found in the given
 input map of a PSBTv2. The output index is given explicitly, so that the non-witness-utxo can be
 that of a different input than the one being processed (which BIP-322 allows for proof of funds).
 If expected_prevout_hash is not NULL, the function fails if the txid computed from the
 non-witness-utxo does not match the one pointed by expected_prevout_hash. Returns -1 on failure, 0
 on success.
*/
int __attribute__((noinline)) get_amount_scriptpubkey_from_psbt_nonwitness_output(
    dispatcher_context_t *dc,
    const merkleized_map_commitment_t *input_map,
    uint32_t prevout_n,
    uint64_t *amount,
    uint8_t scriptPubKey[static MAX_PREVOUT_SCRIPTPUBKEY_LEN],
    size_t *scriptPubKey_len,
    const uint8_t *expected_prevout_hash);

/*
 Convenience function to get the amount and scriptpubkey from the non-witness-utxo of a certain
 input in a PSBTv2.
 If expected_prevout_hash is not NULL, the function fails if the txid computed from the
 non-witness-utxo does not match the one pointed by expected_prevout_hash. Returns -1 on failure, 0
 on success.
*/
int __attribute__((noinline)) get_amount_scriptpubkey_from_psbt_nonwitness(
    dispatcher_context_t *dc,
    const merkleized_map_commitment_t *input_map,
    uint64_t *amount,
    uint8_t scriptPubKey[static MAX_PREVOUT_SCRIPTPUBKEY_LEN],
    size_t *scriptPubKey_len,
    const uint8_t *expected_prevout_hash);

/*
 Convenience function to get the amount and scriptpubkey from the witness-utxo of a certain input in
 a PSBTv2.
 Returns -1 on failure, 0 on success.
*/
int __attribute__((noinline)) get_amount_scriptpubkey_from_psbt_witness(
    dispatcher_context_t *dc,
    const merkleized_map_commitment_t *input_map,
    uint64_t *amount,
    uint8_t scriptPubKey[static MAX_PREVOUT_SCRIPTPUBKEY_LEN],
    size_t *scriptPubKey_len);

/*
 Convenience function to get the amount and scriptpubkey of a certain input in a PSBTv2.
 It first tries to obtain it from the witness-utxo field; in case of failure, it then obtains it
 from the non-witness-utxo.
 Returns -1 on failure, 0 on success.
*/
int get_amount_scriptpubkey_from_psbt(dispatcher_context_t *dc,
                                      const merkleized_map_commitment_t *input_map,
                                      uint64_t *amount,
                                      uint8_t scriptPubKey[static MAX_PREVOUT_SCRIPTPUBKEY_LEN],
                                      size_t *scriptPubKey_len);

/*
 Like get_amount_scriptpubkey_from_psbt_nonwitness, but for a BIP-322 message signing request it
 also accepts a non-witness-utxo omitted from the input's own map, as BIP-322 allows for a
 proof-of-funds input "that spends an output from the same transaction as an input earlier in the
 list": the non-witness-utxo is then looked up in the preceding inputs spending the same
 transaction (which are consecutive, as the app requires the proof-of-funds inputs to be in BIP-69
 order), and must hash to the input's own prevout txid.
 expected_prevout_hash only applies to the input's own non-witness-utxo, as above.
 Returns -1 on failure, 0 on success.
*/
int __attribute__((noinline)) get_amount_scriptpubkey_from_psbt_nonwitness_shared(
    dispatcher_context_t *dc,
    const sign_psbt_state_t *st,
    unsigned int input_index,
    const merkleized_map_commitment_t *input_map,
    uint64_t *amount,
    uint8_t scriptPubKey[static MAX_PREVOUT_SCRIPTPUBKEY_LEN],
    size_t *scriptPubKey_len,
    const uint8_t *expected_prevout_hash);

/*
 Like get_amount_scriptpubkey_from_psbt, but using
 get_amount_scriptpubkey_from_psbt_nonwitness_shared for the non-witness-utxo. Returns -1 on
 failure, 0 on success.
*/
int get_amount_scriptpubkey_from_psbt_shared(
    dispatcher_context_t *dc,
    const sign_psbt_state_t *st,
    unsigned int input_index,
    const merkleized_map_commitment_t *input_map,
    uint64_t *amount,
    uint8_t scriptPubKey[static MAX_PREVOUT_SCRIPTPUBKEY_LEN],
    size_t *scriptPubKey_len);
