#pragma once

#include "../boilerplate/dispatcher.h"
#include "../sign_psbt.h"

// These functions are used to extract the amount and scriptPubKey of an input from the witness-utxo
// or the non-witness-utxo of a PSBTv2.

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
int __attribute__((noinline))
get_amount_scriptpubkey_from_psbt_witness(dispatcher_context_t *dc,
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
