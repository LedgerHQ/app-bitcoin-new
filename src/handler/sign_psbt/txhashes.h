#pragma once

#include "../boilerplate/dispatcher.h"
#include "../sign_psbt.h"

/**
 * @brief Computes the transaction hashes required for signing.
 *
 * @param[in] dc Pointer to the dispatcher context.
 * @param[in] st Pointer to the sign_psbt state.
 * @param[out] hashes Pointer to the structure where the computed hashes will be stored.
 * @return true if the computation is successful, false otherwise.
 */
bool __attribute__((noinline))
compute_tx_hashes(dispatcher_context_t *dc, sign_psbt_state_t *st, tx_hashes_t *hashes);

/**
 * @brief Computes the legacy sighash for a given input.
 *
 * @param[in] dc Pointer to the dispatcher context.
 * @param[in] st Pointer to the sign_psbt state.
 * @param[in] input Pointer to the input information.
 * @param[in] input_index Index of the input for which the sighash is being computed.
 * @param[out] sighash Array where the computed sighash will be stored (must be at least 32 bytes).
 * @return true if the computation is successful, false otherwise.
 */
bool __attribute__((noinline)) compute_sighash_legacy(dispatcher_context_t *dc,
                                                      const sign_psbt_state_t *st,
                                                      const input_info_t *input,
                                                      unsigned int input_index,
                                                      uint8_t sighash[static 32]);

/**
 * @brief Computes the SegWit v0 sighash for a given input.
 *
 * @param[in] dc Pointer to the dispatcher context.
 * @param[in] st Pointer to the sign_psbt state.
 * @param[in] hashes Pointer to the structure containing the precomputed transaction hashes.
 * @param[in] input Pointer to the input information.
 * @param[in] input_index Index of the input for which the sighash is being computed.
 * @param[out] sighash Array where the computed sighash will be stored (must be at least 32 bytes).
 * @return true if the computation is successful, false otherwise.
 */
bool __attribute__((noinline)) compute_sighash_segwitv0(dispatcher_context_t *dc,
                                                        const sign_psbt_state_t *st,
                                                        const tx_hashes_t *hashes,
                                                        const input_info_t *input,
                                                        unsigned int input_index,
                                                        uint8_t sighash[static 32]);

/**
 * Computes the SegWit v1 (Taproot) sighash for a given input.
 *
 * @param[in] dc Pointer to the dispatcher context.
 * @param[in] st Pointer to the sign_psbt state.
 * @param[in] hashes Pointer to the structure containing the precomputed transaction hashes.
 * @param[in] input Pointer to the input information.
 * @param[in] input_index Index of the input for which the sighash is being computed.
 * @param[in] tapleaf_hash Array containing the Taproot leaf hash. It must be NULL if spending using
 * the key path; otherwise, it is a pointer to a 32-byte array.
 * @param[out] sighash Array where the computed sighash will be stored (must be at least 32 bytes).
 * @return true if the computation is successful, false otherwise.
 */
bool __attribute__((noinline)) compute_sighash_segwitv1(dispatcher_context_t *dc,
                                                        const sign_psbt_state_t *st,
                                                        const tx_hashes_t *hashes,
                                                        const input_info_t *input,
                                                        unsigned int input_index,
                                                        const uint8_t *tapleaf_hash,
                                                        uint8_t sighash[static 32]);
