#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/wallet.h"

/**
 * The label used to derive the symmetric key used to register/verify wallet policies on device.
 */
#define WALLET_SLIP0021_LABEL "\0LEDGER-Wallet policy"
#define WALLET_SLIP0021_LABEL_LEN \
    (sizeof(WALLET_SLIP0021_LABEL) - 1)  // sizeof counts the terminating 0

/**
 * Computes the script corresponding to a wallet policy, for a certain change and address index.
 *
 * @param[in] dispatcher_context
 *   Pointer to the dispatcher context
 * @param[in] policy
 *   Pointer to the root node of the policy
 * @param[in] keys_merkle_root
 *   The Merkle root of the tree of key informations in the policy
 * @param[in] n_keys
 *   The number of key information placeholders in the policy
 * @param[in] change
 *   0 for a receive address, 1 for a change address
 * @param[in] address_index
 *   The address index
 * @param[in] out_buf
 *   A buffer to contain the script. If the available space in the buffer is not enough, the result
 * is truncated, but the correct length is still returned in case of success.
 *
 * @return The length of the output on success; -1 in case of error.
 *
 */
int call_get_wallet_script(dispatcher_context_t *dispatcher_context,
                           const policy_node_t *policy,
                           const uint8_t keys_merkle_root[static 32],
                           uint32_t n_keys,
                           bool change,
                           size_t address_index,
                           buffer_t *out_buf);

/**
 * Returns the address type constant corresponding to a standard policy type.
 *
 * @param[in] policy
 *   Pointer to the root node of the policy
 *
 * @return One of, ADDRESS_TYPE_LEGACY, ADDRESS_TYPE_WIT, ADDRESS_TYPE_SH_WIT, ADDRESS_TYPE_TR if
 * the policy pattern is one of the expected types; -1 otherwise.
 */
int get_policy_address_type(const policy_node_t *policy);

/**
 * Verifies if the wallet_hmac is correct for the given wallet_id, using the symmetric key derived
 * with the WALLET_SLIP0021_LABEL label according to SLIP-0021.
 *
 * @param[in] policy
 *   Pointer to the root node of the policy
 * @param[in] policy
 *   Pointer to the root node of the policy

 * @return true if the given hmac is valid, false otherwise.
 */
bool check_wallet_hmac(const uint8_t wallet_id[static 32], const uint8_t wallet_hmac[static 32]);