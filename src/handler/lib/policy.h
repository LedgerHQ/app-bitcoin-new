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
 * Parses a serialized wallet policy, saving the wallet header, the policy map descriptor and the
 * policy descriptor. Then, it parses the descriptor into the Abstract Syntax Tree into the
 * policy_map_bytes array.
 *
 * It returns -1 if any error occurs.
 *
 * @param dispatcher_context Pointer to the dispatcher content
 * @param buf Pointer to the buffer from which the serialized policy is read from
 * @param wallet_header Pointer to policy_map_wallet_header_t that will receive the policy map
 * header
 * @param policy_map_descriptor Pointer to a buffer of MAX_WALLET_POLICY_STR_LENGTH bytes that will
 * contain the descriptor template as a string
 * @param policy_map_bytes Pointer to an array of bytes that will be used for the parsed abstract
 * syntax tree
 * @param policy_map_bytes_len Length of policy_map_bytes in bytes.
 * @return 0 on success, a negative number in case of error.
 */
// TODO: we should distinguish actual errors from just "policy too big to fit in memory"
int read_and_parse_wallet_policy(dispatcher_context_t *dispatcher_context,
                                 buffer_t *buf,
                                 policy_map_wallet_header_t *wallet_header,
                                 uint8_t policy_map_descriptor[static MAX_WALLET_POLICY_STR_LENGTH],
                                 uint8_t *policy_map_bytes,
                                 size_t policy_map_bytes_len);

/**
 * Computes the script corresponding to a wallet policy, for a certain change and address index.
 *
 * @param[in] dispatcher_context
 *   Pointer to the dispatcher context
 * @param[in] policy
 *   Pointer to the root node of the policy
 * @param[in] wallet_version
 *   The wallet policy version, either WALLET_POLICY_VERSION_V1 or WALLET_POLICY_VERSION_V2
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
                           int wallet_version,
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
 * @param[in] wallet_id
 *   Pointer to the a 32-bytes array containing the 32-byte wallet policy id.
 * @param[in] wallet_hmac
 *   Pointer to the a 32-bytes array containing the wallet policy registration hmac.
 * @return true if the given hmac is valid, false otherwise.
 */
bool check_wallet_hmac(const uint8_t wallet_id[static 32], const uint8_t wallet_hmac[static 32]);

/**
 * Copies the i-th placeholder (indexing from 0) of the given policy into `out_placeholder` (if not
 * null).
 *
 * @param[in] policy
 *   Pointer to the root node of the policy
 * @param[in] i
 *   Index of the wanted placeholder. Ignored if out_placeholder is NULL.
 * @param[out] out_placeholder
 *   If not NULL, it is a pointer that will receive the i-th placeholder of the policy.
 * @return the number of placeholders in the policy on success; -1 in case of error.
 */
int get_key_placeholder_by_index(const policy_node_t *policy,
                                 unsigned int i,
                                 policy_node_key_placeholder_t *out_placeholder);