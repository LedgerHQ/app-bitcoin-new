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
 * TODO
 */
int call_get_wallet_script(dispatcher_context_t *dispatcher_context,
                           policy_node_t *policy,
                           const uint8_t keys_merkle_root[static 32],
                           uint32_t n_keys,
                           bool change,
                           size_t address_index,
                           buffer_t *out_buf,
                           cx_hash_t *hash_context);

/**
 * TODO
 */
int get_policy_address_type(policy_node_t *policy);

/**
 * Verifies if the wallet_hmac is correct for the given wallet_id, using the symmetric key derived
 * with the WALLET_SLIP0021_LABEL label according to SLIP-0021. Returns true/false accordingly.
 */
bool check_wallet_hmac(uint8_t wallet_id[static 32], uint8_t wallet_hmac[static 32]);