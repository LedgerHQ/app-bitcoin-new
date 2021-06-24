#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/wallet.h"

/**
 * Convenience structure to optimize the size of parameters passed to a recursive function.
 */
typedef struct {
    dispatcher_context_t *dispatcher_context;
    const uint8_t *keys_merkle_root;
    uint32_t n_keys;
    bool change;
    size_t address_index;
} _policy_parser_args_t;


/**
 * TODO
 */
int _call_get_wallet_address(_policy_parser_args_t *args, policy_node_t *policy, char *out_ptr, size_t out_ptr_len);


/**
 * TODO
 */
int _call_get_wallet_script(_policy_parser_args_t *args,
                            policy_node_t *policy,
                            buffer_t *out_buf,
                            cx_hash_t *hash_context);


/**
 * TODO
 */
static inline int call_get_wallet_address(dispatcher_context_t *dispatcher_context,
                                          policy_node_t *policy,
                                          const uint8_t keys_merkle_root[static 20],
                                          uint32_t n_keys,
                                          bool change,
                                          size_t address_index,
                                          char *out_ptr,
                                          size_t out_ptr_len)
{
    _policy_parser_args_t args = {
        .dispatcher_context = dispatcher_context,
        .keys_merkle_root = keys_merkle_root,
        .n_keys = n_keys,
        .change = change,
        .address_index = address_index
    };
    return _call_get_wallet_address(&args, policy, out_ptr, out_ptr_len);
}


/**
 * TODO
 */
static inline int call_get_wallet_script(dispatcher_context_t *dispatcher_context,
                                         policy_node_t *policy,
                                         const uint8_t keys_merkle_root[static 20],
                                         uint32_t n_keys,
                                         bool change,
                                         size_t address_index,
                                         buffer_t *out_buf,
                                         cx_hash_t *hash_context)
{
    _policy_parser_args_t args = {
        .dispatcher_context = dispatcher_context,
        .keys_merkle_root = keys_merkle_root,
        .n_keys = n_keys,
        .change = change,
        .address_index = address_index
    };
    return _call_get_wallet_script(&args, policy, out_buf, hash_context);
}

