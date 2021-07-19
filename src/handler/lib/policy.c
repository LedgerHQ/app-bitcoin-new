#include <stdlib.h>

#include "policy.h"

#include "../lib/get_merkle_leaf_element.h"
#include "../../crypto.h"
#include "../../common/base58.h"
#include "../../common/segwit_addr.h"
#include "../../types.h"

/**
 * Convenience structure to optimize the size of parameters passed to a recursive function.
 */
typedef struct {
    dispatcher_context_t *dispatcher_context;
    const uint8_t *keys_merkle_root;
    uint32_t n_keys;
    bool change;
    size_t address_index;
    buffer_t *mem;
} _policy_parser_args_t;


extern global_context_t G_context;

// comparator for pointers to compressed pubkeys
static int cmp_compressed_pubkeys(const void *a, const void *b) {
    const uint8_t **key_a = (const uint8_t **)a;
    const uint8_t **key_b = (const uint8_t **)b;
    for (int i = 0; i < 33; i++) {
        int diff = (*key_a)[i] - (*key_b)[i];
        if (diff != 0) {
            return diff;
        }
    }
    return 0;
}


static void update_output(buffer_t *out_buf_ptr, cx_hash_t *hash_context, const uint8_t *data, size_t data_len) {
    if (out_buf_ptr != NULL) {
        buffer_write_bytes(out_buf_ptr, data, data_len);
    }

    if (hash_context != NULL) {
        crypto_hash_update(hash_context, data, data_len);
    }
}


static void update_output_u8(buffer_t *out_buf_ptr, cx_hash_t *hash_context, const uint8_t data) {
    update_output(out_buf_ptr, hash_context, &data, 1);
}


// Returns true iff the type corresponds to a script that is known to be at most 34 bytes.
// Used for some memory optimizations when computing script hashes (e.g. for `sh(wsh(...))` policies).
static bool is_script_type_short(PolicyNodeType type) {
    return (   type == TOKEN_PKH
            || type == TOKEN_WPKH
            || type == TOKEN_SH
            || type == TOKEN_WSH);
}

// p2pkh                     ==> legacy address (start with 1 on mainnet, m or n on testnet)
// p2sh (also nested segwit) ==> legacy script  (start with 3 on mainnet, 2 on testnet)
// p2wpkh or p2wsh           ==> bech32         (sart with bc1 on mainnet, tb1 on testnet)


static int get_derived_pubkey(_policy_parser_args_t *args,
                              int key_index,
                              uint8_t out[static 33])
{
    policy_map_key_info_t key_info;

    { // make sure memory is freed as soon as possible
        char key_info_str[MAX_POLICY_KEY_INFO_LEN];

        int key_info_len = call_get_merkle_leaf_element(args->dispatcher_context,
                                                        args->keys_merkle_root,
                                                        args->n_keys,
                                                        key_index,
                                                        (uint8_t *)key_info_str,
                                                        sizeof(key_info_str));
        if (key_info_len == -1){
            return -1;
        }


        // Make a sub-buffer for the pubkey info
        buffer_t key_info_buffer = buffer_create(key_info_str, key_info_len);

        if (parse_policy_map_key_info(&key_info_buffer, &key_info) == -1) {
            return -1;
        }
    }

    // decode pubkey
    serialized_extended_pubkey_check_t decoded_pubkey_check;
    if (base58_decode(key_info.ext_pubkey, strlen(key_info.ext_pubkey), (uint8_t *)&decoded_pubkey_check, sizeof(decoded_pubkey_check)) == -1) {
        return -1;
    }
    // TODO: validate checksum

    serialized_extended_pubkey_t *ext_pubkey = &decoded_pubkey_check.serialized_extended_pubkey;

    if (key_info.has_wildcard) {
        // we derive the /0/i child of this pubkey
        // we reuse the same memory of ext_pubkey
        bip32_CKDpub(ext_pubkey, args->change, ext_pubkey);
        bip32_CKDpub(ext_pubkey, args->address_index, ext_pubkey);
    }

    memcpy(out, ext_pubkey->compressed_pubkey, 33);

    return 0;
}


// forward-declaration
int _call_get_wallet_script(_policy_parser_args_t *args,
                            policy_node_t *policy,
                            buffer_t *out_buf,
                            cx_hash_t *hash_context);


static int get_pkh_wpkh_script(_policy_parser_args_t *args,
                                      policy_node_t *policy,
                                      buffer_t *out_buf,
                                      cx_hash_t *hash_context)
{
    policy_node_with_key_t *root = (policy_node_with_key_t *)policy;

    unsigned int out_len;
    if (policy->type == TOKEN_PKH) {
        out_len = 3 + 20 + 2;
    } else {
        out_len = 2 + 20;
    }
    if (out_buf != NULL && !buffer_can_read(out_buf, out_len)) {
        return -1;
    }

    int result;
    buffer_snapshot_t snap = buffer_snapshot(args->mem);

    // memory block taking 33 bytes
    {
        uint8_t *compressed_pubkey = (uint8_t *)buffer_alloc(args->mem, 33);

        if (compressed_pubkey == NULL) {
            result = -1;
        } else if (-1 == get_derived_pubkey(args, root->key_index, compressed_pubkey)) {
            result = -1;
        } else if (policy->type == TOKEN_PKH) {
            update_output_u8(out_buf, hash_context, 0x76);
            update_output_u8(out_buf, hash_context, 0xa9);
            update_output_u8(out_buf, hash_context, 0x14);

            crypto_hash160(compressed_pubkey, 33, compressed_pubkey); // reuse memory
            update_output(out_buf, hash_context, compressed_pubkey, 20);

            update_output_u8(out_buf, hash_context, 0x88);
            update_output_u8(out_buf, hash_context, 0xac);

            result = 3 + 20 + 2;
        } else { // policy->type == TOKEN_WPKH
            update_output_u8(out_buf, hash_context, 0x00);
            update_output_u8(out_buf, hash_context, 0x14);

            crypto_hash160(compressed_pubkey, 33, compressed_pubkey); // reuse memory
            update_output(out_buf, hash_context, compressed_pubkey, 20);

            result = 2 + 20;
        }
    }
    buffer_restore(args->mem, snap);
    return result;
}

static int get_sh_wsh_script(_policy_parser_args_t *args,
                                      policy_node_t *policy,
                                      buffer_t *out_buf,
                                      cx_hash_t *hash_context)
{
    policy_node_with_script_t *root = (policy_node_with_script_t *)policy;

    uint8_t *script_hash;

    int result;
    buffer_snapshot_t snap = buffer_snapshot(args->mem);

    // memory block; will take up to:
    // - sizeof(cx_sha256_t) + 32 = 108 + 32 = 140 bytes if the inner script is long/unknown
    // - 34 + 32 = 66 bytes for known standard scripts
    do {
        // Memory optimization: as the script_hash_context is expensive (>100 bytes), if we know that the internal
        // script is short, we are better off computing the full internal script (rather than its hash).
        if (is_script_type_short(root->script->type)) {
            uint8_t *internal_script = buffer_alloc(args->mem, 34);
            if (internal_script == NULL) {
                result = -1;
                break;
            }

            buffer_t internal_script_buf = buffer_create(internal_script, 34);

            int internal_script_len = _call_get_wallet_script(args,
                                                                root->script,
                                                                &internal_script_buf,
                                                                NULL);
            if (internal_script_len == -1) {
                result = -1;
                break;
            }

            script_hash = (uint8_t *)buffer_alloc(args->mem, 32); // sha256 of the script
            if (script_hash == NULL) {
                result = -1;
                break;
            }

            cx_hash_sha256(internal_script, internal_script_len, script_hash, 32);
        } else {
            cx_sha256_t *script_hash_context = (cx_sha256_t *)buffer_alloc(args->mem, sizeof(cx_sha256_t));
            if (script_hash_context == NULL) {
                result = -1;
                break;
            }

            cx_sha256_init(script_hash_context);

            int res = _call_get_wallet_script(args, root->script, NULL, &script_hash_context->header);
            if (res == -1) {
                result = -1;
                break;
            }

            script_hash = (uint8_t *)buffer_alloc(args->mem, 32); // sha256 of the script
            if (script_hash == NULL) {
                result = -1;
                break;
            }

            crypto_hash_digest(&script_hash_context->header, script_hash, 32);
        }


        if (policy->type == TOKEN_SH) {
            update_output_u8(out_buf, hash_context, 0xa9);
            update_output_u8(out_buf, hash_context, 0x14);

            crypto_ripemd160(script_hash, 32, script_hash); // reuse memory
            update_output(out_buf, hash_context, script_hash, 20);

            update_output_u8(out_buf, hash_context, 0x87);

            result = 2 + 20 + 1;
        } else { // policy->type == TOKEN_WSH
            update_output_u8(out_buf, hash_context, 0x00);
            update_output_u8(out_buf, hash_context, 0x20);

            update_output(out_buf, hash_context, script_hash, 32);

            result = 2 + 32;
        }
    } while (false);

    buffer_restore(args->mem, snap);
    return result;
}


int get_multi_script(_policy_parser_args_t *args,
                     policy_node_t *policy,
                     buffer_t *out_buf,
                     cx_hash_t *hash_context)
{
    policy_node_multisig_t *root = (policy_node_multisig_t *)policy;

    // k {pubkey_1} ... {pubkey_n} n OP_CHECKMULTISIG
    unsigned int out_len = 1 + 34 * root->n + 1 + 1;

    if (out_buf != NULL && !buffer_can_read(out_buf, out_len)) {
        return -1;
    }

    update_output_u8(out_buf, hash_context, 0x50 + root->k); // OP_k

    int result = 0;
    buffer_snapshot_t snap = buffer_snapshot(args->mem);

    do {
        uint8_t *compressed_pubkey = (uint8_t *)buffer_alloc(args->mem, 33);
        if (compressed_pubkey == NULL) {
            result = -1;
            break;
        }

        for (unsigned int i = 0; i < root->n; i++) {
            if (-1 == get_derived_pubkey(args, root->key_indexes[i], compressed_pubkey)) {
                result = -1;
                break;
            }
            // push <i-th pubkey> (33 = 0x21 bytes)
            update_output_u8(out_buf, hash_context, 0x21);
            update_output(out_buf, hash_context, compressed_pubkey, 33);
        }
        if (result == -1) {
            break;
        }

        update_output_u8(out_buf, hash_context, 0x50 + root->n); // OP_n
        update_output_u8(out_buf, hash_context, 0xae);           // OP_CHECKMULTISIG

        result = out_len;
    } while (false);

    buffer_restore(args->mem, snap);
    return result;
}

int get_sortedmulti_script(_policy_parser_args_t *args,
                           policy_node_t *policy,
                           buffer_t *out_buf,
                           cx_hash_t *hash_context)
{
    policy_node_multisig_t *root = (policy_node_multisig_t *)policy;

    // TODO: replace with the maximum we can afford
    if (root->n > 5) {
        return -1;
    }

    // k {pubkey_1} ... {pubkey_n} n OP_CHECKMULTISIG
    unsigned int out_len = 1 + 34 * root->n + 1 + 1;

    if (out_buf != NULL && !buffer_can_read(out_buf, out_len)) {
        return -1;
    }

    update_output_u8(out_buf, hash_context, 0x50 + root->k); // OP_k


    // total size occupation n * (4 + 33)
    //   = 185 for n = 5.

    int result = 0;
    buffer_snapshot_t snap = buffer_snapshot(args->mem);

    do {
        uint8_t **compressed_pubkeys = (uint8_t **)buffer_alloc(args->mem, root->n * sizeof(uint8_t *));
        if (compressed_pubkeys == NULL) {
            result = -1;
            break;
        }

        // allocate space for, and derive each key
        for (unsigned int i = 0; i < root->n; i++) {
            compressed_pubkeys[i] = (uint8_t *)buffer_alloc(args->mem, 33);
            if (compressed_pubkeys[i] == NULL) {
                result = -1;
                break;
            }

            if (-1 == get_derived_pubkey(args, root->key_indexes[i], compressed_pubkeys[i])) {
                result = -1;
                break;
            }
        }
        if (result == -1) {
            break;
        }

        // sort the pubkeys
        qsort(compressed_pubkeys, root->n, sizeof(uint8_t *), cmp_compressed_pubkeys);

        for (unsigned int i = 0; i < root->n; i++) {
            // push <i-th pubkey> (33 = 0x21 bytes)
            update_output_u8(out_buf, hash_context, 0x21);
            update_output(out_buf, hash_context, compressed_pubkeys[i], 33);
        }

        update_output_u8(out_buf, hash_context, 0x50 + root->n); // OP_n
        update_output_u8(out_buf, hash_context, 0xae);           // OP_CHECKMULTISIG

        result = out_len;
    } while (false);

    buffer_restore(args->mem, snap);
    return result;
}

int _call_get_wallet_script(_policy_parser_args_t *args,
                            policy_node_t *policy,
                            buffer_t *out_buf,
                            cx_hash_t *hash_context)
{
    switch (policy->type) {
        case TOKEN_PKH:
        case TOKEN_WPKH:
            return get_pkh_wpkh_script(args, policy, out_buf, hash_context);
        case TOKEN_SH:
        case TOKEN_WSH:
            return get_sh_wsh_script(args, policy, out_buf, hash_context);
        case TOKEN_MULTI:
            return get_multi_script(args, policy, out_buf, hash_context);
        case TOKEN_SORTEDMULTI:
            return get_sortedmulti_script(args, policy, out_buf, hash_context);
        default:
            return -1;
    }
}

int call_get_wallet_script(dispatcher_context_t *dispatcher_context,
                           policy_node_t *policy,
                           const uint8_t keys_merkle_root[static 20],
                           uint32_t n_keys,
                           bool change,
                           size_t address_index,
                           buffer_t *out_buf,
                           cx_hash_t *hash_context)
{
    // Estimated worst case memory used for sh(wsh(sortedmulti(5, ...)))
    //   34 + 108 + 5 * 37 = 327
    //   

    uint8_t mem[328];
    buffer_t mem_buf = buffer_create(mem, sizeof(mem));

    _policy_parser_args_t args = {
        .dispatcher_context = dispatcher_context,
        .keys_merkle_root = keys_merkle_root,
        .n_keys = n_keys,
        .change = change,
        .address_index = address_index,
        .mem = &mem_buf
    };
    return _call_get_wallet_script(&args, policy, out_buf, hash_context);
}

int get_policy_address_type(policy_node_t *policy) {
    // legacy, native segwit or wrapped segwit
    switch (policy->type) {
        case TOKEN_PKH:
            return ADDRESS_TYPE_LEGACY;
        case TOKEN_WPKH:
            return ADDRESS_TYPE_WIT;
        case TOKEN_SH:
            // wrapped segwit
            if (((policy_node_with_script_t *)policy)->script->type == TOKEN_WPKH) {
                return ADDRESS_TYPE_SH_WIT;
            }
            return -1;
    }

    // unrecognized type
    return -1;
}