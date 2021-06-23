#include <stdlib.h>

#include "policy.h"

#include "../lib/get_merkle_leaf_element.h"
#include "../../crypto.h"
#include "../../common/base58.h"
#include "../../common/segwit_addr.h"
#include "../../types.h"


extern global_context_t G_context;

static int cmp_compressed_pubkeys(const void *a, const void *b) {
    const uint8_t *key_a = (const uint8_t *)a;
    const uint8_t *key_b = (const uint8_t *)b;

    for (int i = 0; i < 33; i++) {
        int diff = key_a[i] - key_b[i];
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


// p2pkh                     ==> legacy address (start with 1 on mainnet, m or n on testnet)
// p2sh (also nested segwit) ==> legacy script  (start with 3 on mainnet, 2 on testnet)
// p2wpkh or p2wsh           ==> bech32         (sart with bc1 on mainnet, tb1 on testnet)


static int get_derived_pubkey(dispatcher_context_t *dispatcher_context,
                              const uint8_t keys_merkle_root[static 20],
                              uint32_t n_keys,
                              int key_index,
                              bool change,
                              size_t address_index,
                              uint8_t out[static 33])
{
    char key_info_str[MAX_POLICY_KEY_INFO_LEN];


    int key_info_len = call_get_merkle_leaf_element(dispatcher_context,
                                                    keys_merkle_root,
                                                    n_keys,
                                                    key_index,
                                                    (uint8_t *)key_info_str,
                                                    sizeof(key_info_str));
    if (key_info_len == -1){
        return -1;
    }


    // Make a sub-buffer for the pubkey info
    buffer_t key_info_buffer = buffer_create(key_info_str, key_info_len);

    policy_map_key_info_t key_info;
    if (parse_policy_map_key_info(&key_info_buffer, &key_info) == -1) {
        return -1;
    }


    // decode pubkey
    serialized_extended_pubkey_check_t decoded_pubkey_check;
    if (base58_decode(key_info.ext_pubkey, strlen(key_info.ext_pubkey), (uint8_t *)&decoded_pubkey_check, sizeof(decoded_pubkey_check)) == -1) {
        return -1;
    }
    // TODO: validate checksum

    serialized_extended_pubkey_t *ext_pubkey = &decoded_pubkey_check.serialize_extended_pubkey;

    if (key_info.has_wildcard) {
        // we derive the /0/i child of this pubkey
        // we reuse the same memory of ext_pubkey to save memory
        bip32_CKDpub(ext_pubkey, change, ext_pubkey);
        bip32_CKDpub(ext_pubkey, address_index, ext_pubkey);
    }

    memcpy(out, ext_pubkey->compressed_pubkey, 33);

    return 0;
}


int call_get_wallet_address(dispatcher_context_t *dispatcher_context,
                            policy_node_t *policy,
                            const uint8_t keys_merkle_root[static 20],
                            uint32_t n_keys,
                            bool change,
                            size_t address_index,
                            char *out_ptr,
                            size_t out_ptr_len)
{
    LOG_PROCESSOR(dispatcher_context, __FILE__, __LINE__, __func__);

    int addr_len;

    uint8_t script[34]; // the longest script for supported addresses is P2WSH

    int script_len = call_get_wallet_script(dispatcher_context,
                                            policy,
                                            keys_merkle_root,
                                            n_keys,
                                            change,
                                            address_index,
                                            script,
                                            sizeof(script),
                                            NULL);

    if (script_len < 0) {
        return -1;
    }


    switch (policy->type) {
        case TOKEN_PKH:
        {
            if (n_keys != 1) {
                return -1;
            }

            addr_len = base58_encode_address(script + 3, G_context.p2pkh_version, (char *)out_ptr, out_ptr_len);
            break;
        }
        case TOKEN_SH:
        {
            addr_len = base58_encode_address(script + 2, G_context.p2sh_version, (char *)out_ptr, out_ptr_len);
            break;
        }
        case TOKEN_WPKH:
        case TOKEN_WSH:
        {
            int hash_length = (policy->type == TOKEN_WPKH ? 20 : 32);

            // make sure that the output buffer is long enough
            if (out_ptr_len < 72 + strlen(G_context.native_segwit_prefix)) {
                return -1;
            }

            int ret = segwit_addr_encode(
                out_ptr,
                G_context.native_segwit_prefix,
                0,
                script + 2,
                hash_length // 20 for WPKH, 32 for WSH
            );

            if (ret != 1) {
                return -1; // should never happen
            }

            addr_len = strlen(out_ptr);
            break;
        }
        default:
            return -1;
    }

    // Make sure the resulting address is 0-terminated
    out_ptr[addr_len] = '\0';
    return addr_len;
}


int call_get_wallet_script(dispatcher_context_t *dispatcher_context,
                           policy_node_t *policy,
                           const uint8_t keys_merkle_root[static 20],
                           uint32_t n_keys,
                           bool change,
                           size_t address_index,
                           uint8_t *out_ptr,
                           size_t out_ptr_len,
                           cx_hash_t *hash_context)
{
    LOG_PROCESSOR(dispatcher_context, __FILE__, __LINE__, __func__);

    buffer_t out_buf;
    buffer_t *out_buf_ptr = NULL;
    if (out_ptr != NULL) {
        out_buf = buffer_create(out_ptr, out_ptr_len);
        out_buf_ptr = &out_buf;
    }

    switch (policy->type) {
        case TOKEN_PKH:
        case TOKEN_WPKH:
        {
            policy_node_with_key_t *root = (policy_node_with_key_t *)policy;

            unsigned int out_len = 3 + 20 + 2;
            if (out_ptr != NULL && out_ptr_len < out_len) {
                return -1;
            }


            uint8_t compressed_pubkey[33];

            if (-1 == get_derived_pubkey(dispatcher_context,
                                         keys_merkle_root,
                                         n_keys,
                                         root->key_index,
                                         change,
                                         address_index,
                                         compressed_pubkey))
            {
                return -1;
            }

           if (policy->type == TOKEN_PKH) {
                uint8_t out[25];

                out[0] = 0x76;
                out[1] = 0xa9;
                out[2] = 0x14;
                crypto_hash160(compressed_pubkey, 33, out + 3);
                out[23] = 0x88;
                out[24] = 0xac;

                update_output(out_buf_ptr, hash_context, out, sizeof(out));

                return sizeof(out);
            } else { // policy->type == TOKEN_PKH
                uint8_t out[22];

                out[0] = 0x00;
                out[1] = 0x14;
                crypto_hash160(compressed_pubkey, 33, out + 2);

                update_output(out_buf_ptr, hash_context, out, sizeof(out));

                return sizeof(out);
            }
        }
        case TOKEN_SH:
        case TOKEN_WSH:
        {
            policy_node_with_script_t *root = (policy_node_with_script_t *)policy;

            cx_sha256_t script_hash_context;
            cx_sha256_init(&script_hash_context);

            int res = call_get_wallet_script(dispatcher_context,
                                             root->script,
                                             keys_merkle_root,
                                             n_keys,
                                             change,
                                             address_index,
                                             NULL,
                                             0,
                                             &script_hash_context.header);
            if (res == -1) {
                return -1;
            }

            uint8_t script_hash[32]; //sha256 of the script
            crypto_hash_digest(&script_hash_context.header, script_hash, 32);


            if (policy->type == TOKEN_SH) {
                uint8_t out[23];

                out[0] = 0xa9;
                out[1] = 0x14;
                crypto_ripemd160(script_hash, 32, out + 2);
                out[22] = 0x87;

                update_output(out_buf_ptr, hash_context, out, sizeof(out));

                return sizeof(out);
            } else { // policy->type == TOKEN_WSH
                uint8_t out[34];

                out[0] = 0x00;
                out[1] = 0x20;
                memcpy(out + 2, script_hash, 32);

                update_output(out_buf_ptr, hash_context, out, sizeof(out));

                return sizeof(out);
            }
        }
        case TOKEN_MULTI:
        {
            policy_node_multisig_t *root = (policy_node_multisig_t *)policy;

            // k {pubkey_1} ... {pubkey_n} n OP_CHECKMULTISIG
            unsigned int out_len = 1 + 34 * root->n + 1 + 1;

            if (out_ptr != NULL && out_ptr_len < out_len) {
                return -1;
            }

            uint8_t tmp = 0x50 + root->k; // OP_k
            update_output(out_buf_ptr, hash_context, &tmp, 1);

            for (unsigned int i = 0; i < root->n; i++) {
                uint8_t compressed_pubkey[33];

                if (-1 == get_derived_pubkey(dispatcher_context,
                                             keys_merkle_root,
                                             n_keys,
                                             root->key_indexes[i],
                                             change,
                                             address_index,
                                             compressed_pubkey))
                {
                    return -1;
                }

                tmp = 0x21;              // push <i-th pubkey>
                update_output(out_buf_ptr, hash_context, &tmp, 1);
                update_output(out_buf_ptr, hash_context, compressed_pubkey, 33);
            }

            tmp = 0x50 + root->n;         // OP_n
            update_output(out_buf_ptr, hash_context, &tmp, 1);
            tmp = 0xae;                   // OP_CHECKMULTISIG
            update_output(out_buf_ptr, hash_context, &tmp, 1);

            return out_len;
        }
        case TOKEN_SORTEDMULTI:
        {
            policy_node_multisig_t *root = (policy_node_multisig_t *)policy;


            // TODO: replace with the maximum we can afford
            if (root->n >= 5) {
                return -1;
            }

            // k {pubkey_1} ... {pubkey_n} n OP_CHECKMULTISIG
            unsigned int out_len = 1 + 34 * root->n + 1 + 1;

            if (out_ptr != NULL && out_ptr_len < out_len) {
                return -1;
            }


            uint8_t tmp = 0x50 + root->k; // OP_k
            update_output(out_buf_ptr, hash_context, &tmp, 1);


            uint8_t compressed_pubkeys[5][33];
            for (unsigned int i = 0; i < root->n; i++) {

                if (-1 == get_derived_pubkey(dispatcher_context,
                                             keys_merkle_root,
                                             n_keys,
                                             root->key_indexes[i],
                                             change,
                                             address_index,
                                             compressed_pubkeys[i]))
                {
                    return -1;
                }
            }


            // sort the pubkeys
            qsort(compressed_pubkeys, root->n, 33, cmp_compressed_pubkeys);

            for (unsigned int i = 0; i < root->n; i++) {
                tmp = 0x21;              // push <i-th pubkey>
                update_output(out_buf_ptr, hash_context, &tmp, 1);
                update_output(out_buf_ptr, hash_context, compressed_pubkeys[i], 33);
            }


            tmp = 0x50 + root->n;         // OP_n
            update_output(out_buf_ptr, hash_context, &tmp, 1);
            tmp = 0xae;                   // OP_CHECKMULTISIG
            update_output(out_buf_ptr, hash_context, &tmp, 1);


            return out_len;
        }
        default:
            return -1;
    }
}