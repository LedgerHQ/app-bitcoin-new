#include <stdlib.h>

#include "policy.h"

#include "../lib/get_merkle_leaf_element.h"
#include "../../crypto.h"
#include "../../common/base58.h"
#include "../../common/segwit_addr.h"

extern global_context_t G_context;

#define MAX_POLICY_DEPTH 3

#define MODE_OUT_BYTES 0
#define MODE_OUT_HASH  1

typedef struct {
    const policy_node_t *policy_node;

    // Only one of the two is used, depending on the `mode`
    union {
        cx_sha256_t *hash_context;
        buffer_t *out_buf;
    };

    // used to identify the stage of execution for nodes that require multiple rounds
    uint8_t step;

    // MODE_OUT_BYTES if the current node is outputting the actual script bytes, or MODE_OUT_HASH
    // if it is outputting the script hash
    uint8_t mode;
} policy_parser_node_state_t;

typedef struct {
    dispatcher_context_t *dispatcher_context;
    const uint8_t *keys_merkle_root;
    uint32_t n_keys;
    bool change;
    size_t address_index;

    policy_parser_node_state_t nodes[MAX_POLICY_DEPTH];  // stack of nodes being processed
    int node_stack_eos;  // index of node being processed within nodes; will be set -1 at the end of
                         // processing

    cx_sha256_t hash_context;  // shared among all the nodes; there are never two concurrent hash
                               // computations in process.
    uint8_t hash[32];  // when a node processed in hash mode is popped, the hash is computed here
} policy_parser_state_t;

// comparator for pointers to compressed pubkeys
static int cmp_compressed_pubkeys(const void *a, const void *b) {
    const uint8_t *key_a = (const uint8_t *) a;
    const uint8_t *key_b = (const uint8_t *) b;
    for (int i = 0; i < 33; i++) {
        int diff = key_a[i] - key_b[i];
        if (diff != 0) {
            return diff;
        }
    }
    return 0;
}

// p2pkh                     ==> legacy address (start with 1 on mainnet, m or n on testnet)
// p2sh (also nested segwit) ==> legacy script  (start with 3 on mainnet, 2 on testnet)
// p2wpkh or p2wsh           ==> bech32         (sart with bc1 on mainnet, tb1 on testnet)

// convenience function, split from get_derived_pubkey only to improve stack usage
// returns -1 on error, 0 if the returned key info has no wildcard (**), 1 if it has the wildcard
static int __attribute__((noinline)) get_extended_pubkey(policy_parser_state_t *state,
                                                         int key_index,
                                                         serialized_extended_pubkey_t *out) {
    PRINT_STACK_POINTER();

    policy_map_key_info_t key_info;

    {
        char key_info_str[MAX_POLICY_KEY_INFO_LEN];

        int key_info_len = call_get_merkle_leaf_element(state->dispatcher_context,
                                                        state->keys_merkle_root,
                                                        state->n_keys,
                                                        key_index,
                                                        (uint8_t *) key_info_str,
                                                        sizeof(key_info_str));
        if (key_info_len == -1) {
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
    if (base58_decode(key_info.ext_pubkey,
                      strlen(key_info.ext_pubkey),
                      (uint8_t *) &decoded_pubkey_check,
                      sizeof(decoded_pubkey_check)) == -1) {
        return -1;
    }
    // TODO: validate checksum

    memcpy(out,
           &decoded_pubkey_check.serialized_extended_pubkey,
           sizeof(decoded_pubkey_check.serialized_extended_pubkey));

    return key_info.has_wildcard ? 1 : 0;
}

static int get_derived_pubkey(policy_parser_state_t *state, int key_index, uint8_t out[static 33]) {
    PRINT_STACK_POINTER();

    serialized_extended_pubkey_t ext_pubkey;

    int ret = get_extended_pubkey(state, key_index, &ext_pubkey);
    if (ret < 0) {
        return -1;
    }

    if (ret == 1) {
        // we derive the /0/i child of this pubkey
        // we reuse the same memory of ext_pubkey
        bip32_CKDpub(&ext_pubkey, state->change, &ext_pubkey);
        bip32_CKDpub(&ext_pubkey, state->address_index, &ext_pubkey);
    }

    memcpy(out, ext_pubkey.compressed_pubkey, 33);

    return 0;
}

/**
 * Pushes a node onto the stack. Returns 0 on success, -1 if the stack is exhausted.
 */
static int state_stack_push(policy_parser_state_t *state, policy_node_t *policy_node) {
    ++state->node_stack_eos;

    if (state->node_stack_eos >= MAX_POLICY_DEPTH) {
        return -1;
    }

    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];
    cx_sha256_init(&state->hash_context);
    node->policy_node = policy_node;
    node->step = 0;
    node->mode = MODE_OUT_HASH;
    node->hash_context = &state->hash_context;

    return 0;
}

/**
 * Pops a node the stack. If the node is in HASH mode, computes the hash.
 * Returns 0 on success, -1 on error.
 */
static int state_stack_pop(policy_parser_state_t *state) {
    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];

    if (state->node_stack_eos >= MAX_POLICY_DEPTH || state->node_stack_eos <= -1) {
        return -1;
    }

    if (node->mode == MODE_OUT_HASH) {
        crypto_hash_digest(&state->hash_context.header, state->hash, 32);
    }

    --state->node_stack_eos;
    return 0;
}

static void update_output(policy_parser_state_t *state, const uint8_t *data, size_t data_len) {
    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];
    if (node->mode == MODE_OUT_BYTES) {
        buffer_write_bytes(node->out_buf, data, data_len);
    } else {
        crypto_hash_update(&node->hash_context->header, data, data_len);
    }
}

static void update_output_u8(policy_parser_state_t *state, const uint8_t data) {
    update_output(state, &data, 1);
}

static int process_pkh_wpkh_node(policy_parser_state_t *state) {
    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];

    if (node->step != 0) {
        return -1;
    }

    policy_node_with_key_t *policy = (policy_node_with_key_t *) node->policy_node;

    unsigned int out_len;
    if (policy->type == TOKEN_PKH) {
        out_len = 3 + 20 + 2;
    } else {
        out_len = 2 + 20;
    }

    if (node->mode == MODE_OUT_BYTES && !buffer_can_read(node->out_buf, out_len)) {
        return -1;
    }

    uint8_t compressed_pubkey[33];

    if (node->mode == MODE_OUT_HASH) {
        cx_sha256_init(&state->hash_context);
    }

    int result;
    if (-1 == get_derived_pubkey(state, policy->key_index, compressed_pubkey)) {
        return -1;
    } else if (policy->type == TOKEN_PKH) {
        update_output_u8(state, 0x76);
        update_output_u8(state, 0xa9);
        update_output_u8(state, 0x14);

        crypto_hash160(compressed_pubkey, 33, compressed_pubkey);  // reuse memory
        update_output(state, compressed_pubkey, 20);

        update_output_u8(state, 0x88);
        update_output_u8(state, 0xac);

        result = 3 + 20 + 2;
    } else {  // policy->type == TOKEN_WPKH
        update_output_u8(state, 0x00);
        update_output_u8(state, 0x14);

        crypto_hash160(compressed_pubkey, 33, compressed_pubkey);  // reuse memory
        update_output(state, compressed_pubkey, 20);

        result = 2 + 20;
    }

    if (-1 == state_stack_pop(state)) {
        return -1;
    }
    return result;
}

static int process_sh_wsh_node(policy_parser_state_t *state) {
    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];

    policy_node_with_script_t *policy = (policy_node_with_script_t *) node->policy_node;

    if (node->step != 0 && node->step != 1) {
        return -1;
    }

    if (node->step == 0) {
        // process child in HASH mode
        if (-1 == state_stack_push(state, policy->script)) {
            return -1;
        }
        ++node->step;
        return 0;
    }

    // child already computed

    if (node->mode == MODE_OUT_HASH) {
        cx_sha256_init(&state->hash_context);
    }

    int result;
    if (policy->type == TOKEN_SH) {
        update_output_u8(state, 0xa9);
        update_output_u8(state, 0x14);

        crypto_ripemd160(state->hash, 32, state->hash);  // reuse memory
        update_output(state, state->hash, 20);

        update_output_u8(state, 0x87);

        result = 2 + 20 + 1;
    } else {  // policy->type == TOKEN_WSH
        update_output_u8(state, 0x00);
        update_output_u8(state, 0x20);

        update_output(state, state->hash, 32);

        result = 2 + 32;
    }

    if (-1 == state_stack_pop(state)) {
        return -1;
    }
    return result;
}

static int process_multi_sortedmulti_node(policy_parser_state_t *state) {
    PRINT_STACK_POINTER();

    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];

    if (node->step != 0) {
        return -1;
    }

    policy_node_multisig_t *policy = (policy_node_multisig_t *) node->policy_node;

    // k {pubkey_1} ... {pubkey_n} n OP_CHECKMULTISIG
    unsigned int out_len = 1 + 34 * policy->n + 1 + 1;

    if (node->mode == MODE_OUT_BYTES && !buffer_can_read(node->out_buf, out_len)) {
        return -1;
    }

    if (node->mode == MODE_OUT_HASH) {
        cx_sha256_init(&state->hash_context);
    }

    update_output_u8(state, 0x50 + policy->k);  // OP_k

    // derive each key
    uint8_t compressed_pubkeys[MAX_POLICY_MAP_KEYS][33];
    for (unsigned int i = 0; i < policy->n; i++) {
        if (-1 == get_derived_pubkey(state, policy->key_indexes[i], compressed_pubkeys[i])) {
            return -1;
        }
    }

    if (policy->type == TOKEN_SORTEDMULTI) {
        // sort the pubkeys (we avoid using qsort, as it takes ~700 bytes in binary size)

        // bubble sort
        bool swapped;
        do {
            swapped = false;
            for (unsigned int i = 1; i < policy->n; i++) {
                if (cmp_compressed_pubkeys(compressed_pubkeys[i - 1], compressed_pubkeys[i]) > 0) {
                    swapped = true;

                    for (int j = 0; j < 33; j++) {
                        uint8_t t = compressed_pubkeys[i - 1][j];
                        compressed_pubkeys[i - 1][j] = compressed_pubkeys[i][j];
                        compressed_pubkeys[i][j] = t;
                    }
                }
            }
        } while (swapped);
    }

    for (unsigned int i = 0; i < policy->n; i++) {
        // push <i-th pubkey> (33 = 0x21 bytes)
        update_output_u8(state, 0x21);
        update_output(state, compressed_pubkeys[i], 33);
    }

    update_output_u8(state, 0x50 + policy->n);  // OP_n
    update_output_u8(state, 0xae);              // OP_CHECKMULTISIG

    if (-1 == state_stack_pop(state)) {
        return -1;
    }
    return out_len;
}

static int process_tr_node(policy_parser_state_t *state) {
    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];

    if (node->step != 0) {
        return -1;
    }

    policy_node_with_key_t *policy = (policy_node_with_key_t *) node->policy_node;

    unsigned int out_len = 2 + 32;

    if (node->mode == MODE_OUT_BYTES && !buffer_can_read(node->out_buf, out_len)) {
        return -1;
    }

    int result;

    uint8_t compressed_pubkey[33];
    uint8_t tweaked_key[32];

    if (-1 == get_derived_pubkey(state, policy->key_index, compressed_pubkey)) {
        return -1;
    } else {
        update_output_u8(state, 0x51);
        update_output_u8(state, 0x20);

        uint8_t parity;
        crypto_tr_tweak_pubkey(compressed_pubkey + 1, &parity, tweaked_key);

        update_output(state, tweaked_key, 32);

        result = 2 + 32;
    }

    if (-1 == state_stack_pop(state)) {
        return -1;
    }
    return result;
}

int call_get_wallet_script(dispatcher_context_t *dispatcher_context,
                           const policy_node_t *policy,
                           const uint8_t keys_merkle_root[static 32],
                           uint32_t n_keys,
                           bool change,
                           size_t address_index,
                           buffer_t *out_buf) {
    policy_parser_state_t state = {.dispatcher_context = dispatcher_context,
                                   .keys_merkle_root = keys_merkle_root,
                                   .n_keys = n_keys,
                                   .change = change,
                                   .address_index = address_index,
                                   .node_stack_eos = 0};

    state.nodes[0] = (policy_parser_node_state_t){.mode = MODE_OUT_BYTES,
                                                  .step = 0,
                                                  .policy_node = policy,
                                                  .out_buf = out_buf};

    int ret;
    do {
        switch (state.nodes[state.node_stack_eos].policy_node->type) {
            case TOKEN_PKH:
            case TOKEN_WPKH:
                ret = process_pkh_wpkh_node(&state);
                break;
            case TOKEN_SH:
            case TOKEN_WSH:
                ret = process_sh_wsh_node(&state);
                break;
            case TOKEN_MULTI:
            case TOKEN_SORTEDMULTI:
                ret = process_multi_sortedmulti_node(&state);
                break;
            case TOKEN_TR:
                ret = process_tr_node(&state);
                break;
            default:
                ret = -1;
        }
    } while (ret >= 0 && state.node_stack_eos >= 0);
    return ret;
}

int get_policy_address_type(const policy_node_t *policy) {
    // legacy, native segwit, wrapped segwit, or taproot
    switch (policy->type) {
        case TOKEN_PKH:
            return ADDRESS_TYPE_LEGACY;
        case TOKEN_WPKH:
            return ADDRESS_TYPE_WIT;
        case TOKEN_SH:
            // wrapped segwit
            if (((policy_node_with_script_t *) policy)->script->type == TOKEN_WPKH) {
                return ADDRESS_TYPE_SH_WIT;
            }
            return -1;
        case TOKEN_TR:
            return ADDRESS_TYPE_TR;
        default:
            return -1;
    }
}

bool check_wallet_hmac(const uint8_t wallet_id[static 32], const uint8_t wallet_hmac[static 32]) {
    uint8_t key[32];
    uint8_t correct_hmac[32];

    bool result = false;
    BEGIN_TRY {
        TRY {
            crypto_derive_symmetric_key(WALLET_SLIP0021_LABEL, WALLET_SLIP0021_LABEL_LEN, key);

            cx_hmac_sha256(key, sizeof(key), wallet_id, 32, correct_hmac, 32);

            // It is important to use a constant-time function to compare the hmac,
            // to avoid timing-attack that could be exploited to extract it.
            result = os_secure_memcmp((void *) wallet_hmac, (void *) correct_hmac, 32) == 0;
        }
        FINALLY {
            explicit_bzero(key, sizeof(key));
            explicit_bzero(correct_hmac, sizeof(correct_hmac));
        }
    }
    END_TRY;

    return result;
}