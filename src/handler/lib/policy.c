#include <stdlib.h>

#include "policy.h"

#include "../lib/get_merkle_leaf_element.h"
#include "../lib/get_preimage.h"
#include "../../crypto.h"
#include "../../common/base58.h"
#include "../../common/bitvector.h"
#include "../../common/read.h"
#include "../../common/script.h"
#include "../../common/segwit_addr.h"
#include "../../common/wallet.h"

#include "debug-helpers/debug.h"

#define MAX_POLICY_DEPTH 10

// The last opcode must be processed as a VERIFY flag
#define PROCESSOR_FLAG_V 1

/**
 * The label used to derive the symmetric key used to register/verify wallet policies on device.
 */
#define WALLET_SLIP0021_LABEL "\0LEDGER-Wallet policy"
#define WALLET_SLIP0021_LABEL_LEN \
    (sizeof(WALLET_SLIP0021_LABEL) - 1)  // sizeof counts the terminating 0

typedef struct {
    const policy_node_t *policy_node;

    // bytes written to output
    uint16_t length;
    // used to identify the stage of execution for nodes that require multiple rounds
    uint8_t step;

    uint8_t flags;
} policy_parser_node_state_t;

typedef struct {
    dispatcher_context_t *dispatcher_context;
    const wallet_derivation_info_t *wdi;
    bool is_taproot;

    policy_parser_node_state_t nodes[MAX_POLICY_DEPTH];  // stack of nodes being processed
    int node_stack_eos;  // index of node being processed within nodes; will be set -1 at the end of
                         // processing

    cx_hash_t *hash_context;
    uint8_t hash[32];  // when a node is popped, the hash is computed here
} policy_parser_state_t;

// comparator for pointers to arrays of equal length
static int cmp_arrays(const void *a, const void *b, size_t length) {
    const uint8_t *key_a = (const uint8_t *) a;
    const uint8_t *key_b = (const uint8_t *) b;
    for (size_t i = 0; i < length; i++) {
        int diff = key_a[i] - key_b[i];
        if (diff != 0) {
            return diff;
        }
    }
    return 0;
}

typedef int (*policy_parser_processor_t)(policy_parser_state_t *state, const void *arg);

typedef enum {
    CMD_CODE_OP,       // data is a byte to emit (usually an opcode)
    CMD_CODE_OP_V,     // data is an opcode, but transform according to 'v' if necessary
    CMD_CODE_PUSH_PK,  // push the compressed pubkey indicated by the current policy_node_with_key_t
    CMD_CODE_PUSH_PKH,         // push the hash160 of the compressed pubkey indicated by the current
                               // policy_node_with_key_t
    CMD_CODE_PUSH_UINT32,      // push the integer in the current policy_node_with_uint32_t
    CMD_CODE_PUSH_HASH20,      // push a 20 bytes hash in the current policy_node_with_hash_160_t
    CMD_CODE_PUSH_HASH32,      // push a 32 bytes hash in the current policy_node_with_hash_256_t
    CMD_CODE_PROCESS_CHILD,    // process the i-th script of a policy_node_with_scripts_t,
                               // where i is indicated by the command data
    CMD_CODE_PROCESS_CHILD_V,  // like the previous, but it propagates the v flag to the child
    CMD_CODE_PROCESS_CHILD_VV,  // like the previous, but it activates the v flag in the child

    CMD_CODE_END  // last step, should terminate here
} generic_processor_command_code_e;

typedef struct {
    uint8_t code;
    uint8_t data;
} generic_processor_command_t;

// Whitelistes for allowed fragments when processing inner scripts expressions
static const uint8_t fragment_whitelist_sh[] = {TOKEN_WPKH, TOKEN_MULTI, TOKEN_SORTEDMULTI};
static const uint8_t fragment_whitelist_sh_wsh[] = {TOKEN_MULTI, TOKEN_SORTEDMULTI};
static const uint8_t fragment_whitelist_wsh[] = {
    /* tokens for miniscript on segwit */
    TOKEN_0,
    TOKEN_1,
    TOKEN_PK,
    TOKEN_PKH,
    TOKEN_PK_K,
    TOKEN_PK_H,
    TOKEN_OLDER,
    TOKEN_AFTER,
    TOKEN_SHA256,
    TOKEN_HASH256,
    TOKEN_RIPEMD160,
    TOKEN_HASH160,
    TOKEN_ANDOR,
    TOKEN_AND_V,
    TOKEN_AND_B,
    TOKEN_AND_N,
    TOKEN_MULTI,
    TOKEN_OR_B,
    TOKEN_OR_C,
    TOKEN_OR_D,
    TOKEN_OR_I,
    TOKEN_SORTEDMULTI,
    TOKEN_THRESH,
    // wrappers
    TOKEN_A,
    TOKEN_S,
    TOKEN_C,
    TOKEN_T,
    TOKEN_D,
    TOKEN_V,
    TOKEN_J,
    TOKEN_N,
    TOKEN_L,
    TOKEN_U};
static const uint8_t fragment_whitelist_tapscript[] = {TOKEN_PK,
                                                       TOKEN_MULTI_A,
                                                       TOKEN_SORTEDMULTI_A};

static const generic_processor_command_t commands_0[] = {{CMD_CODE_OP_V, OP_0}, {CMD_CODE_END, 0}};
static const generic_processor_command_t commands_1[] = {{CMD_CODE_OP_V, OP_1}, {CMD_CODE_END, 0}};
static const generic_processor_command_t commands_pk_k[] = {{CMD_CODE_PUSH_PK, 0},
                                                            {CMD_CODE_END, 0}};
static const generic_processor_command_t commands_pk_h[] = {{CMD_CODE_OP, OP_DUP},
                                                            {CMD_CODE_OP, OP_HASH160},
                                                            {CMD_CODE_PUSH_PKH, 0},
                                                            {CMD_CODE_OP, OP_EQUALVERIFY},
                                                            {CMD_CODE_END, 0}};
static const generic_processor_command_t commands_pk[] = {{CMD_CODE_PUSH_PK, 0},
                                                          {CMD_CODE_OP_V, OP_CHECKSIG},
                                                          {CMD_CODE_END, 0}};
static const generic_processor_command_t commands_older[] = {{CMD_CODE_PUSH_UINT32, 0},
                                                             {CMD_CODE_OP_V, OP_CSV},
                                                             {CMD_CODE_END, 0}};
static const generic_processor_command_t commands_after[] = {{CMD_CODE_PUSH_UINT32, 0},
                                                             {CMD_CODE_OP_V, OP_CLTV},
                                                             {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_sha256[] = {{CMD_CODE_OP, OP_SIZE},
                                                              {CMD_CODE_OP, 1},   // 1-byte push
                                                              {CMD_CODE_OP, 32},  // pushed value
                                                              {CMD_CODE_OP, OP_EQUALVERIFY},
                                                              {CMD_CODE_OP, OP_SHA256},
                                                              {CMD_CODE_PUSH_HASH32, 0},
                                                              {CMD_CODE_OP_V, OP_EQUAL},
                                                              {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_hash256[] = {{CMD_CODE_OP, OP_SIZE},
                                                               {CMD_CODE_OP, 1},   // 1-byte push
                                                               {CMD_CODE_OP, 32},  // pushed value
                                                               {CMD_CODE_OP, OP_EQUALVERIFY},
                                                               {CMD_CODE_OP, OP_HASH256},
                                                               {CMD_CODE_PUSH_HASH32, 0},
                                                               {CMD_CODE_OP_V, OP_EQUAL},
                                                               {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_ripemd160[] = {{CMD_CODE_OP, OP_SIZE},
                                                                 {CMD_CODE_OP, 1},   // 1-byte push
                                                                 {CMD_CODE_OP, 32},  // pushed value
                                                                 {CMD_CODE_OP, OP_EQUALVERIFY},
                                                                 {CMD_CODE_OP, OP_RIPEMD160},
                                                                 {CMD_CODE_PUSH_HASH20, 0},
                                                                 {CMD_CODE_OP_V, OP_EQUAL},
                                                                 {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_hash160[] = {{CMD_CODE_OP, OP_SIZE},
                                                               {CMD_CODE_OP, 1},   // 1-byte push
                                                               {CMD_CODE_OP, 32},  // pushed value
                                                               {CMD_CODE_OP, OP_EQUALVERIFY},
                                                               {CMD_CODE_OP, OP_HASH160},
                                                               {CMD_CODE_PUSH_HASH20, 0},
                                                               {CMD_CODE_OP_V, OP_EQUAL},
                                                               {CMD_CODE_END, 0}};

// andor(X,Y,X) ==> [X] NOTIF [Z] ELSE [Y] ENDIF
static const generic_processor_command_t commands_andor[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                             {CMD_CODE_OP, OP_NOTIF},
                                                             {CMD_CODE_PROCESS_CHILD, 2},
                                                             {CMD_CODE_OP, OP_ELSE},
                                                             {CMD_CODE_PROCESS_CHILD, 1},
                                                             {CMD_CODE_OP_V, OP_ENDIF},
                                                             {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_and_v[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                             {CMD_CODE_PROCESS_CHILD_V, 1},
                                                             {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_and_b[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                             {CMD_CODE_PROCESS_CHILD, 1},
                                                             {CMD_CODE_OP_V, OP_BOOLAND},
                                                             {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_and_n[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                             {CMD_CODE_OP, OP_NOTIF},
                                                             {CMD_CODE_OP, OP_0},
                                                             {CMD_CODE_OP, OP_ELSE},
                                                             {CMD_CODE_PROCESS_CHILD, 1},
                                                             {CMD_CODE_OP_V, OP_ENDIF},
                                                             {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_or_b[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                            {CMD_CODE_PROCESS_CHILD, 1},
                                                            {CMD_CODE_OP_V, OP_BOOLOR},
                                                            {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_or_c[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                            {CMD_CODE_OP, OP_NOTIF},
                                                            {CMD_CODE_PROCESS_CHILD, 1},
                                                            {CMD_CODE_OP_V, OP_ENDIF},
                                                            {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_or_d[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                            {CMD_CODE_OP, OP_IFDUP},
                                                            {CMD_CODE_OP, OP_NOTIF},
                                                            {CMD_CODE_PROCESS_CHILD, 1},
                                                            {CMD_CODE_OP_V, OP_ENDIF},
                                                            {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_or_i[] = {{CMD_CODE_OP, OP_IF},
                                                            {CMD_CODE_PROCESS_CHILD, 0},
                                                            {CMD_CODE_OP, OP_ELSE},
                                                            {CMD_CODE_PROCESS_CHILD, 1},
                                                            {CMD_CODE_OP_V, OP_ENDIF},
                                                            {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_a[] = {{CMD_CODE_OP, OP_TOALTSTACK},
                                                         {CMD_CODE_PROCESS_CHILD, 0},
                                                         {CMD_CODE_OP, OP_FROMALTSTACK},
                                                         {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_s[] = {{CMD_CODE_OP, OP_SWAP},
                                                         {CMD_CODE_PROCESS_CHILD, 0},
                                                         {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_c[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                         {CMD_CODE_OP_V, OP_CHECKSIG},
                                                         {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_t[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                         {CMD_CODE_OP_V, OP_1},
                                                         {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_d[] = {{CMD_CODE_OP, OP_DUP},
                                                         {CMD_CODE_OP, OP_IF},
                                                         {CMD_CODE_PROCESS_CHILD, 0},
                                                         {CMD_CODE_OP_V, OP_ENDIF},
                                                         {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_v[] = {{CMD_CODE_PROCESS_CHILD_VV, 0},
                                                         {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_j[] = {{CMD_CODE_OP, OP_SIZE},
                                                         {CMD_CODE_OP, OP_0NOTEQUAL},
                                                         {CMD_CODE_OP, OP_IF},
                                                         {CMD_CODE_PROCESS_CHILD, 0},
                                                         {CMD_CODE_OP_V, OP_ENDIF},
                                                         {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_n[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                         {CMD_CODE_OP_V, OP_0NOTEQUAL},
                                                         {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_l[] = {{CMD_CODE_OP, OP_IF},
                                                         {CMD_CODE_OP, OP_0},
                                                         {CMD_CODE_OP, OP_ELSE},
                                                         {CMD_CODE_PROCESS_CHILD, 0},
                                                         {CMD_CODE_OP_V, OP_ENDIF},
                                                         {CMD_CODE_END, 0}};

static const generic_processor_command_t commands_u[] = {{CMD_CODE_OP, OP_IF},
                                                         {CMD_CODE_PROCESS_CHILD, 0},
                                                         {CMD_CODE_OP, OP_ELSE},
                                                         {CMD_CODE_OP, OP_0},
                                                         {CMD_CODE_OP_V, OP_ENDIF},
                                                         {CMD_CODE_END, 0}};

int read_and_parse_wallet_policy(
    dispatcher_context_t *dispatcher_context,
    buffer_t *buf,
    policy_map_wallet_header_t *wallet_header,
    uint8_t policy_map_descriptor_template[static MAX_DESCRIPTOR_TEMPLATE_LENGTH],
    uint8_t *policy_map_bytes,
    size_t policy_map_bytes_len) {
    if ((read_wallet_policy_header(buf, wallet_header)) < 0) {
        return WITH_ERROR(-1, "Failed reading wallet policy header");
    }

    if (wallet_header->version == WALLET_POLICY_VERSION_V1) {
        memcpy(policy_map_descriptor_template,
               wallet_header->descriptor_template,
               wallet_header->descriptor_template_len);
    } else {
        // if V2, stream and parse descriptor template from client first
        int descriptor_template_len = call_get_preimage(dispatcher_context,
                                                        wallet_header->descriptor_template_sha256,
                                                        policy_map_descriptor_template,
                                                        MAX_DESCRIPTOR_TEMPLATE_LENGTH);
        if (descriptor_template_len < 0) {
            return WITH_ERROR(-1, "Failed getting wallet policy descriptor template");
        }
    }

    buffer_t policy_map_buffer =
        buffer_create(policy_map_descriptor_template, wallet_header->descriptor_template_len);
    if (parse_descriptor_template(&policy_map_buffer,
                                  policy_map_bytes,
                                  policy_map_bytes_len,
                                  wallet_header->version) < 0) {
        return WITH_ERROR(-1, "Failed parsing descriptor template");
    }
    return 0;
}

/**
 * Pushes a node onto the stack. Returns 0 on success, -1 if the stack is exhausted.
 */
__attribute__((warn_unused_result)) static int state_stack_push(policy_parser_state_t *state,
                                                                const policy_node_t *policy_node,
                                                                uint8_t flags) {
    ++state->node_stack_eos;

    if (state->node_stack_eos >= MAX_POLICY_DEPTH) {
        return WITH_ERROR(-1, "Reached maximum policy depth");
    }

    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];
    node->policy_node = policy_node;
    node->length = 0;
    node->step = 0;
    node->flags = flags;

    return 0;
}

/**
 * Pops a node from the stack.
 * Returns the emitted length on success, -1 on error.
 */
__attribute__((warn_unused_result)) static int state_stack_pop(policy_parser_state_t *state) {
    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];

    if (state->node_stack_eos <= -1) {
        return WITH_ERROR(-1, "Stack underflow");
    }

    --state->node_stack_eos;

    if (state->node_stack_eos >= 0) {
        state->nodes[state->node_stack_eos].length += node->length;
    }
    return node->length;
}

__attribute__((warn_unused_result)) static inline int
execute_processor(policy_parser_state_t *state, policy_parser_processor_t proc, const void *arg) {
    int ret = proc(state, arg);

    // if the processor is done, pop the stack
    if (ret > 0) {
        return state_stack_pop(state);
    }

    return ret;
}

// p2pkh                     ==> legacy address (start with 1 on mainnet, m or n on testnet)
// p2sh (also nested segwit) ==> legacy script  (start with 3 on mainnet, 2 on testnet)
// p2wpkh or p2wsh           ==> bech32         (sart with bc1 on mainnet, tb1 on testnet)

// convenience function, split from get_derived_pubkey only to improve stack usage
// returns -1 on error, 0 if the returned key info has no wildcard (**), 1 if it has the wildcard
__attribute__((noinline, warn_unused_result)) static int get_extended_pubkey(
    dispatcher_context_t *dispatcher_context,
    const wallet_derivation_info_t *wdi,
    int key_index,
    serialized_extended_pubkey_t *out) {
    PRINT_STACK_POINTER();

    policy_map_key_info_t key_info;

    {
        char key_info_str[MAX_POLICY_KEY_INFO_LEN];

        int key_info_len = call_get_merkle_leaf_element(dispatcher_context,
                                                        wdi->keys_merkle_root,
                                                        wdi->n_keys,
                                                        key_index,
                                                        (uint8_t *) key_info_str,
                                                        sizeof(key_info_str));
        if (key_info_len == -1) {
            return -1;
        }

        // Make a sub-buffer for the pubkey info
        buffer_t key_info_buffer = buffer_create(key_info_str, key_info_len);

        if (parse_policy_map_key_info(&key_info_buffer, &key_info, wdi->wallet_version) == -1) {
            return -1;
        }
    }
    *out = key_info.ext_pubkey;

    return key_info.has_wildcard ? 1 : 0;
}

__attribute__((warn_unused_result)) static int get_derived_pubkey(
    dispatcher_context_t *dispatcher_context,
    const wallet_derivation_info_t *wdi,
    const policy_node_key_placeholder_t *key_placeholder,
    uint8_t out[static 33]) {
    PRINT_STACK_POINTER();

    serialized_extended_pubkey_t ext_pubkey;

    int ret = get_extended_pubkey(dispatcher_context, wdi, key_placeholder->key_index, &ext_pubkey);
    if (ret < 0) {
        return -1;
    }

    // we derive the /<change>/<address_index> child of this pubkey
    // we reuse the same memory of ext_pubkey
    bip32_CKDpub(&ext_pubkey,
                 wdi->change ? key_placeholder->num_second : key_placeholder->num_first,
                 &ext_pubkey);
    bip32_CKDpub(&ext_pubkey, wdi->address_index, &ext_pubkey);

    memcpy(out, ext_pubkey.compressed_pubkey, 33);

    return 0;
}

static void update_output(policy_parser_state_t *state, const uint8_t *data, size_t data_len) {
    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];
    node->length += data_len;
    if (state->hash_context != NULL) {
        crypto_hash_update(state->hash_context, data, data_len);
    }
}

static inline void update_output_u8(policy_parser_state_t *state, uint8_t data) {
    update_output(state, &data, 1);
}

// outputs the minimal push opcode for an unsigned 32bit integer
static void update_output_push_u32(policy_parser_state_t *state, uint32_t n) {
    if (n == 0) {
        update_output_u8(state, OP_0);
    } else if (n <= 16) {
        update_output_u8(state, 0x50 + (uint8_t) n);
    } else {
        uint8_t n_le[4];
        write_u32_le(n_le, 0, n);
        uint8_t byte_size;
        if (n <= 0x7f)
            byte_size = 1;
        else if (n <= 0x7fff)
            byte_size = 2;
        else if (n <= 0x7fffff)
            byte_size = 3;
        else if (n <= 0x7fffffff)
            byte_size = 4;
        else
            byte_size = 5;  // no 32-bit number needs more than 5 bytes

        update_output_u8(state, byte_size);
        if (byte_size < 5) {
            update_output(state, n_le, byte_size);
        } else {
            // Since numbers are signed little endian, unsigned numbers bigger than 0x7FFFFFFF
            // need an extra 0x00 byte.
            update_output(state, n_le, 4);
            update_output_u8(state, 0);
        }
    }
}

static void update_output_op_v(policy_parser_state_t *state, uint8_t op) {
    const policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];
    if (node->flags & PROCESSOR_FLAG_V) {
        if (op == OP_CHECKSIG || op == OP_CHECKMULTISIG || op == OP_NUMEQUAL || op == OP_EQUAL) {
            // the _VERIFY versions of the opcodes are all 1 larger
            update_output_u8(state, op + 1);
        } else {
            update_output_u8(state, op);
            update_output_u8(state, OP_VERIFY);
        }
    } else {
        update_output_u8(state, op);
    }
}

__attribute__((warn_unused_result)) static int process_generic_node(policy_parser_state_t *state,
                                                                    const void *arg) {
    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];

    const generic_processor_command_t *commands = (const generic_processor_command_t *) arg;

    size_t n_commands = 0;
    while (commands[n_commands].code != CMD_CODE_END) ++n_commands;

    if (node->step > n_commands) {
        return WITH_ERROR(-1, "Inconsistent state");
    } else if (node->step == n_commands) {
        return 1;
    } else {
        uint8_t cmd_code = commands[node->step].code;
        uint8_t cmd_data = commands[node->step].data;

        switch (cmd_code) {
            case CMD_CODE_OP: {
                update_output_u8(state, cmd_data);
                break;
            }
            case CMD_CODE_OP_V: {
                update_output_op_v(state, cmd_data);
                break;
            }
            case CMD_CODE_PUSH_PK: {
                const policy_node_with_key_t *policy =
                    (const policy_node_with_key_t *) node->policy_node;
                uint8_t compressed_pubkey[33];
                if (-1 == get_derived_pubkey(state->dispatcher_context,
                                             state->wdi,
                                             policy->key_placeholder,
                                             compressed_pubkey)) {
                    return -1;
                }

                if (!state->is_taproot) {
                    update_output_u8(state, 33);  // PUSH 33 bytes
                    update_output(state, compressed_pubkey, 33);
                } else {
                    // x-only pubkey if within taproot
                    update_output_u8(state, 32);  // PUSH 32 bytes
                    update_output(state, compressed_pubkey + 1, 32);
                }
                break;
            }
            case CMD_CODE_PUSH_PKH: {
                const policy_node_with_key_t *policy =
                    (const policy_node_with_key_t *) node->policy_node;
                uint8_t compressed_pubkey[33];
                if (-1 == get_derived_pubkey(state->dispatcher_context,
                                             state->wdi,
                                             policy->key_placeholder,
                                             compressed_pubkey)) {
                    return -1;
                }
                crypto_hash160(compressed_pubkey, 33, compressed_pubkey);  // reuse memory

                update_output_u8(state, 20);  // PUSH 20 bytes
                update_output(state, compressed_pubkey, 20);
                break;
            }
            case CMD_CODE_PUSH_UINT32: {
                const policy_node_with_uint32_t *policy =
                    (const policy_node_with_uint32_t *) node->policy_node;
                update_output_push_u32(state, policy->n);
                break;
            }
            case CMD_CODE_PUSH_HASH20: {
                const policy_node_with_hash_160_t *policy =
                    (const policy_node_with_hash_160_t *) node->policy_node;
                update_output_u8(state, 20);
                update_output(state, policy->h, 20);
                break;
            }
            case CMD_CODE_PUSH_HASH32: {
                const policy_node_with_hash_256_t *policy =
                    (const policy_node_with_hash_256_t *) node->policy_node;
                update_output_u8(state, 32);
                update_output(state, policy->h, 32);
                break;
            }
            case CMD_CODE_PROCESS_CHILD: {
                const policy_node_with_scripts_t *policy =
                    (const policy_node_with_scripts_t *) node->policy_node;
                if (0 > state_stack_push(state, resolve_node_ptr(&policy->scripts[cmd_data]), 0)) {
                    return -1;
                }
                break;
            }
            case CMD_CODE_PROCESS_CHILD_V: {
                const policy_node_with_scripts_t *policy =
                    (const policy_node_with_scripts_t *) node->policy_node;
                if (0 > state_stack_push(state,
                                         resolve_node_ptr(&policy->scripts[cmd_data]),
                                         node->flags)) {
                    return -1;
                }
                break;
            }
            case CMD_CODE_PROCESS_CHILD_VV: {
                const policy_node_with_scripts_t *policy =
                    (const policy_node_with_scripts_t *) node->policy_node;
                if (0 > state_stack_push(state,
                                         resolve_node_ptr(&policy->scripts[cmd_data]),
                                         node->flags | PROCESSOR_FLAG_V)) {
                    return -1;
                }
                break;
            }
            default:
                PRINTF("Unexpected command code: %d\n", cmd_code);
                return -1;
        }
        ++node->step;
        return 0;
    }
}

__attribute__((warn_unused_result)) static int process_pkh_wpkh_node(policy_parser_state_t *state,
                                                                     const void *arg) {
    UNUSED(arg);

    PRINT_STACK_POINTER();

    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];

    if (node->step != 0) {
        return -1;
    }

    policy_node_with_key_t *policy = (policy_node_with_key_t *) node->policy_node;

    uint8_t compressed_pubkey[33];

    if (-1 == get_derived_pubkey(state->dispatcher_context,
                                 state->wdi,
                                 policy->key_placeholder,
                                 compressed_pubkey)) {
        return -1;
    } else if (policy->base.type == TOKEN_PKH) {
        update_output_u8(state, OP_DUP);
        update_output_u8(state, OP_HASH160);

        update_output_u8(state, 20);  // PUSH 20 bytes

        crypto_hash160(compressed_pubkey, 33, compressed_pubkey);  // reuse memory
        update_output(state, compressed_pubkey, 20);

        update_output_u8(state, OP_EQUALVERIFY);
        update_output_op_v(state, OP_CHECKSIG);
    } else {  // policy->base.type == TOKEN_WPKH
        update_output_u8(state, OP_0);

        update_output_u8(state, 20);  // PUSH 20 bytes

        crypto_hash160(compressed_pubkey, 33, compressed_pubkey);  // reuse memory
        update_output(state, compressed_pubkey, 20);
    }

    return 1;
}

__attribute__((warn_unused_result)) static int process_thresh_node(policy_parser_state_t *state,
                                                                   const void *arg) {
    UNUSED(arg);

    PRINT_STACK_POINTER();

    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];
    const policy_node_thresh_t *policy = (const policy_node_thresh_t *) node->policy_node;

    // [X1] [X2] ADD ... [Xn] ADD <k> EQUAL

    /*
      It's a bit unnatural to encode thresh in a way that is compatible with our
      stack-based encoder, as every "step" that needs to recur on a child Script
      must emit the child script as its last thing. The natural way of splitting
      this would be:

      [X1]   /   [X2] ADD   /   [X3] ADD   /   ...   /   [Xn] ADD   /   <k> EQUAL

      Instead, we have to split it as follows:

      [X1]   /   [X2]   /   ADD [X3]   /   ...   /   ADD [Xn]   /   ADD <k> EQUAL

      But this is incorrect if n == 1, because the correct encoding is just

      [X1] <k> EQUAL

      Therefore, the case n == 1 needs to be handled separately to avoid the extra ADD.
    */

    // n+1 steps
    // at step i, for 0 <= i < n, we produce [Xi] if i <= 1, or ADD [Xi] otherwise
    // at step n, we produce <k> EQUAL if n == 1, or ADD <k> EQUAL otherwise

    if (node->step < policy->n) {
        // find the current child node
        policy_node_scriptlist_t *cur = policy->scriptlist;
        for (size_t i = 0; i < node->step; i++) {
            cur = cur->next;
        }

        // process child node
        if (node->step > 1) {
            update_output_u8(state, OP_ADD);
        }

        if (-1 == state_stack_push(state, resolve_node_ptr(&cur->script), 0)) {
            return -1;
        }
        ++node->step;
        return 0;
    } else {
        // final step
        if (policy->n >= 2) {
            // no OP_ADD if n == 1, per comment above
            update_output_u8(state, OP_ADD);
        }
        update_output_push_u32(state, policy->k);
        update_output_op_v(state, OP_EQUAL);
        return 1;
    }
}

__attribute__((warn_unused_result)) static int process_multi_sortedmulti_node(
    policy_parser_state_t *state,
    const void *arg) {
    UNUSED(arg);

    PRINT_STACK_POINTER();

    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];
    const policy_node_multisig_t *policy = (const policy_node_multisig_t *) node->policy_node;

    if (policy->n > 16) {
        return WITH_ERROR(-1, "Implemented only for n <= 16");
    }

    // k {pubkey_1} ... {pubkey_n} n OP_CHECKMULTISIG

    update_output_u8(state, 0x50 + policy->k);  // OP_k

    // bitvector of used keys (only relevant for sorting keys in SORTEDMULTI)
    uint8_t used[BITVECTOR_REAL_SIZE(MAX_PUBKEYS_PER_MULTISIG)];
    memset(used, 0, sizeof(used));

    for (int i = 0; i < policy->n; i++) {
        uint8_t compressed_pubkey[33];

        if (policy->base.type == TOKEN_MULTI) {
            if (-1 == get_derived_pubkey(state->dispatcher_context,
                                         state->wdi,
                                         &policy->key_placeholders[i],
                                         compressed_pubkey)) {
                return -1;
            }
        } else {
            // sortedmulti is problematic, especially for very large wallets: we don't have enough
            // memory on Nano S to keep all the keys in memory. Therefore, we use a slow method: at
            // each iteration, find the lexicographically smallest key that was not already used
            // (basically, like in insertion sort). This means quadratic communication with the
            // client, and a quadratic number of pubkey derivations as well, which are quite slow.
            // Performance might become an issue for very large multisig wallets, but this allows us
            // to remove any limitation on the supported number of pubkeys, and to keep the code
            // simple.
            // Should speed be reported as an issue in practice, sorting could be done in-memory for
            // non-Nano S devices, instead (requiring 33*MAX_PUBKEYS_PER_MULTISIG > 500 bytes more
            // memory).

            int smallest_pubkey_index = -1;
            memset(compressed_pubkey, 0xFF, sizeof(compressed_pubkey));  // init to largest value

            for (int j = 0; j < policy->n; j++) {
                if (!bitvector_get(used, j)) {
                    uint8_t cur_pubkey[33];
                    if (-1 == get_derived_pubkey(state->dispatcher_context,
                                                 state->wdi,
                                                 &policy->key_placeholders[j],
                                                 cur_pubkey)) {
                        return -1;
                    }

                    if (cmp_arrays(compressed_pubkey, cur_pubkey, 33) > 0) {
                        memcpy(compressed_pubkey, cur_pubkey, 33);
                        smallest_pubkey_index = j;
                    }
                }
            }
            bitvector_set(used, smallest_pubkey_index, true);  // mark the key as used
        }

        // push <i-th pubkey> (33 = 0x21 bytes)
        update_output_u8(state, 0x21);
        update_output(state, compressed_pubkey, 33);
    }

    update_output_u8(state, 0x50 + policy->n);    // OP_n
    update_output_op_v(state, OP_CHECKMULTISIG);  // OP_CHECKMULTISIG

    return 1;
}

__attribute__((warn_unused_result)) static int process_multi_a_sortedmulti_a_node(
    policy_parser_state_t *state,
    const void *arg) {
    UNUSED(arg);

    PRINT_STACK_POINTER();

    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];
    const policy_node_multisig_t *policy = (const policy_node_multisig_t *) node->policy_node;

    if (policy->k > 16) {
        return WITH_ERROR(-1, "Implemented only for k <= 16");
    }

    // <pk_1> OP_CHECKSIG <pk_2> OP_CHECKSIGADD ... <pk_n> OP_CHECKSIGADD <k> OP_NUMEQUAL

    // bitvector of used keys (only relevant for sorting keys in SORTEDMULTI)
    uint8_t used[BITVECTOR_REAL_SIZE(MAX_PUBKEYS_PER_MULTISIG)];
    memset(used, 0, sizeof(memset));

    for (int i = 0; i < policy->n; i++) {
        uint8_t compressed_pubkey[33];

        if (policy->base.type == TOKEN_MULTI_A) {
            if (-1 == get_derived_pubkey(state->dispatcher_context,
                                         state->wdi,
                                         &policy->key_placeholders[i],
                                         compressed_pubkey)) {
                return -1;
            }
        } else {
            // Inefficient O(n^2) sorting; check process_multi_sortedmulti_node for the motivation.

            int smallest_pubkey_index = -1;
            memset(compressed_pubkey, 0xFF, sizeof(compressed_pubkey));  // init to largest value

            for (int j = 0; j < policy->n; j++) {
                if (!bitvector_get(used, j)) {
                    uint8_t cur_pubkey[33];
                    if (-1 == get_derived_pubkey(state->dispatcher_context,
                                                 state->wdi,
                                                 &policy->key_placeholders[j],
                                                 cur_pubkey)) {
                        return -1;
                    }

                    // x-only pubkeys must be compared ignoring the first byte
                    if (cmp_arrays(compressed_pubkey + 1, cur_pubkey + 1, 32) > 0) {
                        memcpy(compressed_pubkey, cur_pubkey, 33);
                        smallest_pubkey_index = j;
                    }
                }
            }
            bitvector_set(used, smallest_pubkey_index, true);  // mark the key as used
        }

        // push <i-th pubkey> as x-only key (32 = 0x20 bytes)
        update_output_u8(state, 0x20);
        update_output(state, compressed_pubkey + 1, 32);

        if (i == 0) {
            update_output_u8(state, OP_CHECKSIG);
        } else {
            update_output_u8(state, OP_CHECKSIGADD);
        }
    }

    update_output_u8(state, 0x50 + policy->k);  // <k>
    update_output_op_v(state, OP_NUMEQUAL);     // OP_NUMEQUAL

    return 1;
}

__attribute__((warn_unused_result, noinline)) static int compute_tapleaf_hash(
    dispatcher_context_t *dispatcher_context,
    const wallet_derivation_info_t *wdi,
    const policy_node_t *script_policy,
    uint8_t out[static 32]) {
    cx_sha256_t hash_context;
    crypto_tr_tapleaf_hash_init(&hash_context);

    // we compute the tapscript once just to compute its length
    // this avoids having to store the script in memory
    int tapscript_len = get_wallet_internal_script_hash(dispatcher_context,
                                                        script_policy,
                                                        wdi,
                                                        WRAPPED_SCRIPT_TYPE_TAPSCRIPT,
                                                        NULL);

    if (tapscript_len < 0) {
        return WITH_ERROR(-1, "Failed to compute tapleaf script");
    }

    crypto_hash_update_u8(&hash_context.header, 0xC0);
    crypto_hash_update_varint(&hash_context.header, tapscript_len);

    if (0 > get_wallet_internal_script_hash(dispatcher_context,
                                            script_policy,
                                            wdi,
                                            WRAPPED_SCRIPT_TYPE_TAPSCRIPT,
                                            &hash_context.header)) {
        return WITH_ERROR(-1, "Failed to compute tapscript hash");  // should never happen!
    }

    crypto_hash_digest(&hash_context.header, out, 32);
    return 0;
}

// Separated from compute_taptree_hash to optimize its stack usage
__attribute__((warn_unused_result, noinline)) static int compute_and_combine_taptree_child_hashes(
    dispatcher_context_t *dc,
    const wallet_derivation_info_t *wdi,
    const policy_node_tree_t *tree,
    uint8_t out[static 32]) {
    uint8_t left_h[32], right_h[32];
    if (0 > compute_taptree_hash(dc, wdi, resolve_ptr(&tree->left_tree), left_h)) return -1;
    if (0 > compute_taptree_hash(dc, wdi, resolve_ptr(&tree->right_tree), right_h)) return -1;
    crypto_tr_combine_taptree_hashes(left_h, right_h, out);
    return 0;
}

// See taproot_tree_helper in BIP-0341
__attribute__((noinline)) int compute_taptree_hash(dispatcher_context_t *dc,
                                                   const wallet_derivation_info_t *wdi,
                                                   const policy_node_tree_t *tree,
                                                   uint8_t out[static 32]) {
    if (tree->is_leaf)
        return compute_tapleaf_hash(dc, wdi, resolve_node_ptr(&tree->script), out);
    else
        return compute_and_combine_taptree_child_hashes(dc, wdi, tree, out);
}

#pragma GCC diagnostic push
// make sure that the compiler gives an error if any PolicyNodeType is missed
#pragma GCC diagnostic error "-Wswitch-enum"

int get_wallet_script(dispatcher_context_t *dispatcher_context,
                      const policy_node_t *policy,
                      const wallet_derivation_info_t *wdi,
                      uint8_t out[static 34]) {
    int script_type = -1;

    cx_sha256_t hash_context;
    cx_sha256_init(&hash_context);

    if (policy->type == TOKEN_PKH) {
        uint8_t compressed_pubkey[33];
        policy_node_with_key_t *pkh_policy = (policy_node_with_key_t *) policy;
        if (0 > get_derived_pubkey(dispatcher_context,
                                   wdi,
                                   pkh_policy->key_placeholder,
                                   compressed_pubkey)) {
            return -1;
        }
        out[0] = OP_DUP;
        out[1] = OP_HASH160;

        out[2] = 20;  // PUSH 20 bytes

        crypto_hash160(compressed_pubkey, 33, out + 3);

        out[23] = OP_EQUALVERIFY;
        out[24] = OP_CHECKSIG;
        return 25;
    } else if (policy->type == TOKEN_WPKH) {
        uint8_t compressed_pubkey[33];
        policy_node_with_key_t *wpkh_policy = (policy_node_with_key_t *) policy;
        if (0 > get_derived_pubkey(dispatcher_context,
                                   wdi,
                                   wpkh_policy->key_placeholder,
                                   compressed_pubkey)) {
            return -1;
        }
        out[0] = OP_0;
        out[1] = 20;  // PUSH 20 bytes

        crypto_hash160(compressed_pubkey, 33, out + 2);

        return 22;
    } else if (policy->type == TOKEN_SH || policy->type == TOKEN_WSH) {
        const policy_node_t *core_policy;
        if (policy->type == TOKEN_SH) {
            const policy_node_t *child =
                resolve_node_ptr(&((const policy_node_with_script_t *) policy)->script);
            if (child->type == TOKEN_WSH) {
                script_type = WRAPPED_SCRIPT_TYPE_SH_WSH;
                core_policy =
                    resolve_node_ptr(&((const policy_node_with_script_t *) child)->script);
            } else {
                script_type = WRAPPED_SCRIPT_TYPE_SH;
                core_policy = child;
            }
        } else {  // if (policy->type == TOKEN_WSH
            script_type = WRAPPED_SCRIPT_TYPE_WSH;
            core_policy = resolve_node_ptr(&((const policy_node_with_script_t *) policy)->script);
        }

        if (0 > get_wallet_internal_script_hash(dispatcher_context,
                                                core_policy,
                                                wdi,
                                                script_type,
                                                &hash_context.header)) {
            return -1;
        }

        uint8_t script_hash[32];
        crypto_hash_digest(&hash_context.header, script_hash, 32);

        switch (script_type) {
            case WRAPPED_SCRIPT_TYPE_SH:
            case WRAPPED_SCRIPT_TYPE_SH_WSH: {
                if (script_type == WRAPPED_SCRIPT_TYPE_SH_WSH) {
                    cx_sha256_init(&hash_context);
                    crypto_hash_update_u8(&hash_context.header, OP_0);

                    crypto_hash_update_u8(&hash_context.header, 32);  // PUSH 32 bytes
                    crypto_hash_update(&hash_context.header, script_hash, 32);

                    crypto_hash_digest(&hash_context.header, script_hash, 32);
                }

                out[0] = OP_HASH160;
                out[1] = 20;  // PUSH 20 bytes

                crypto_ripemd160(script_hash, 32, out + 2);

                out[22] = OP_EQUAL;
                return 1 + 1 + 20 + 1;
            }
            case WRAPPED_SCRIPT_TYPE_WSH: {
                out[0] = OP_0;
                out[1] = 32;  // PUSH 32 bytes

                memcpy(out + 2, script_hash, 32);

                return 1 + 1 + 32;
            }
            default: {
                // This should never happen!
                return -1;
            }
        }
    } else if (policy->type == TOKEN_TR) {
        policy_node_tr_t *tr_policy = (policy_node_tr_t *) policy;

        uint8_t compressed_pubkey[33];

        if (0 > get_derived_pubkey(dispatcher_context,
                                   wdi,
                                   tr_policy->key_placeholder,
                                   compressed_pubkey)) {
            return -1;
        }

        out[0] = OP_1;
        out[1] = 32;  // PUSH 32 bytes

        // uint8_t h[32];
        uint8_t *h = out + 2;  // hack: re-use the output array to save memory

        int h_length = 0;
        if (tr_policy->tree != NULL) {
            if (0 > compute_taptree_hash(dispatcher_context, wdi, tr_policy->tree, h)) {
                return -1;
            }
            h_length = 32;
        }

        uint8_t parity;
        crypto_tr_tweak_pubkey(compressed_pubkey + 1, h, h_length, &parity, out + 2);

        return 34;
    }

    PRINTF("Invalid or unsupported top-level script\n");
    return -1;
}

__attribute__((noinline)) int get_wallet_internal_script_hash(
    dispatcher_context_t *dispatcher_context,
    const policy_node_t *policy,
    const wallet_derivation_info_t *wdi,
    internal_script_type_e script_type,
    cx_hash_t *hash_context) {
    const uint8_t *whitelist;
    size_t whitelist_len;
    switch (script_type) {
        case WRAPPED_SCRIPT_TYPE_SH:
            whitelist = fragment_whitelist_sh;
            whitelist_len = sizeof(fragment_whitelist_sh);
            break;
        case WRAPPED_SCRIPT_TYPE_SH_WSH:
            whitelist = fragment_whitelist_sh_wsh;
            whitelist_len = sizeof(fragment_whitelist_sh_wsh);
            break;
        case WRAPPED_SCRIPT_TYPE_WSH:
            whitelist = fragment_whitelist_wsh;
            whitelist_len = sizeof(fragment_whitelist_wsh);
            break;
        case WRAPPED_SCRIPT_TYPE_TAPSCRIPT:
            whitelist = fragment_whitelist_tapscript;
            whitelist_len = sizeof(fragment_whitelist_tapscript);
            break;
        default:
            PRINTF("Unexpected script_type: %d\n", script_type);
            return -1;
    }

    policy_parser_state_t state = {.dispatcher_context = dispatcher_context,
                                   .wdi = wdi,
                                   .is_taproot = (script_type == WRAPPED_SCRIPT_TYPE_TAPSCRIPT),
                                   .node_stack_eos = 0,
                                   .hash_context = hash_context};

    state.nodes[0] =
        (policy_parser_node_state_t){.length = 0, .flags = 0, .step = 0, .policy_node = policy};

    int ret;
    do {
        const policy_parser_node_state_t *node = &state.nodes[state.node_stack_eos];

        bool is_whitelisted = false;
        for (size_t i = 0; i < whitelist_len; i++) {
            if (node->policy_node->type == whitelist[i]) {
                is_whitelisted = true;
                break;
            }
        }

        if (!is_whitelisted) {
            PRINTF("Fragment %d not allowed in script type %d\n",
                   node->policy_node->type,
                   script_type);
            return -1;
        }

        switch (node->policy_node->type) {
            case TOKEN_0:
                ret = execute_processor(&state, process_generic_node, commands_0);
                break;
            case TOKEN_1:
                ret = execute_processor(&state, process_generic_node, commands_1);
                break;
            case TOKEN_PK_K:
                ret = execute_processor(&state, process_generic_node, commands_pk_k);
                break;
            case TOKEN_PK_H:
                ret = execute_processor(&state, process_generic_node, commands_pk_h);
                break;
            case TOKEN_PK:
                ret = execute_processor(&state, process_generic_node, commands_pk);
                break;
            case TOKEN_PKH:
            case TOKEN_WPKH:
                ret = execute_processor(&state, process_pkh_wpkh_node, NULL);
                break;
            case TOKEN_OLDER:
                ret = execute_processor(&state, process_generic_node, commands_older);
                break;
            case TOKEN_AFTER:
                ret = execute_processor(&state, process_generic_node, commands_after);
                break;

            case TOKEN_SHA256:
                ret = execute_processor(&state, process_generic_node, commands_sha256);
                break;
            case TOKEN_HASH256:
                ret = execute_processor(&state, process_generic_node, commands_hash256);
                break;
            case TOKEN_RIPEMD160:
                ret = execute_processor(&state, process_generic_node, commands_ripemd160);
                break;
            case TOKEN_HASH160:
                ret = execute_processor(&state, process_generic_node, commands_hash160);
                break;

            case TOKEN_ANDOR:
                ret = execute_processor(&state, process_generic_node, commands_andor);
                break;
            case TOKEN_AND_V:
                ret = execute_processor(&state, process_generic_node, commands_and_v);
                break;
            case TOKEN_AND_B:
                ret = execute_processor(&state, process_generic_node, commands_and_b);
                break;
            case TOKEN_AND_N:
                ret = execute_processor(&state, process_generic_node, commands_and_n);
                break;

            case TOKEN_OR_B:
                ret = execute_processor(&state, process_generic_node, commands_or_b);
                break;
            case TOKEN_OR_C:
                ret = execute_processor(&state, process_generic_node, commands_or_c);
                break;
            case TOKEN_OR_D:
                ret = execute_processor(&state, process_generic_node, commands_or_d);
                break;
            case TOKEN_OR_I:
                ret = execute_processor(&state, process_generic_node, commands_or_i);
                break;

            case TOKEN_THRESH:
                ret = execute_processor(&state, process_thresh_node, NULL);
                break;

            case TOKEN_MULTI:
            case TOKEN_SORTEDMULTI:
                ret = execute_processor(&state, process_multi_sortedmulti_node, NULL);
                break;
            case TOKEN_MULTI_A:
            case TOKEN_SORTEDMULTI_A:
                ret = execute_processor(&state, process_multi_a_sortedmulti_a_node, NULL);
                break;
            case TOKEN_A:
                ret = execute_processor(&state, process_generic_node, commands_a);
                break;
            case TOKEN_S:
                ret = execute_processor(&state, process_generic_node, commands_s);
                break;
            case TOKEN_C:
                ret = execute_processor(&state, process_generic_node, commands_c);
                break;
            case TOKEN_T:
                ret = execute_processor(&state, process_generic_node, commands_t);
                break;
            case TOKEN_D:
                ret = execute_processor(&state, process_generic_node, commands_d);
                break;
            case TOKEN_V:
                ret = execute_processor(&state, process_generic_node, commands_v);
                break;
            case TOKEN_J:
                ret = execute_processor(&state, process_generic_node, commands_j);
                break;
            case TOKEN_N:
                ret = execute_processor(&state, process_generic_node, commands_n);
                break;
            case TOKEN_L:
                ret = execute_processor(&state, process_generic_node, commands_l);
                break;
            case TOKEN_U:
                ret = execute_processor(&state, process_generic_node, commands_u);
                break;
            case TOKEN_TR:
            case TOKEN_SH:
            case TOKEN_WSH:
                PRINTF("Unexpected token type: %d\n", node->policy_node->type);
                return -1;

            case TOKEN_INVALID:
            default:
                PRINTF("Unknown token type: %d\n", node->policy_node->type);
                return -1;
        }
    } while (ret >= 0 && state.node_stack_eos >= 0);

    if (ret < 0) {
        return WITH_ERROR(ret, "Processor failed");
    }

    return ret;
}

#pragma GCC diagnostic pop

// For a standard descriptor template, return the corresponding BIP44 purpose
// Otherwise, returns -1.
static int get_bip44_purpose(const policy_node_t *descriptor_template) {
    const policy_node_key_placeholder_t *kp = NULL;
    int purpose = -1;
    switch (descriptor_template->type) {
        case TOKEN_PKH:
            kp = ((const policy_node_with_key_t *) descriptor_template)->key_placeholder;
            purpose = 44;  // legacy
            break;
        case TOKEN_WPKH:
            kp = ((const policy_node_with_key_t *) descriptor_template)->key_placeholder;
            purpose = 84;  // native segwit
            break;
        case TOKEN_SH: {
            const policy_node_t *inner = resolve_node_ptr(
                &((const policy_node_with_script_t *) descriptor_template)->script);
            if (inner->type != TOKEN_WPKH) {
                return -1;
            }

            kp = ((const policy_node_with_key_t *) inner)->key_placeholder;
            purpose = 49;  // nested segwit
            break;
        }
        case TOKEN_TR:
            if (((const policy_node_tr_t *) descriptor_template)->tree != NULL) {
                return -1;
            }

            kp = ((const policy_node_tr_t *) descriptor_template)->key_placeholder;
            purpose = 86;  // standard single-key P2TR
            break;
        default:
            return -1;
    }

    if (kp->key_index != 0 || kp->num_first != 0 || kp->num_second != 1) {
        return -1;
    }

    return purpose;
}

bool is_wallet_policy_standard(dispatcher_context_t *dispatcher_context,
                               const policy_map_wallet_header_t *wallet_policy_header,
                               const policy_node_t *descriptor_template) {
    // Based on the address type, we set the expected bip44 purpose
    int bip44_purpose = get_bip44_purpose(descriptor_template);
    if (bip44_purpose < 0) {
        PRINTF("Non-standard policy, and no hmac provided\n");
        return false;
    }

    if (wallet_policy_header->n_keys != 1) {
        PRINTF("Standard wallets must have exactly 1 key\n");
        return false;
    }

    // we check if the key is indeed internal
    uint32_t master_key_fingerprint = crypto_get_master_key_fingerprint();

    uint8_t key_info_str[MAX_POLICY_KEY_INFO_LEN];
    int key_info_len = call_get_merkle_leaf_element(dispatcher_context,
                                                    wallet_policy_header->keys_info_merkle_root,
                                                    wallet_policy_header->n_keys,
                                                    0,  // only one key
                                                    key_info_str,
                                                    sizeof(key_info_str));
    if (key_info_len < 0) {
        return false;
    }

    // Make a sub-buffer for the pubkey info
    buffer_t key_info_buffer = buffer_create(key_info_str, key_info_len);

    policy_map_key_info_t key_info;
    if (0 > parse_policy_map_key_info(&key_info_buffer, &key_info, wallet_policy_header->version)) {
        return false;
    }

    if (!key_info.has_key_origin) {
        return false;
    }

    if (read_u32_be(key_info.master_key_fingerprint, 0) != master_key_fingerprint) {
        return false;
    }

    // generate pubkey and check if it matches
    serialized_extended_pubkey_t derived_pubkey;
    if (0 > get_extended_pubkey_at_path(key_info.master_key_derivation,
                                        key_info.master_key_derivation_len,
                                        BIP32_PUBKEY_VERSION,
                                        &derived_pubkey)) {
        PRINTF("Failed to derive pubkey\n");
        return false;
    }

    if (memcmp(&key_info.ext_pubkey, &derived_pubkey, sizeof(derived_pubkey)) != 0) {
        return false;
    }

    // check if derivation path of the key is indeed standard

    // per BIP-0044, derivation must be
    // m / purpose' / coin_type' / account'

    const uint32_t H = BIP32_FIRST_HARDENED_CHILD;
    if (key_info.master_key_derivation_len != 3 ||
        key_info.master_key_derivation[0] != H + bip44_purpose ||
        key_info.master_key_derivation[1] != H + BIP44_COIN_TYPE ||
        key_info.master_key_derivation[2] < H ||
        key_info.master_key_derivation[2] > H + MAX_BIP44_ACCOUNT_RECOMMENDED) {
        return false;
    }

    return true;
}

bool compute_wallet_hmac(const uint8_t wallet_id[static 32], uint8_t wallet_hmac[static 32]) {
    uint8_t key[32];

    bool result = false;

    if (!crypto_derive_symmetric_key(WALLET_SLIP0021_LABEL, WALLET_SLIP0021_LABEL_LEN, key)) {
        goto end;
    }

    cx_hmac_sha256(key, sizeof(key), wallet_id, 32, wallet_hmac, 32);

    result = true;

end:
    explicit_bzero(key, sizeof(key));

    return result;
}

bool check_wallet_hmac(const uint8_t wallet_id[static 32], const uint8_t wallet_hmac[static 32]) {
    uint8_t key[32];
    uint8_t correct_hmac[32];

    bool result = false;

    if (!crypto_derive_symmetric_key(WALLET_SLIP0021_LABEL, WALLET_SLIP0021_LABEL_LEN, key)) {
        goto end;
    }

    cx_hmac_sha256(key, sizeof(key), wallet_id, 32, correct_hmac, 32);

    // It is important to use a constant-time function to compare the hmac,
    // to avoid timing-attack that could be exploited to extract it.
    result = os_secure_memcmp((void *) wallet_hmac, (void *) correct_hmac, 32) == 0;

end:
    explicit_bzero(key, sizeof(key));
    explicit_bzero(correct_hmac, sizeof(correct_hmac));

    return result;
}

#pragma GCC diagnostic push
// make sure that the compiler gives an error if any PolicyNodeType is missed
#pragma GCC diagnostic error "-Wswitch-enum"

static int get_key_placeholder_by_index_in_tree(const policy_node_tree_t *tree,
                                                unsigned int i,
                                                const policy_node_t **out_tapleaf_ptr,
                                                policy_node_key_placeholder_t *out_placeholder) {
    if (tree->is_leaf) {
        int ret =
            get_key_placeholder_by_index(resolve_node_ptr(&tree->script), i, NULL, out_placeholder);
        if (ret >= 0 && out_tapleaf_ptr != NULL && i < (unsigned) ret) {
            *out_tapleaf_ptr = resolve_ptr(&tree->script);
        }
        return ret;
    } else {
        int ret1 = get_key_placeholder_by_index_in_tree(
            (policy_node_tree_t *) resolve_ptr(&tree->left_tree),
            i,
            out_tapleaf_ptr,
            out_placeholder);
        if (ret1 < 0) return -1;

        bool found = i < (unsigned int) ret1;

        int ret2 = get_key_placeholder_by_index_in_tree(
            (policy_node_tree_t *) resolve_ptr(&tree->right_tree),
            found ? 0 : i - ret1,
            found ? NULL : out_tapleaf_ptr,
            found ? NULL : out_placeholder);
        if (ret2 < 0) return -1;

        return ret1 + ret2;
    }
}

int get_key_placeholder_by_index(const policy_node_t *policy,
                                 unsigned int i,
                                 const policy_node_t **out_tapleaf_ptr,
                                 policy_node_key_placeholder_t *out_placeholder) {
    // make sure that out_placeholder is a valid pointer, if the output is not needed
    policy_node_key_placeholder_t tmp;
    if (out_placeholder == NULL) {
        out_placeholder = &tmp;
    }

    switch (policy->type) {
        // terminal nodes with absolutely no keys
        case TOKEN_0:
        case TOKEN_1:
        case TOKEN_OLDER:
        case TOKEN_AFTER:
        case TOKEN_SHA256:
        case TOKEN_HASH256:
        case TOKEN_RIPEMD160:
        case TOKEN_HASH160:
            return 0;

        // terminal nodes with exactly 1 key
        case TOKEN_PK_K:
        case TOKEN_PK_H:
        case TOKEN_PK:
        case TOKEN_PKH:
        case TOKEN_WPKH: {
            if (i == 0) {
                memcpy(out_placeholder,
                       ((policy_node_with_key_t *) policy)->key_placeholder,
                       sizeof(policy_node_key_placeholder_t));
            }
            return 1;
        }
        case TOKEN_TR: {
            if (i == 0) {
                memcpy(out_placeholder,
                       ((policy_node_tr_t *) policy)->key_placeholder,
                       sizeof(policy_node_key_placeholder_t));
            }
            if (((policy_node_tr_t *) policy)->tree != NULL) {
                int ret_tree = get_key_placeholder_by_index_in_tree(
                    ((policy_node_tr_t *) policy)->tree,
                    i == 0 ? 0 : i - 1,
                    i == 0 ? NULL : out_tapleaf_ptr,
                    i == 0 ? NULL : out_placeholder);  // if i == 0, we already found it; so we
                                                       // recur with out_placeholder set to NULL
                if (ret_tree < 0) {
                    return -1;
                }
                return 1 + ret_tree;
            } else {
                return 1;
            }
        }

        // terminal nodes with multiple keys
        case TOKEN_MULTI:
        case TOKEN_MULTI_A:
        case TOKEN_SORTEDMULTI:
        case TOKEN_SORTEDMULTI_A: {
            const policy_node_multisig_t *node = (const policy_node_multisig_t *) policy;

            if (i < (unsigned int) node->n) {
                memcpy(out_placeholder,
                       &node->key_placeholders[i],
                       sizeof(policy_node_key_placeholder_t));
            }

            return node->n;
        }

        // nodes with a single child script (including miniscript wrappers)
        case TOKEN_SH:
        case TOKEN_WSH:
        case TOKEN_A:
        case TOKEN_S:
        case TOKEN_C:
        case TOKEN_T:
        case TOKEN_D:
        case TOKEN_V:
        case TOKEN_J:
        case TOKEN_N:
        case TOKEN_L:
        case TOKEN_U: {
            return get_key_placeholder_by_index(
                resolve_node_ptr(&((const policy_node_with_script_t *) policy)->script),
                i,
                out_tapleaf_ptr,
                out_placeholder);
        }

        // nodes with exactly two child scripts
        case TOKEN_AND_V:
        case TOKEN_AND_B:
        case TOKEN_AND_N:
        case TOKEN_OR_B:
        case TOKEN_OR_C:
        case TOKEN_OR_D:
        case TOKEN_OR_I: {
            const policy_node_with_script2_t *node = (const policy_node_with_script2_t *) policy;
            int ret1 = get_key_placeholder_by_index(resolve_node_ptr(&node->scripts[0]),
                                                    i,
                                                    out_tapleaf_ptr,
                                                    out_placeholder);
            if (ret1 < 0) return -1;

            bool found = i < (unsigned int) ret1;
            int ret2 = get_key_placeholder_by_index(resolve_node_ptr(&node->scripts[1]),
                                                    found ? 0 : i - ret1,
                                                    found ? NULL : out_tapleaf_ptr,
                                                    found ? NULL : out_placeholder);
            if (ret2 < 0) return -1;

            return ret1 + ret2;
        }

        // nodes with exactly three child scripts
        case TOKEN_ANDOR: {
            const policy_node_with_script3_t *node = (const policy_node_with_script3_t *) policy;
            int ret1 = get_key_placeholder_by_index(resolve_node_ptr(&node->scripts[0]),
                                                    i,
                                                    out_tapleaf_ptr,
                                                    out_placeholder);
            if (ret1 < 0) return -1;

            bool found = i < (unsigned int) ret1;
            int ret2 = get_key_placeholder_by_index(resolve_node_ptr(&node->scripts[1]),
                                                    found ? 0 : i - ret1,
                                                    found ? NULL : out_tapleaf_ptr,
                                                    found ? NULL : out_placeholder);
            if (ret2 < 0) return -1;

            found = i < (unsigned int) (ret1 + ret2);
            int ret3 = get_key_placeholder_by_index(resolve_node_ptr(&node->scripts[2]),
                                                    found ? 0 : i - ret1 - ret2,
                                                    found ? NULL : out_tapleaf_ptr,
                                                    found ? NULL : out_placeholder);
            if (ret3 < 0) return -1;
            return ret1 + ret2 + ret3;
        }

        // nodes with multiple child scripts
        case TOKEN_THRESH: {
            const policy_node_thresh_t *node = (const policy_node_thresh_t *) policy;
            bool found;
            int ret = 0;
            policy_node_scriptlist_t *cur_child = node->scriptlist;
            for (int script_idx = 0; script_idx < node->n; script_idx++) {
                found = i < (unsigned int) ret;
                int ret_partial = get_key_placeholder_by_index(resolve_node_ptr(&cur_child->script),
                                                               found ? 0 : i - ret,
                                                               found ? NULL : out_tapleaf_ptr,
                                                               found ? NULL : out_placeholder);
                if (ret_partial < 0) return -1;

                ret += ret_partial;
                cur_child = cur_child->next;
            }
            return ret;
        }

        case TOKEN_INVALID:
        default:
            PRINTF("Unknown token type: %d\n", policy->type);
            return -1;
    }

    // unreachable
    assert(0);
    return -1;
}

int count_distinct_keys_info(const policy_node_t *policy) {
    policy_node_key_placeholder_t placeholder;
    int ret = -1, cur, n_placeholders;

    for (cur = 0;
         cur < (n_placeholders = get_key_placeholder_by_index(policy, cur, NULL, &placeholder));
         ++cur) {
        if (n_placeholders < 0) {
            return -1;
        }
        ret = MAX(ret, placeholder.key_index + 1);
    }
    return ret;
}

// Utility function to extract and decode the i-th xpub from the keys information vector
static int get_pubkey_from_merkle_tree(dispatcher_context_t *dispatcher_context,
                                       int wallet_version,
                                       const uint8_t keys_merkle_root[static 32],
                                       uint32_t n_keys,
                                       uint32_t index,
                                       serialized_extended_pubkey_t *out) {
    char key_info_str[MAX_POLICY_KEY_INFO_LEN];
    int key_info_len = call_get_merkle_leaf_element(dispatcher_context,
                                                    keys_merkle_root,
                                                    n_keys,
                                                    index,
                                                    (uint8_t *) key_info_str,
                                                    sizeof(key_info_str));
    if (key_info_len == -1) {
        return WITH_ERROR(-1, "Failed to retrieve key info");
    }

    // Make a sub-buffer for the pubkey info
    buffer_t key_info_buffer = buffer_create(key_info_str, key_info_len);

    policy_map_key_info_t key_info;
    if (parse_policy_map_key_info(&key_info_buffer, &key_info, wallet_version) == -1) {
        return WITH_ERROR(-1, "Failed to parse key information");
    }
    *out = key_info.ext_pubkey;
    return 0;
}

int is_policy_sane(dispatcher_context_t *dispatcher_context,
                   const policy_node_t *policy,
                   int wallet_version,
                   const uint8_t keys_merkle_root[static 32],
                   uint32_t n_keys) {
    if (policy->type == TOKEN_WSH) {
        const policy_node_t *inner =
            resolve_node_ptr(&((const policy_node_with_script_t *) policy)->script);
        if (inner->flags.is_miniscript) {
            // Top level node in miniscript must be type B
            if (inner->flags.miniscript_type != MINISCRIPT_TYPE_B) {
                return WITH_ERROR(-1, "Top level miniscript node must be of type B");
            }

            // check miniscript sanity conditions
            policy_node_ext_info_t ext_info;
            if (0 > compute_miniscript_policy_ext_info(inner, &ext_info)) {
                return WITH_ERROR(-1, "Error analyzing miniscript policy");
            }

            // Check that non-malleability can be guaranteed
            if (!ext_info.m) {
                return WITH_ERROR(-1, "Miniscript cannot always be satisfied non-malleably");
            }

            // Check that a signature is always required to satisfy the miniscript
            if (!ext_info.s) {
                return WITH_ERROR(-1, "Miniscript does not always require a signature");
            }

            // Check that there is no time-lock mix
            if (!ext_info.k) {
                return WITH_ERROR(-1, "Miniscript with time-lock mix");
            }

            // Check the maximum stack size to satisfy the policy
            if (ext_info.ss.sat == -1 ||
                (uint32_t) ext_info.ss.sat > MAX_STANDARD_P2WSH_STACK_ITEMS) {
                return WITH_ERROR(-1, "Miniscript exceeds maximum standard stack size");
            }

            if (ext_info.ops.sat == -1) {
                // Should never happen for non-malleable scripts
                return WITH_ERROR(-1, "Invalid maximum ops computations");
            }

            // Check ops limit
            if ((uint32_t) ext_info.ops.count + (uint32_t) ext_info.ops.sat > MAX_OPS_PER_SCRIPT) {
                return WITH_ERROR(-1, "Miniscript exceeds maximum ops");
            }

            // Check the script size
            if (ext_info.script_size > MAX_STANDARD_P2WSH_SCRIPT_SIZE) {
                return WITH_ERROR(-1, "Miniscript exceeds maximum script size");
            }
        }
    }

    // check that all the xpubs are different
    for (unsigned int i = 0; i < n_keys - 1; i++) {  // no point in running this for the last key
        serialized_extended_pubkey_t pubkey_i;
        if (0 > get_pubkey_from_merkle_tree(dispatcher_context,
                                            wallet_version,
                                            keys_merkle_root,
                                            n_keys,
                                            i,
                                            &pubkey_i)) {
            return -1;
        }

        for (unsigned int j = i + 1; j < n_keys; j++) {
            serialized_extended_pubkey_t pubkey_j;
            if (0 > get_pubkey_from_merkle_tree(dispatcher_context,
                                                wallet_version,
                                                keys_merkle_root,
                                                n_keys,
                                                j,
                                                &pubkey_j)) {
                return -1;
            }

            // We reject if any two xpubs have the same pubkey
            // Conservatively, we only compare the compressed pubkey, rather than the whole xpub:
            // there is no good reason for allowing two different xpubs with the same pubkey.
            if (memcmp(pubkey_i.compressed_pubkey,
                       pubkey_j.compressed_pubkey,
                       sizeof(pubkey_i.compressed_pubkey)) == 0) {
                // duplicated pubkey
                return WITH_ERROR(-1, "Repeated pubkey in wallet policy");
            }
        }
    }

    // check that all the key placeholders for the same xpub do indeed have different
    // derivations
    int n_placeholders = get_key_placeholder_by_index(policy, 0, NULL, NULL);
    if (n_placeholders < 0) {
        return WITH_ERROR(-1, "Unexpected error while counting placeholders");
    }

    // The following loop computationally very inefficient (quadratic in the number of
    // placeholders), but more efficient solutions likely require a substantial amount of RAM
    // (proportional to the number of key placeholders). Instead, this only requires stack depth
    // proportional to the depth of the wallet policy's abstract syntax tree.
    for (int i = 0; i < n_placeholders - 1;
         i++) {  // no point in running this for the last placeholder
        policy_node_key_placeholder_t kp_i;
        if (0 > get_key_placeholder_by_index(policy, i, NULL, &kp_i)) {
            return WITH_ERROR(-1, "Unexpected error retrieving placeholders from the policy");
        }
        for (int j = i + 1; j < n_placeholders; j++) {
            policy_node_key_placeholder_t kp_j;
            if (0 > get_key_placeholder_by_index(policy, j, NULL, &kp_j)) {
                return WITH_ERROR(-1, "Unexpected error retrieving placeholders from the policy");
            }

            // placeholders for the same key must have disjoint derivation options
            if (kp_i.key_index == kp_j.key_index) {
                if (kp_i.num_first == kp_j.num_first || kp_i.num_first == kp_j.num_second ||
                    kp_i.num_second == kp_j.num_first || kp_i.num_second == kp_j.num_second) {
                    return WITH_ERROR(-1,
                                      "Key placeholders with repeated derivations in miniscript");
                }
            }
        }
    }
    return 0;
}

#pragma GCC diagnostic pop
