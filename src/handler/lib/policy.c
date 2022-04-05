#include <stdlib.h>

#include "policy.h"

#include "../lib/get_merkle_leaf_element.h"
#include "../../crypto.h"
#include "../../common/base58.h"
#include "../../common/script.h"
#include "../../common/segwit_addr.h"

#include "debug-helpers/debug.h"

extern global_context_t G_context;

#define MAX_POLICY_DEPTH 10

#define MODE_OUT_BYTES 0
#define MODE_OUT_HASH  1

// The last opcode must be processed as a VERIFY flag
#define PROCESSOR_FLAG_V 1

// The last processor ran out of output space
#define PROCESSOR_FLAG_OUTPUT_OVERFLOW 128

typedef struct {
    const policy_node_t *policy_node;

    // Only one of the two is used, depending on the `mode`
    union {
        cx_sha256_t *hash_context;
        buffer_t *out_buf;
    };

    // bytes written to output
    uint16_t length;
    // used to identify the stage of execution for nodes that require multiple rounds
    uint8_t step;

    // MODE_OUT_BYTES if the current node is outputting the actual script bytes, or MODE_OUT_HASH
    // if it is outputting the script hash
    uint8_t mode;
    uint8_t flags;
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

const generic_processor_command_t commands_0[] = {{CMD_CODE_OP_V, OP_0}, {CMD_CODE_END, 0}};
const generic_processor_command_t commands_1[] = {{CMD_CODE_OP_V, OP_1}, {CMD_CODE_END, 0}};
const generic_processor_command_t commands_pk_k[] = {{CMD_CODE_PUSH_PK, 0}, {CMD_CODE_END, 0}};
const generic_processor_command_t commands_pk_h[] = {{CMD_CODE_OP, OP_DUP},
                                                     {CMD_CODE_OP, OP_HASH160},
                                                     {CMD_CODE_PUSH_PKH, 0},
                                                     {CMD_CODE_OP, OP_EQUALVERIFY},
                                                     {CMD_CODE_END, 0}};
const generic_processor_command_t commands_pk[] = {{CMD_CODE_PUSH_PK, 0},
                                                   {CMD_CODE_OP_V, OP_CHECKSIG},
                                                   {CMD_CODE_END, 0}};
const generic_processor_command_t commands_older[] = {{CMD_CODE_PUSH_UINT32, 0},
                                                      {CMD_CODE_OP_V, OP_CHECKSEQUENCEVERIFY},
                                                      {CMD_CODE_END, 0}};
const generic_processor_command_t commands_after[] = {{CMD_CODE_PUSH_UINT32, 0},
                                                      {CMD_CODE_OP_V, OP_CHECKLOCKTIMEVERIFY},
                                                      {CMD_CODE_END, 0}};

const generic_processor_command_t commands_sha256[] = {{CMD_CODE_OP, OP_SIZE},
                                                       {CMD_CODE_OP, 1},   // 1-byte push
                                                       {CMD_CODE_OP, 32},  // pushed value
                                                       {CMD_CODE_OP, OP_EQUALVERIFY},
                                                       {CMD_CODE_OP, OP_SHA256},
                                                       {CMD_CODE_PUSH_HASH32, 0},
                                                       {CMD_CODE_OP_V, OP_EQUAL},
                                                       {CMD_CODE_END, 0}};

const generic_processor_command_t commands_hash256[] = {{CMD_CODE_OP, OP_SIZE},
                                                        {CMD_CODE_OP, 1},   // 1-byte push
                                                        {CMD_CODE_OP, 32},  // pushed value
                                                        {CMD_CODE_OP, OP_EQUALVERIFY},
                                                        {CMD_CODE_OP, OP_HASH256},
                                                        {CMD_CODE_PUSH_HASH32, 0},
                                                        {CMD_CODE_OP_V, OP_EQUAL},
                                                        {CMD_CODE_END, 0}};

const generic_processor_command_t commands_ripemd160[] = {{CMD_CODE_OP, OP_SIZE},
                                                          {CMD_CODE_OP, 1},   // 1-byte push
                                                          {CMD_CODE_OP, 32},  // pushed value
                                                          {CMD_CODE_OP, OP_EQUALVERIFY},
                                                          {CMD_CODE_OP, OP_RIPEMD160},
                                                          {CMD_CODE_PUSH_HASH20, 0},
                                                          {CMD_CODE_OP_V, OP_EQUAL},
                                                          {CMD_CODE_END, 0}};

const generic_processor_command_t commands_hash160[] = {{CMD_CODE_OP, OP_SIZE},
                                                        {CMD_CODE_OP, 1},   // 1-byte push
                                                        {CMD_CODE_OP, 32},  // pushed value
                                                        {CMD_CODE_OP, OP_EQUALVERIFY},
                                                        {CMD_CODE_OP, OP_HASH160},
                                                        {CMD_CODE_PUSH_HASH20, 0},
                                                        {CMD_CODE_OP_V, OP_EQUAL},
                                                        {CMD_CODE_END, 0}};

// andor(X,Y,X) ==> [X] NOTIF [Z] ELSE [Y] ENDIF
const generic_processor_command_t commands_andor[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                      {CMD_CODE_OP, OP_NOTIF},
                                                      {CMD_CODE_PROCESS_CHILD, 2},
                                                      {CMD_CODE_OP, OP_ELSE},
                                                      {CMD_CODE_PROCESS_CHILD, 1},
                                                      {CMD_CODE_OP_V, OP_ENDIF},
                                                      {CMD_CODE_END, 0}};

const generic_processor_command_t commands_and_v[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                      {CMD_CODE_PROCESS_CHILD_V, 1},
                                                      {CMD_CODE_END, 0}};

const generic_processor_command_t commands_and_b[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                      {CMD_CODE_PROCESS_CHILD, 1},
                                                      {CMD_CODE_OP_V, OP_BOOLAND},
                                                      {CMD_CODE_END, 0}};

const generic_processor_command_t commands_and_n[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                      {CMD_CODE_OP, OP_NOTIF},
                                                      {CMD_CODE_OP, OP_0},
                                                      {CMD_CODE_OP, OP_ELSE},
                                                      {CMD_CODE_PROCESS_CHILD, 1},
                                                      {CMD_CODE_OP_V, OP_ENDIF},
                                                      {CMD_CODE_END, 0}};

const generic_processor_command_t commands_or_b[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                     {CMD_CODE_PROCESS_CHILD, 1},
                                                     {CMD_CODE_OP_V, OP_BOOLOR},
                                                     {CMD_CODE_END, 0}};

const generic_processor_command_t commands_or_c[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                     {CMD_CODE_OP, OP_NOTIF},
                                                     {CMD_CODE_PROCESS_CHILD, 1},
                                                     {CMD_CODE_OP_V, OP_ENDIF},
                                                     {CMD_CODE_END, 0}};

const generic_processor_command_t commands_or_d[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                     {CMD_CODE_OP, OP_IFDUP},
                                                     {CMD_CODE_OP, OP_NOTIF},
                                                     {CMD_CODE_PROCESS_CHILD, 1},
                                                     {CMD_CODE_OP_V, OP_ENDIF},
                                                     {CMD_CODE_END, 0}};

const generic_processor_command_t commands_or_i[] = {{CMD_CODE_OP, OP_IF},
                                                     {CMD_CODE_PROCESS_CHILD, 0},
                                                     {CMD_CODE_OP, OP_ELSE},
                                                     {CMD_CODE_PROCESS_CHILD, 1},
                                                     {CMD_CODE_OP_V, OP_ENDIF},
                                                     {CMD_CODE_END, 0}};

const generic_processor_command_t commands_a[] = {{CMD_CODE_OP, OP_TOALTSTACK},
                                                  {CMD_CODE_PROCESS_CHILD, 0},
                                                  {CMD_CODE_END, 0}};

const generic_processor_command_t commands_s[] = {{CMD_CODE_OP, OP_SWAP},
                                                  {CMD_CODE_PROCESS_CHILD, 0},
                                                  {CMD_CODE_END, 0}};

const generic_processor_command_t commands_c[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                  {CMD_CODE_OP_V, OP_CHECKSIG},
                                                  {CMD_CODE_END, 0}};

const generic_processor_command_t commands_t[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                  {CMD_CODE_OP_V, OP_1},
                                                  {CMD_CODE_END, 0}};

const generic_processor_command_t commands_d[] = {{CMD_CODE_OP, OP_DUP},
                                                  {CMD_CODE_OP, OP_IF},
                                                  {CMD_CODE_PROCESS_CHILD, 0},
                                                  {CMD_CODE_OP_V, OP_ENDIF},
                                                  {CMD_CODE_END, 0}};

const generic_processor_command_t commands_v[] = {{CMD_CODE_PROCESS_CHILD_VV, 0},
                                                  {CMD_CODE_END, 0}};

const generic_processor_command_t commands_j[] = {{CMD_CODE_OP, OP_SIZE},
                                                  {CMD_CODE_OP, OP_0NOTEQUAL},
                                                  {CMD_CODE_OP, OP_IF},
                                                  {CMD_CODE_PROCESS_CHILD, 0},
                                                  {CMD_CODE_OP_V, OP_ENDIF},
                                                  {CMD_CODE_END, 0}};

const generic_processor_command_t commands_n[] = {{CMD_CODE_PROCESS_CHILD, 0},
                                                  {CMD_CODE_OP_V, OP_0NOTEQUAL},
                                                  {CMD_CODE_END, 0}};

const generic_processor_command_t commands_l[] = {{CMD_CODE_OP, OP_IF},
                                                  {CMD_CODE_OP, OP_0},
                                                  {CMD_CODE_OP, OP_ELSE},
                                                  {CMD_CODE_PROCESS_CHILD, 0},
                                                  {CMD_CODE_OP_V, OP_ENDIF},
                                                  {CMD_CODE_END, 0}};

const generic_processor_command_t commands_u[] = {{CMD_CODE_OP, OP_IF},
                                                  {CMD_CODE_PROCESS_CHILD, 0},
                                                  {CMD_CODE_OP, OP_ELSE},
                                                  {CMD_CODE_OP, OP_0},
                                                  {CMD_CODE_OP_V, OP_ENDIF},
                                                  {CMD_CODE_END, 0}};

static void print_parser_info(policy_parser_state_t *state, const char *func_name) {
    (void) func_name;  // avoid warnings when DEBUG=0

    for (int i = 0; i < state->node_stack_eos; i++) {
        PRINTF("##");
    }
    PRINTF("%s(%d); FLAGS: %d\n",
           func_name,
           state->nodes[state->node_stack_eos].step,
           state->nodes[state->node_stack_eos].flags);
}

#define PRINT_PARSER_INFO(state) print_parser_info(state, __func__)

/**
 * Pushes a node onto the stack. Returns 0 on success, -1 if the stack is exhausted.
 */
static int state_stack_push(policy_parser_state_t *state,
                            policy_node_t *policy_node,
                            uint8_t mode,
                            uint8_t flags) {
    ++state->node_stack_eos;

    if (state->node_stack_eos >= MAX_POLICY_DEPTH) {
        return WITH_ERROR(-1, "Reached maximum policy depth");
    }

    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];
    node->policy_node = policy_node;
    node->length = 0;
    node->step = 0;
    node->mode = mode;
    node->flags = flags;
    node->hash_context = &state->hash_context;

    return 0;
}

/**
 * Pops a node from the stack.
 * Returns the emitted length on success, -1 on error.
 */
static int state_stack_pop(policy_parser_state_t *state) {
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

static inline int execute_processor(policy_parser_state_t *state,
                                    policy_parser_processor_t proc,
                                    const void *arg) {
    int ret = proc(state, arg);
    if (ret < 0) {
        return ret;
    }

    if (state->nodes[state->node_stack_eos].flags & PROCESSOR_FLAG_OUTPUT_OVERFLOW) {
        PRINTF("Output buffer overflow\n");
        return -1;
    }

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

static void update_output(policy_parser_state_t *state, const uint8_t *data, size_t data_len) {
    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];

    node->length += data_len;

    PRINTF("ADD TO HASH: ");
    for (unsigned int i = 0; i < data_len; i++) {
        PRINTF("%02X", data[i]);
    }
    PRINTF("\n");

    if (node->mode == MODE_OUT_BYTES) {
        if (!buffer_write_bytes(node->out_buf, data, data_len)) {
            node->flags |= PROCESSOR_FLAG_OUTPUT_OVERFLOW;
        };
    } else {
        crypto_hash_update(&node->hash_context->header, data, data_len);
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
        update_output_u8(state, 0x50 + n);
    } else {
        uint8_t n_le[4];
        write_u32_le(n_le, 0, n);
        int byte_size;
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
    PRINT_PARSER_INFO(state);
    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];
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

static int process_generic_node(policy_parser_state_t *state, const void *arg) {
    for (int i = 0; i < state->node_stack_eos; i++) {
        PRINTF("##");
    }

    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];

    generic_processor_command_t *commands = (generic_processor_command_t *) arg;

    size_t n_commands = 0;
    while (commands[n_commands].code != CMD_CODE_END) ++n_commands;

    if (node->step > n_commands) {
        return WITH_ERROR(-1, "Inconsistent state");
    } else if (node->step == n_commands) {
        return 1;
    } else {
        uint8_t cmd_code = commands[node->step].code;
        uint8_t cmd_data = commands[node->step].data;

        PRINTF("process_command-%d(%d); FLAGS: %d\n",
               node->policy_node->type,
               node->step,
               node->flags);

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
                policy_node_with_key_t *policy = (policy_node_with_key_t *) node->policy_node;
                uint8_t compressed_pubkey[33];
                if (-1 == get_derived_pubkey(state, policy->key_index, compressed_pubkey)) {
                    return -1;
                }

                update_output_u8(state, 33);  // PUSH 33 bytes
                update_output(state, compressed_pubkey, 33);
                break;
            }
            case CMD_CODE_PUSH_PKH: {
                policy_node_with_key_t *policy = (policy_node_with_key_t *) node->policy_node;
                uint8_t compressed_pubkey[33];
                if (-1 == get_derived_pubkey(state, policy->key_index, compressed_pubkey)) {
                    return -1;
                }
                crypto_hash160(compressed_pubkey, 33, compressed_pubkey);  // reuse memory

                update_output_u8(state, 20);  // PUSH 20 bytes
                update_output(state, compressed_pubkey, 20);
                break;
            }
            case CMD_CODE_PUSH_UINT32: {
                policy_node_with_uint32_t *policy = (policy_node_with_uint32_t *) node->policy_node;
                update_output_push_u32(state, policy->n);
                break;
            }
            case CMD_CODE_PUSH_HASH20: {
                policy_node_with_hash_160_t *policy =
                    (policy_node_with_hash_160_t *) node->policy_node;
                update_output_u8(state, 20);
                update_output(state, policy->h, 20);
                break;
            }
            case CMD_CODE_PUSH_HASH32: {
                policy_node_with_hash_256_t *policy =
                    (policy_node_with_hash_256_t *) node->policy_node;
                update_output_u8(state, 32);
                update_output(state, policy->h, 32);
                break;
            }
            case CMD_CODE_PROCESS_CHILD: {
                policy_node_with_scripts_t *policy =
                    (policy_node_with_scripts_t *) node->policy_node;
                state_stack_push(state, policy->scripts[cmd_data], node->mode, 0);
                break;
            }
            case CMD_CODE_PROCESS_CHILD_V: {
                policy_node_with_scripts_t *policy =
                    (policy_node_with_scripts_t *) node->policy_node;
                state_stack_push(state, policy->scripts[cmd_data], node->mode, node->flags);
                break;
            }
            case CMD_CODE_PROCESS_CHILD_VV: {
                policy_node_with_scripts_t *policy =
                    (policy_node_with_scripts_t *) node->policy_node;
                state_stack_push(state,
                                 policy->scripts[cmd_data],
                                 node->mode,
                                 node->flags | PROCESSOR_FLAG_V);
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

// TODO: wpkh can't be inside miniscript, but pkh can
static int process_pkh_wpkh_node(policy_parser_state_t *state, const void *arg) {
    UNUSED(arg);

    PRINT_PARSER_INFO(state);
    PRINT_STACK_POINTER();

    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];

    if (node->step != 0) {
        return -1;
    }

    policy_node_with_key_t *policy = (policy_node_with_key_t *) node->policy_node;

    uint8_t compressed_pubkey[33];

    if (-1 == get_derived_pubkey(state, policy->key_index, compressed_pubkey)) {
        return -1;
    } else if (policy->type == TOKEN_PKH) {
        update_output_u8(state, OP_DUP);
        update_output_u8(state, OP_HASH160);

        update_output_u8(state, 20);  // PUSH 20 bytes

        crypto_hash160(compressed_pubkey, 33, compressed_pubkey);  // reuse memory
        update_output(state, compressed_pubkey, 20);

        update_output_u8(state, OP_EQUALVERIFY);
        update_output_op_v(state, OP_CHECKSIG);
    } else {  // policy->type == TOKEN_WPKH
        update_output_u8(state, OP_0);

        update_output_u8(state, 20);  // PUSH 20 bytes

        crypto_hash160(compressed_pubkey, 33, compressed_pubkey);  // reuse memory
        update_output(state, compressed_pubkey, 20);
    }

    return 1;
}

static int process_thresh_node(policy_parser_state_t *state, const void *arg) {
    UNUSED(arg);

    PRINT_PARSER_INFO(state);
    PRINT_STACK_POINTER();

    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];
    policy_node_thresh_t *policy = (policy_node_thresh_t *) node->policy_node;

    // [X1] [X2] ADD ... [Xn] ADD ... <k> EQUAL

    // n+1 steps
    // at step i, for 0 <= i < n, we produce [Xi] (or ADD X[i])
    // at step i, for i == n, we produce ADD <k> EQUAL

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

        if (-1 == state_stack_push(state, cur->script, node->mode, 0)) {
            return -1;
        }
        ++node->step;
        return 0;
    } else {
        // final step
        if (policy->n >= 1) {
            update_output_u8(state, OP_ADD);
        }
        update_output_push_u32(state, policy->k);
        update_output_op_v(state, OP_EQUAL);
        return 1;
    }
}

static int process_multi_sortedmulti_node(policy_parser_state_t *state, const void *arg) {
    UNUSED(arg);

    PRINT_PARSER_INFO(state);
    PRINT_STACK_POINTER();

    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];
    policy_node_multisig_t *policy = (policy_node_multisig_t *) node->policy_node;

    // k {pubkey_1} ... {pubkey_n} n OP_CHECKMULTISIG

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

    update_output_u8(state, 0x50 + policy->n);    // OP_n
    update_output_op_v(state, OP_CHECKMULTISIG);  // OP_CHECKMULTISIG

    return 1;
}

// TODO: this can only be toplevel
static int process_tr_node(policy_parser_state_t *state, const void *arg) {
    UNUSED(arg);

    PRINT_PARSER_INFO(state);
    PRINT_STACK_POINTER();

    policy_parser_node_state_t *node = &state->nodes[state->node_stack_eos];
    policy_node_with_key_t *policy = (policy_node_with_key_t *) node->policy_node;

    uint8_t compressed_pubkey[33];
    uint8_t tweaked_key[32];

    if (-1 == get_derived_pubkey(state, policy->key_index, compressed_pubkey)) {
        return -1;
    }

    update_output_u8(state, OP_1);
    update_output_u8(state, 32);  // PUSH 32 bytes

    uint8_t parity;
    crypto_tr_tweak_pubkey(compressed_pubkey + 1, &parity, tweaked_key);

    update_output(state, tweaked_key, 32);

    return 1;
}

#define WRAPPED_SCRIPT_TYPE_SH     0
#define WRAPPED_SCRIPT_TYPE_WSH    1
#define WRAPPED_SCRIPT_TYPE_SH_WSH 2

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

    const policy_node_t *core_policy;

    uint8_t core_mode = MODE_OUT_BYTES;

    int script_type = -1;
    if (policy->type == TOKEN_SH) {
        policy_node_t *child = ((policy_node_with_script_t *) policy)->script;
        if (child->type == TOKEN_WSH) {
            script_type = WRAPPED_SCRIPT_TYPE_SH_WSH;
            core_policy = ((policy_node_with_script_t *) child)->script;
        } else {
            script_type = WRAPPED_SCRIPT_TYPE_SH;
            core_policy = child;
        }
        core_mode = MODE_OUT_HASH;
    } else if (policy->type == TOKEN_WSH) {
        script_type = WRAPPED_SCRIPT_TYPE_WSH;
        core_mode = MODE_OUT_HASH;
        core_policy = ((policy_node_with_script_t *) policy)->script;
    } else {
        core_policy = policy;
    }

    state.nodes[0] = (policy_parser_node_state_t){.mode = core_mode,
                                                  .length = 0,
                                                  .flags = 0,
                                                  .step = 0,
                                                  .policy_node = core_policy};

    if (core_mode == MODE_OUT_HASH) {
        cx_sha256_init(&state.hash_context);
        state.nodes[0].hash_context = &state.hash_context;
    } else {
        state.nodes[0].out_buf = out_buf;
    }

    int ret;
    do {
        policy_parser_node_state_t *node = &state.nodes[state.node_stack_eos];

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

            // case TOKEN_SH:
            // case TOKEN_WSH:
            //     ret = execute_processor(&state, process_sh_wsh_node, NULL);
            //     break;
            case TOKEN_MULTI:
            case TOKEN_SORTEDMULTI:
                ret = execute_processor(&state, process_multi_sortedmulti_node, NULL);
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
                ret = execute_processor(&state, process_tr_node, NULL);
                break;
            default:
                PRINTF("Unknown token type: %d\n", node->policy_node->type);
                return -1;
        }
    } while (ret >= 0 && state.node_stack_eos >= 0);

    if (ret < 0) {
        return WITH_ERROR(ret, "Processor failed");
    }

    if (core_mode == MODE_OUT_HASH) {
        crypto_hash_digest(&state.hash_context.header, state.hash, 32);

        // TODO: process sh/wsh to produce final script
        switch (script_type) {
            case WRAPPED_SCRIPT_TYPE_SH:
            case WRAPPED_SCRIPT_TYPE_SH_WSH: {
                if (script_type == WRAPPED_SCRIPT_TYPE_SH_WSH) {
                    cx_sha256_init(&state.hash_context);
                    crypto_hash_update_u8(&state.hash_context.header, OP_0);

                    crypto_hash_update_u8(&state.hash_context.header, 32);  // PUSH 32 bytes
                    crypto_hash_update(&state.hash_context.header, state.hash, 32);

                    crypto_hash_digest(&state.hash_context.header, state.hash, 32);
                }

                buffer_write_u8(out_buf, OP_HASH160);
                buffer_write_u8(out_buf, 20);  // PUSH 20 bytes

                crypto_ripemd160(state.hash, 32, state.hash);  // reuse memory
                buffer_write_bytes(out_buf, state.hash, 20);

                buffer_write_u8(out_buf, OP_EQUAL);
                ret = 1 + 1 + 20 + 1;
                break;
            }
            case WRAPPED_SCRIPT_TYPE_WSH: {
                buffer_write_u8(out_buf, OP_0);

                buffer_write_u8(out_buf, 32);  // PUSH 32 bytes
                buffer_write_bytes(out_buf, state.hash, 32);

                ret = 1 + 1 + 32;
                break;
            }
            default:
                PRINTF("This should never happen\n");
                return -1;
        }
    }

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