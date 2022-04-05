#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "../common/bip32.h"
#include "../common/buffer.h"
#include "../common/segwit_addr.h"
#include "../common/wallet.h"

#include "../boilerplate/sw.h"

#ifndef SKIP_FOR_CMOCKA
#include "../crypto.h"
#else
// disable problematic macros when compiling unit tests with CMOCKA
#define PRINTF(...)
#define PIC(x) (x)
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
// The compiler doesn't like /** inside a block comment, so we disable this warning temporarily.

/*
Currently supported policies for singlesig:

- pkh(key/**) where `key` follows `BIP44`       (legacy)
- wpkh(key/**) where `key` follows `BIP 84`     (native segwit)
- sh(wpkh(key/**)) where `key` follows `BIP 49` (nested segwit)
- tr(key/**) where `key` follows `BIP 86`       (single-key p2tr)

Currently supported wallet policies for multisig:

   LEGACY
  sh(multi(...)))
  sh(sortedmulti(...)))

   NATIVE SEGWIT
  wsh(multi(...))
  wsh(sortedmulti(...))

   WRAPPED SEGWIT
  sh(wsh(multi(...)))
  sh(wsh(sortedmulti(...)))
*/

#pragma GCC diagnostic pop

// TODO: add unit tests to this module

typedef struct {
    PolicyNodeType type;
    const char *name;
} token_descriptor_t;

static const token_descriptor_t KNOWN_TOKENS[] = {
    {.type = TOKEN_SH, .name = "sh"},
    {.type = TOKEN_WSH, .name = "wsh"},
    {.type = TOKEN_PKH, .name = "pkh"},
    {.type = TOKEN_WPKH, .name = "wpkh"},
    {.type = TOKEN_MULTI, .name = "multi"},
    {.type = TOKEN_SORTEDMULTI, .name = "sortedmulti"},
    {.type = TOKEN_TR, .name = "tr"},

    // miniscript tokens (except wrappers)
    {.type = TOKEN_0, .name = "0"},
    {.type = TOKEN_1, .name = "1"},
    {.type = TOKEN_PK, .name = "pk"},
    {.type = TOKEN_PK_K, .name = "pk_k"},
    {.type = TOKEN_PK_H, .name = "pk_h"},
    {.type = TOKEN_OLDER, .name = "older"},
    {.type = TOKEN_AFTER, .name = "after"},
    {.type = TOKEN_SHA256, .name = "sha256"},
    {.type = TOKEN_HASH256, .name = "hash256"},
    {.type = TOKEN_RIPEMD160, .name = "ripemd160"},
    {.type = TOKEN_HASH160, .name = "hash160"},
    {.type = TOKEN_ANDOR, .name = "andor"},
    {.type = TOKEN_AND_V, .name = "and_v"},
    {.type = TOKEN_AND_B, .name = "and_b"},
    {.type = TOKEN_AND_N, .name = "and_n"},
    {.type = TOKEN_OR_B, .name = "or_b"},
    {.type = TOKEN_OR_C, .name = "or_c"},
    {.type = TOKEN_OR_D, .name = "or_d"},
    {.type = TOKEN_OR_I, .name = "or_i"},
    {.type = TOKEN_THRESH, .name = "thresh"},
};

// lookup table for characters that represent a valid miniscript wrapper fragment
const bool is_valid_miniscript_wrapper[] = {
    1,  // "a"
    0,  // "b"
    1,  // "c"
    1,  // "d"
    0,  // "e"
    0,  // "f"
    0,  // "g"
    0,  // "h"
    0,  // "i"
    1,  // "j"
    0,  // "k"
    1,  // "l"
    0,  // "m"
    1,  // "n"
    0,  // "o"
    0,  // "p"
    0,  // "q"
    0,  // "r"
    1,  // "s"
    1,  // "t"
    1,  // "u"
    1,  // "v"
    0,  // "w"
    0,  // "x"
    0,  // "y"
    0,  // "z"
};

/**
 * Length of the longest token in the policy wallet descriptor language (not including the
 * terminating \0 byte).
 */
#define MAX_TOKEN_LENGTH (sizeof("sortedmulti") - 1)

int read_policy_map_wallet(buffer_t *buffer, policy_map_wallet_header_t *header) {
    if (!buffer_read_u8(buffer, &header->type)) {
        return -1;
    }

    if (header->type != WALLET_TYPE_POLICY_MAP) {
        return -2;
    }

    if (!buffer_read_u8(buffer, &header->name_len)) {
        return -3;
    }

    if (header->name_len > MAX_WALLET_NAME_LENGTH) {
        return -4;
    }

    if (!buffer_read_bytes(buffer, (uint8_t *) header->name, header->name_len)) {
        return -5;
    }
    header->name[header->name_len] = '\0';

    uint64_t policy_map_len;
    if (!buffer_read_varint(buffer, &policy_map_len)) {
        return -6;
    }
    header->policy_map_len = (uint16_t) policy_map_len;

    if (header->policy_map_len > MAX_POLICY_MAP_STR_LENGTH) {
        return -7;
    }

    if (!buffer_read_bytes(buffer, (uint8_t *) header->policy_map, header->policy_map_len)) {
        return -8;
    }

    uint64_t n_keys;
    if (!buffer_read_varint(buffer, &n_keys) || n_keys > 252) {
        return -9;
    }
    header->n_keys = (uint16_t) n_keys;

    if (!buffer_read_bytes(buffer, (uint8_t *) header->keys_info_merkle_root, 32)) {
        return -10;
    }

    return 0;
}

static bool is_digit(char c) {
    return '0' <= c && c <= '9';
}

static bool is_alpha(char c) {
    return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z');
}

static bool is_alphanumeric(char c) {
    return is_alpha(c) || is_digit(c);
}

static bool is_lowercase_hex(char c) {
    return is_digit(c) || ('a' <= c && c <= 'f');
}

static uint8_t lowercase_hex_to_int(char c) {
    return (uint8_t) (is_digit(c) ? c - '0' : c - 'a' + 10);
}

/**
 * Read up to out_len characters from buffer, until either:
 * - the buffer is exhausted
 * - out_len characters are read
 * - the next character is _not_ in [a-zAZ0-9_]
 */
static size_t read_token(buffer_t *buffer, char *out, size_t out_len) {
    size_t word_len = 0;
    char c;
    while (word_len < out_len && buffer_peek(buffer, (uint8_t *) &c) &&
           (is_alphanumeric(c) || c == '_')) {
        out[word_len++] = c;
        buffer_seek_cur(buffer, 1);
    }
    return word_len;
}

/**
 * Read the next word from buffer (or up to MAX_TOKEN_LENGTH characters), and
 * returns the index of this word in KNOWN_TOKENS if found; -1 otherwise.
 */
static int parse_token(buffer_t *buffer) {
    char word[MAX_TOKEN_LENGTH + 1];

    size_t word_len = read_token(buffer, word, MAX_TOKEN_LENGTH);
    word[word_len] = '\0';

    for (unsigned int i = 0; i < sizeof(KNOWN_TOKENS) / sizeof(KNOWN_TOKENS[0]); i++) {
        if (strncmp((const char *) PIC(KNOWN_TOKENS[i].name), word, MAX_TOKEN_LENGTH) == 0) {
            return (int) PIC(KNOWN_TOKENS[i].type);
        }
    }
    return -1;
}

/**
 * Parses an unsigned decimal number from buffer, stopping when either the buffer ends, the next
 * character is not a number, or the number is already too big. Leading zeros are not allowed.
 * Returns a valid 0 on success, -1 on failure.
 * The read number is saved into *out on success.
 */
static int parse_unsigned_decimal(buffer_t *buffer, size_t *out) {
    uint8_t c;
    if (!buffer_peek(buffer, &c) || !is_digit(c)) {
        return -1;
    }

    size_t result = 0;
    int digits_read = 0;
    while (buffer_peek(buffer, &c) && is_digit(c)) {
        ++digits_read;
        uint8_t next_digit = c - '0';

        if (digits_read == 2 && result == 0) {
            // if the first digit was a 0, than it should be the only digit
            return -1;
        }

        if (10 * result + next_digit < result) {
            return -1;  // overflow, integer too large
        }

        result = 10 * result + next_digit;

        buffer_seek_cur(buffer, 1);
    }
    *out = result;

    if (digits_read == 0) {
        return -1;
    }

    return 0;
}

/**
 * Reads exactly 2*n lowercase hecadecimal characters, storing them in exactly n bytes in `out` (1
 * byte every two hex characters); returns -1 if any character is not hexadecimal, or if less than
 * 2*n characters can be read.
 */
static int buffer_read_hex_hash(buffer_t *buffer, uint8_t *out, size_t n) {
    if (!buffer_can_read(buffer, 2 * n)) {
        return -1;
    }

    for (unsigned int i = 0; i < n; i++) {
        uint8_t c1, c2;
        buffer_read_u8(buffer, &c1);
        buffer_read_u8(buffer, &c2);

        if (!is_lowercase_hex(c1) || !is_lowercase_hex(c2)) {
            return -1;
        }

        out[i] = 16 * lowercase_hex_to_int((char) c1) + lowercase_hex_to_int((char) c2);
    }
    return 0;
}

// Reads a derivation step expressed in decimal, with the symbol ' to mark if hardened (h is not
// supported) Returns 0 on success, -1 on error.
static int buffer_read_derivation_step(buffer_t *buffer, uint32_t *out) {
    uint32_t der_step;
    if (parse_unsigned_decimal(buffer, &der_step) == -1 || der_step >= BIP32_FIRST_HARDENED_CHILD) {
        PRINTF("Failed reading derivation step\n");
        return -1;
    }

    *out = der_step;

    // Check if hardened
    uint8_t c;
    if (buffer_peek(buffer, &c) && c == '\'') {
        *out |= BIP32_FIRST_HARDENED_CHILD;
        buffer_seek_cur(buffer, 1);  // skip the ' character
    }
    return 0;
}

// TODO: we are currently enforcing that the master key fingerprint (if present) is in lowercase
// hexadecimal digits,
//       and that the symbol for "hardened derivation" is "'".
//       This implies descriptors should be normalized on the client side.
int parse_policy_map_key_info(buffer_t *buffer, policy_map_key_info_t *out) {
    memset(out, 0, sizeof(policy_map_key_info_t));

    uint8_t c;
    if (!buffer_peek(buffer, &c)) {
        return -1;
    }

    if (c == '[') {
        out->has_key_origin = 1;

        buffer_seek_cur(buffer, 1);         // skip 1 byte
        if (!buffer_can_read(buffer, 9)) {  // at least 8 bytes + (closing parenthesis or '\')
            return -1;
        }
        for (int i = 0; i < 4; i++) {
            char num[2];
            buffer_read_bytes(buffer, (uint8_t *) num, 2);
            if (!is_lowercase_hex(num[0]) || !is_lowercase_hex(num[1])) {
                return -1;
            }
            out->master_key_fingerprint[i] =
                16 * lowercase_hex_to_int(num[0]) + lowercase_hex_to_int(num[1]);
        }

        // read all the given derivation steps
        out->master_key_derivation_len = 0;
        while (buffer_peek(buffer, &c) && c == '/') {
            buffer_seek_cur(buffer, 1);  // skip the '/' character
            if (out->master_key_derivation_len > MAX_BIP32_PATH_STEPS) {
                return -1;
            }

            if (buffer_read_derivation_step(
                    buffer,
                    &out->master_key_derivation[out->master_key_derivation_len]) == -1) {
                return -1;
            };

            ++out->master_key_derivation_len;
        }

        // the next character must be ']'
        if (!buffer_read_u8(buffer, &c) || c != ']') {
            return -1;
        }
    }

    // consume the rest of the buffer into the pubkey, except possibly the final "/**"
    unsigned int ext_pubkey_len = 0;
    while (ext_pubkey_len < MAX_SERIALIZED_PUBKEY_LENGTH && buffer_peek(buffer, &c) &&
           is_alphanumeric(c)) {
        out->ext_pubkey[ext_pubkey_len] = c;
        ++ext_pubkey_len;
        buffer_seek_cur(buffer, 1);
    }
    out->ext_pubkey[ext_pubkey_len] = '\0';

    // either the string terminates now, or it has a final "/**" suffix for the wildcard.
    if (!buffer_can_read(buffer, 1)) {
        // no wildcard
        return 0;
    }

    out->has_wildcard = 1;

    // Only the final "/**" suffix should be left
    uint8_t wildcard[3];
    // Make sure that the buffer is indeed exhausted
    if (!buffer_read_bytes(buffer, wildcard, 3)  // should be able to read 3 characters
        || buffer_can_read(buffer, 1)            // but nothing more
        || wildcard[0] != '/'                    // suffix should be exactly "/**"
        || wildcard[1] != '*' || wildcard[2] != '*') {
        return -1;
    }

    return 0;
}

static size_t parse_key_index(buffer_t *in_buf) {
    char c;
    if (!buffer_read_u8(in_buf, (uint8_t *) &c) || c != '@') {
        return -1;
    }

    size_t k;
    if (parse_unsigned_decimal(in_buf, &k) == -1) {
        return -1;
    }
    return k;
}

#define CONTEXT_WITHIN_SH  1  // parsing a direct child of SH
#define CONTEXT_WITHIN_WSH 2  // parsing a direct child of WSH

static bool consume_character(buffer_t *in_buf, char expected) {
    // the next character must be a comma
    char c;
    if (!buffer_read_u8(in_buf, (uint8_t *) &c) || c != expected) {
        PRINTF("Unexpected char: %c. Was expecting: %c\n", c, expected);
        return false;
    }
    return true;
}

/**
 * Parses a SCRIPT expression from the in_buf buffer, allocating the nodes and variables in out_buf.
 * The initial pointer in out_buf will contain the root node of the SCRIPT.
 */
static int parse_script(buffer_t *in_buf,
                        buffer_t *out_buf,
                        size_t depth,
                        unsigned int context_flags) {
    // look ahead to finds out if the buffer starts with alphanumeric digits that could be wrappers,
    // followed by a colon
    int n_wrappers = 0;
    char c;
    bool can_read;
    while (true) {
        can_read = buffer_peek_n(in_buf, n_wrappers, (uint8_t *) &c);
        if (can_read && 'a' <= c && c <= 'z' && is_valid_miniscript_wrapper[c - 'a']) {
            ++n_wrappers;
        } else {
            break;
        }
    }

    policy_node_with_script_t *inner_wrapper = NULL;  // pointer to the inner wrapper, if any

    if (can_read && c == ':') {
        // parse wrappers
        for (int i = 0; i < n_wrappers; i++) {
            policy_node_with_script_t *node =
                (policy_node_with_script_t *) buffer_alloc(out_buf,
                                                           sizeof(policy_node_with_script_t),
                                                           true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            buffer_read_u8(in_buf, (uint8_t *) &c);
            switch (c) {
                case 'a':
                    node->type = TOKEN_A;
                    break;
                case 's':
                    node->type = TOKEN_S;
                    break;
                case 'c':
                    node->type = TOKEN_C;
                    break;
                case 't':
                    node->type = TOKEN_T;
                    break;
                case 'd':
                    node->type = TOKEN_D;
                    break;
                case 'v':
                    node->type = TOKEN_V;
                    break;
                case 'j':
                    node->type = TOKEN_J;
                    break;
                case 'n':
                    node->type = TOKEN_N;
                    break;
                case 'l':
                    node->type = TOKEN_L;
                    break;
                case 'u':
                    node->type = TOKEN_U;
                    break;
                default:
                    PRINTF("Unexpected wrapper: %c\n", c);
                    return -1;
            }

            if (inner_wrapper != NULL) {
                inner_wrapper->script = (policy_node_t *) node;
            }
            inner_wrapper = node;
        }
        buffer_seek_cur(in_buf, 1);  // skip ":"
    }

    // We read the token, we'll do different parsing based on what token we find
    int token = parse_token(in_buf);

    // Opening '('
    if (!buffer_read_u8(in_buf, (uint8_t *) &c) && c != '(') {
        return WITH_ERROR(-1, "Expected '('");
    }
    policy_node_t *parsed_node;

    switch (token) {
        case TOKEN_0:
        case TOKEN_1: {
            policy_node_with_script_t *node =
                (policy_node_with_script_t *) buffer_alloc(out_buf,
                                                           sizeof(policy_node_with_script_t),
                                                           true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;

            node->type = token;
            break;
        }
        case TOKEN_SH:
        case TOKEN_WSH: {
            if (token == TOKEN_SH) {
                if (depth != 0) {
                    return WITH_ERROR(-1, "sh can only be a top-level function");
                }

            } else if (token == TOKEN_WSH) {
                if (depth != 0 && ((context_flags & CONTEXT_WITHIN_SH) == 0)) {
                    return WITH_ERROR(-1, "wsh can only be top-level or inside sh");
                }
            }

            policy_node_with_script_t *node =
                (policy_node_with_script_t *) buffer_alloc(out_buf,
                                                           sizeof(policy_node_with_script_t),
                                                           true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;

            node->type = token;

            unsigned int inner_context_flags =
                (token == TOKEN_SH) ? CONTEXT_WITHIN_SH : CONTEXT_WITHIN_WSH;

            // the internal script is recursively parsed (if successful) in the current location
            // of the output buffer
            buffer_alloc(out_buf, 0, true);  // ensure alignment of current pointer
            node->script = (policy_node_t *) buffer_get_cur(out_buf);

            if (0 > parse_script(in_buf, out_buf, depth + 1, inner_context_flags)) {
                // failed while parsing internal script
                return -1;
            }

            break;
        }
        case TOKEN_SHA256:
        case TOKEN_HASH256: {
            policy_node_with_hash_256_t *node =
                (policy_node_with_hash_256_t *) buffer_alloc(out_buf,
                                                             sizeof(policy_node_with_hash_256_t),
                                                             true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;

            node->type = token;
            if (0 > buffer_read_hex_hash(in_buf, node->h, 32)) {
                return WITH_ERROR(-1, "Failed to parse 32-byte hash image");
            }
            break;
        }

        case TOKEN_RIPEMD160:
        case TOKEN_HASH160: {
            policy_node_with_hash_160_t *node =
                (policy_node_with_hash_160_t *) buffer_alloc(out_buf,
                                                             sizeof(policy_node_with_hash_160_t),
                                                             true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;

            node->type = token;
            if (0 > buffer_read_hex_hash(in_buf, node->h, 20)) {
                return WITH_ERROR(-1, "Failed to parse 20-byte hash image");
            }
            break;
        }

        case TOKEN_ANDOR: {
            policy_node_with_script3_t *node =
                (policy_node_with_script3_t *) buffer_alloc(out_buf,
                                                            sizeof(policy_node_with_script3_t),
                                                            true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;

            node->type = token;

            // TODO: what's the right context flags?
            unsigned int inner_context_flags = context_flags;

            // the internal scripts are recursively parsed (if successful) in the current location
            // of the output buffer

            for (int child_index = 0; child_index < 3; child_index++) {
                buffer_alloc(out_buf, 0, true);  // ensure alignment of current pointer
                node->scripts[child_index] = (policy_node_t *) buffer_get_cur(out_buf);

                if (0 > parse_script(in_buf, out_buf, depth + 1, inner_context_flags)) {
                    // failed while parsing internal script
                    return -1;
                }

                // the next character must be a comma (except after the last child)
                if (child_index <= 1 && !consume_character(in_buf, ',')) {
                    return WITH_ERROR(-1, "Expected ','");
                }
            }
            break;
        }
        case TOKEN_AND_V:
        case TOKEN_AND_B:
        case TOKEN_AND_N:
        case TOKEN_OR_B:
        case TOKEN_OR_C:
        case TOKEN_OR_D:
        case TOKEN_OR_I: {
            policy_node_with_script2_t *node =
                (policy_node_with_script2_t *) buffer_alloc(out_buf,
                                                            sizeof(policy_node_with_script2_t),
                                                            true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;

            node->type = token;

            // TODO: what's the right context flags?
            unsigned int inner_context_flags = context_flags;

            // the internal scripts are recursively parsed (if successful) in the current location
            // of the output buffer

            buffer_alloc(out_buf, 0, true);  // ensure alignment of current pointer
            node->scripts[0] = (policy_node_t *) buffer_get_cur(out_buf);

            if (0 > parse_script(in_buf, out_buf, depth + 1, inner_context_flags)) {
                // failed while parsing internal script
                return -1;
            }

            // the next character must be a comma
            if (!consume_character(in_buf, ',')) {
                return WITH_ERROR(-1, "Expected ','");
            }

            buffer_alloc(out_buf, 0, true);  // ensure alignment of current pointer
            node->scripts[1] = (policy_node_t *) buffer_get_cur(out_buf);

            if (0 > parse_script(in_buf, out_buf, depth + 1, inner_context_flags)) {
                // failed while parsing internal script
                return -1;
            }

            break;
        }
        case TOKEN_THRESH: {
            policy_node_thresh_t *node =
                (policy_node_thresh_t *) buffer_alloc(out_buf, sizeof(policy_node_thresh_t), true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;
            node->type = token;

            // TODO: what's the right context flags?
            unsigned int inner_context_flags = context_flags;

            // the internal scripts are recursively parsed (if successful) in the current location
            // of the output buffer

            if (parse_unsigned_decimal(in_buf, &node->k) == -1) {
                return WITH_ERROR(-1, "Error parsing threshold");
            }

            // the next character must be a comma
            if (!consume_character(in_buf, ',')) {
                return WITH_ERROR(-1, "Expected a comma");
            }

            if (node->k < 1) {
                return WITH_ERROR(-1, "Threshold must be at least 1");
            }

            node->n = 0;
            node->scriptlist =
                (policy_node_scriptlist_t *) buffer_alloc(out_buf,
                                                          sizeof(policy_node_scriptlist_t),
                                                          true);
            if (node->scriptlist == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            policy_node_scriptlist_t *cur = node->scriptlist;
            cur->next = NULL;
            while (true) {
                ++node->n;
                // parse a script into cur->script
                buffer_alloc(out_buf, 0, true);  // ensure alignment of current pointer
                cur->script = (policy_node_t *) buffer_get_cur(out_buf);
                if (0 > parse_script(in_buf, out_buf, depth + 1, inner_context_flags)) {
                    // failed while parsing internal script
                    return -1;
                }
                // peek, if next character is ',', consume it and exit
                uint8_t c;
                if (buffer_peek(in_buf, &c) && c == ',') {
                    buffer_seek_cur(in_buf, 1);  // skip the comma
                    cur->next =
                        (policy_node_scriptlist_t *) buffer_alloc(out_buf,
                                                                  sizeof(policy_node_scriptlist_t),
                                                                  true);
                    if (cur->next == NULL) {
                        return WITH_ERROR(-1, "Out of memory");
                    }

                    cur = cur->next;
                    cur->next = NULL;
                } else {
                    // no more scripts to parse
                    break;
                }
            }

            break;
        }
        case TOKEN_PK:
        case TOKEN_PKH:
        case TOKEN_PK_K:
        case TOKEN_PK_H:
        case TOKEN_WPKH:
        case TOKEN_TR:  // currently supporting x-only keys
        {
            policy_node_with_key_t *node =
                (policy_node_with_key_t *) buffer_alloc(out_buf,
                                                        sizeof(policy_node_with_key_t),
                                                        true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }

            if (token == TOKEN_TR && depth > 1) {
                return WITH_ERROR(-1, "tr can only be top-level");
            }

            if (token == TOKEN_WPKH) {
                if (depth > 0 && ((context_flags & CONTEXT_WITHIN_SH) == 0)) {
                    return WITH_ERROR(-1, "wpkh can only be top-level or inside sh");
                }
            }

            parsed_node = (policy_node_t *) node;

            node->type = token;

            int key_index = parse_key_index(in_buf);
            if (key_index == -1) {
                return WITH_ERROR(-1, "Couldn't parse key index");
            }
            node->key_index = (size_t) key_index;

            break;
        }
        case TOKEN_OLDER:
        case TOKEN_AFTER: {
            policy_node_with_uint32_t *node =
                (policy_node_with_uint32_t *) buffer_alloc(out_buf,
                                                           sizeof(policy_node_with_uint32_t),
                                                           true);
            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }
            parsed_node = (policy_node_t *) node;
            node->type = token;

            if (parse_unsigned_decimal(in_buf, &node->n) == -1) {
                return WITH_ERROR(-1, "Error parsing number");
            }

            // TODO: any checks on n?

            break;
        }
        case TOKEN_MULTI:
        case TOKEN_SORTEDMULTI: {
            policy_node_multisig_t *node =
                (policy_node_multisig_t *) buffer_alloc(out_buf,
                                                        sizeof(policy_node_multisig_t),
                                                        true);

            if (node == NULL) {
                return WITH_ERROR(-1, "Out of memory");
            }

            if (token == TOKEN_SORTEDMULTI) {
                if (((context_flags & CONTEXT_WITHIN_SH) != 0) &&
                    ((context_flags & CONTEXT_WITHIN_WSH) != 0)) {
                    return WITH_ERROR(-1, "sortedmulti can only be directly under sh or wsh");
                }
            }

            parsed_node = (policy_node_t *) node;
            node->type = token;

            if (parse_unsigned_decimal(in_buf, &node->k) == -1) {
                return WITH_ERROR(-1, "Error parsing threshold");
            }

            // We allocate the array of key indices at the current position in the output buffer
            // (on success)
            buffer_alloc(out_buf, 0, true);  // ensure alignment of current pointer
            node->key_indexes = (size_t *) buffer_get_cur(out_buf);

            node->n = 0;
            while (true) {
                // If the next character is a ')', we exit and leave it in the buffer
                if (buffer_peek(in_buf, (uint8_t *) &c) && c == ')') {
                    break;
                }

                // otherwise, there must be a comma
                if (!consume_character(in_buf, ',')) {
                    return WITH_ERROR(-1, "Expected ','");
                }

                int key_index = parse_key_index(in_buf);
                if (key_index == -1) {
                    return WITH_ERROR(-1, "Error parsing key index");
                }

                size_t *key_index_out = (size_t *) buffer_alloc(out_buf, sizeof(size_t), true);
                if (key_index_out == NULL) {
                    return WITH_ERROR(-1, "Out of memory");
                }
                *key_index_out = (size_t) key_index;

                ++node->n;
            }

            // check integrity of k and n
            if (!(1 <= node->k && node->k <= node->n && node->n <= MAX_POLICY_MAP_COSIGNERS)) {
                return WITH_ERROR(-1, "Invalid k and/or n");
            }

            break;
        }
        default:
            PRINTF("Unknown token: %d\n", token);
            return -1;
    }

    if (!consume_character(in_buf, ')')) {
        return WITH_ERROR(-1, "Expected ')'");
    }

    if (depth == 0 && buffer_can_read(in_buf, 1)) {
        return WITH_ERROR(-1, "Input buffer too long");
    }

    // if there was one or more wrappers wrapper, the script of the most internal node must point
    // to the parsed node
    if (inner_wrapper != NULL) {
        inner_wrapper->script = parsed_node;
    }

    return 0;
}

int parse_policy_map(buffer_t *in_buf, void *out, size_t out_len) {
    if ((unsigned long) out % 4 != 0) {
        return WITH_ERROR(-1, "Unaligned pointer");
    }

    buffer_t out_buf = buffer_create(out, out_len);

    return parse_script(in_buf, &out_buf, 0, 0);
}

#ifndef SKIP_FOR_CMOCKA

void get_policy_wallet_id(policy_map_wallet_header_t *wallet_header, uint8_t out[static 32]) {
    cx_sha256_t wallet_hash_context;
    cx_sha256_init(&wallet_hash_context);

    crypto_hash_update_u8(&wallet_hash_context.header, wallet_header->type);
    crypto_hash_update_u8(&wallet_hash_context.header, wallet_header->name_len);
    crypto_hash_update(&wallet_hash_context.header, wallet_header->name, wallet_header->name_len);

    crypto_hash_update_varint(&wallet_hash_context.header, wallet_header->policy_map_len);
    crypto_hash_update(&wallet_hash_context.header,
                       wallet_header->policy_map,
                       wallet_header->policy_map_len);

    crypto_hash_update_varint(&wallet_hash_context.header, wallet_header->n_keys);

    crypto_hash_update(&wallet_hash_context.header, wallet_header->keys_info_merkle_root, 32);

    crypto_hash_digest(&wallet_hash_context.header, out, 32);
}

#endif
