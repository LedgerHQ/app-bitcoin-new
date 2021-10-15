#include <stdint.h>
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
    {.type = TOKEN_TR, .name = "tr"}};

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
    if (!buffer_read_varint(buffer, &policy_map_len) || policy_map_len > 74) {
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
 * - the next character is _not_ in [a-zAZ]
 */
static size_t read_word(buffer_t *buffer, char *out, size_t out_len) {
    size_t word_len = 0;
    while (word_len < out_len && buffer_can_read(buffer, 1)) {
        char c = buffer->ptr[buffer->offset];
        if (!is_alpha(c)) {
            break;
        }
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

    size_t word_len = read_word(buffer, word, MAX_TOKEN_LENGTH);
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
    if (!buffer_can_read(buffer, 1) || !is_digit(buffer->ptr[buffer->offset])) {
        PRINTF("parse_unsigned_decimal: couldn't read byte, or not a digit: %d\n",
               buffer->ptr[buffer->offset]);
        return -1;
    }

    size_t result = 0;
    int digits_read = 0;
    while ((buffer_can_read(buffer, 1) && is_digit(buffer->ptr[buffer->offset]))) {
        ++digits_read;
        uint8_t next_digit = buffer->ptr[buffer->offset] - '0';

        if (digits_read == 2 && result == 0) {
            // if the first digit was a 0, than it should be the only digit
            return -1;
        }

        if (10 * result + next_digit < result) {
            PRINTF("parse_unsigned_decimal: overflow. Current: %d. Next digit: %d\n",
                   result,
                   next_digit);
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
    if (buffer_can_read(buffer, 1) || buffer->ptr[buffer->offset] == '\'') {
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

    if (!buffer_can_read(buffer, 1)) {
        return -1;
    }

    if (buffer->ptr[buffer->offset] == '[') {
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
        while (buffer->ptr[buffer->offset] == '/') {
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
        uint8_t c;
        if (!buffer_read_u8(buffer, &c) || c != ']') {
            return -1;
        }
    }

    // consume the rest of the buffer into the pubkey, except possibly the final "/**"
    unsigned int ext_pubkey_len = 0;
    while (ext_pubkey_len < MAX_SERIALIZED_PUBKEY_LENGTH && buffer_can_read(buffer, 1) &&
           is_alphanumeric(buffer->ptr[buffer->offset])) {
        buffer_read_u8(buffer, (uint8_t *) &out->ext_pubkey[ext_pubkey_len]);
        ++ext_pubkey_len;
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

#define CONTEXT_WITHIN_SH 1

/**
 * Parses a SCRIPT expression from the in_buf buffer, allocating the nodes and variables in out_buf.
 * The initial pointer in out_buf will contain the root node of the SCRIPT.
 */
static int parse_script(buffer_t *in_buf,
                        buffer_t *out_buf,
                        size_t depth,
                        unsigned long context_flags) {
    // We read the token, we'll do different parsing based on what token we find
    int token = parse_token(in_buf);
    char c;

    // Opening '('
    if (!buffer_read_u8(in_buf, (uint8_t *) &c) && c != '(') {
        return -1;
    }

    switch (token) {
        case TOKEN_SH:
        case TOKEN_WSH: {
            if (token == TOKEN_SH) {
                if (depth != 0) {
                    return -2;  // can only be top-level
                }

            } else if (token == TOKEN_WSH) {
                if (depth != 0 && (context_flags & CONTEXT_WITHIN_SH) == 0) {
                    return -3;  // only top-level or inside sh
                }
            }

            policy_node_with_script_t *node =
                (policy_node_with_script_t *) buffer_alloc(out_buf,
                                                           sizeof(policy_node_with_script_t),
                                                           true);
            if (node == NULL) {
                return -4;
            }
            node->type = token;

            unsigned int inner_context_flags = context_flags;

            if (token == TOKEN_SH) {
                inner_context_flags |= CONTEXT_WITHIN_SH;
            }

            // the internal script is recursively parsed (if successful) in the current location of
            // the output buffer
            node->script = (policy_node_t *) (out_buf->ptr + out_buf->offset);

            int res2;
            if ((res2 = parse_script(in_buf, out_buf, depth + 1, inner_context_flags)) < 0) {
                // failed while parsing internal script
                return res2 * 100 - 5;
            }

            break;
        }
        case TOKEN_PKH:
        case TOKEN_WPKH:
        case TOKEN_TR:  // not currently supporting x-only keys
        {
            policy_node_with_key_t *node =
                (policy_node_with_key_t *) buffer_alloc(out_buf,
                                                        sizeof(policy_node_with_key_t),
                                                        true);
            if (node == NULL) {
                return -6;
            }
            node->type = token;

            int key_index = parse_key_index(in_buf);
            if (key_index == -1) {
                return -7;
            }
            node->key_index = (size_t) key_index;

            break;
        }
        case TOKEN_MULTI:
        case TOKEN_SORTEDMULTI: {
            policy_node_multisig_t *node =
                (policy_node_multisig_t *) buffer_alloc(out_buf,
                                                        sizeof(policy_node_multisig_t),
                                                        true);

            if (node == NULL) {
                return -8;
            }
            node->type = token;

            if (parse_unsigned_decimal(in_buf, &node->k) == -1) {
                PRINTF("Error parsing threshold\n");
                return -9;
            }

            // We allocate the array of key indices at the current position in the output buffer (on
            // success)
            node->key_indexes = (size_t *) (out_buf->ptr + out_buf->offset);

            node->n = 0;
            while (true) {
                // If the next character is a ')', we exit and leave it in the buffer
                if (buffer_can_read(in_buf, 1) && in_buf->ptr[in_buf->offset] == ')') {
                    break;
                }

                // otherwise, there must be a comma
                if (!buffer_read_u8(in_buf, (uint8_t *) &c) || c != ',') {
                    PRINTF("Unexpected char: %c. Was expecting: ,\n", c);
                    return -10;
                }

                int key_index = parse_key_index(in_buf);
                if (key_index == -1) {
                    return -11;
                }

                size_t *key_index_out = (size_t *) buffer_alloc(out_buf, sizeof(size_t), true);
                if (key_index_out == NULL) {
                    return -12;
                }
                *key_index_out = (size_t) key_index;

                ++node->n;
            }

            // check integrity of k and n
            if (!(1 <= node->k && node->k <= node->n && node->n <= MAX_POLICY_MAP_COSIGNERS)) {
                return -13;
            }

            break;
        }
        default:
            PRINTF("Unknown token\n");
            return -14;
    }

    if (!buffer_read_u8(in_buf, (uint8_t *) &c) && c != ')') {
        return -15;
    }

    if (depth == 0 && buffer_can_read(in_buf, 1)) {
        PRINTF("Input buffer too long\n");
        return -16;
    }

    return 0;
}

int parse_policy_map(buffer_t *in_buf, void *out, size_t out_len) {
    if ((unsigned long) out % 4 != 0) {
        PRINTF("Unaligned pointer\n");
        return -1;
    }

    buffer_t out_buf = buffer_create(out, out_len);

    return parse_script(in_buf, &out_buf, 0, 0);
}

// TODO: add unit tests
int get_script_type(const uint8_t script[], size_t script_len) {
    if (script_len == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 &&
        script[23] == 0x88 && script[24] == 0xac) {
        return SCRIPT_TYPE_P2PKH;
    }

    if (script_len == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87) {
        return SCRIPT_TYPE_P2SH;
    }

    if (script_len == 22 && script[0] == 0x00 && script[1] == 0x14) {
        return SCRIPT_TYPE_P2WPKH;
    }

    if (script_len == 34 && script[0] == 0x00 && script[1] == 0x20) {
        return SCRIPT_TYPE_P2WSH;
    }

    if (script_len == 34 && script[0] == 0x51 && script[1] == 0x20) {
        return SCRIPT_TYPE_P2TR;
    }

    // unknown
    return -1;
}

#ifndef SKIP_FOR_CMOCKA

// TODO: add unit tests
int get_script_address(const uint8_t script[],
                       size_t script_len,
                       global_context_t *coin_config,
                       char *out,
                       size_t out_len) {
    int script_type = get_script_type(script, script_len);
    int addr_len;
    switch (script_type) {
        case SCRIPT_TYPE_P2PKH:
            addr_len =
                base58_encode_address(script + 3, coin_config->p2pkh_version, out, out_len - 1);
            break;
        case SCRIPT_TYPE_P2SH:
            addr_len =
                base58_encode_address(script + 2, coin_config->p2sh_version, out, out_len - 1);
            break;
        case SCRIPT_TYPE_P2WPKH:
        case SCRIPT_TYPE_P2WSH:
        case SCRIPT_TYPE_P2TR: {
            // bech32/bech32m encoding

            // 20 for P2WPKH, 32 for P2WSH or P2TR
            int hash_length = (script_type == SCRIPT_TYPE_P2WPKH ? 20 : 32);

            // witness program version
            int version = (script_type == SCRIPT_TYPE_P2TR ? 1 : 0);

            // make sure that the output buffer is long enough
            if (out_len < 73 + strlen(coin_config->native_segwit_prefix)) {
                return -1;
            }

            int ret = segwit_addr_encode(out,
                                         coin_config->native_segwit_prefix,
                                         version,
                                         script + 2,
                                         hash_length  // 20 for WPKH, 32 for WSH
            );

            if (ret != 1) {
                return -1;  // should never happen
            }

            addr_len = strlen(out);
            break;
        }
        default:
            return -1;
    }
    out[addr_len] = '\0';
    return addr_len;
}

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
