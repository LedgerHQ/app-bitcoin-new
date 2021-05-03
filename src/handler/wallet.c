#include <stdint.h>
#include <limits.h>

#include "../common/bip32.h"
#include "../common/buffer.h"
#include "../boilerplate/sw.h"

#include "wallet.h"

#include "../crypto.h"

// only tokens that are relevant for multisig, until we generalize to more wallet types
static const char *KNOWN_TOKENS[] = {
    "sh",
    "wsh",
    "multi",
    "sortedmulti"
};

/*
Currently supported wallet policies for multisig:

   LEGACY
  sh(multi(k,...)))
  sh(sortedmulti(...)))
  
   NATIVE SEGWIT
  wsh(multi(...))
  wsh(sortedmulti(...))
  
   WRAPPED SEGWIT
  sh(wsh(multi(...)))
  sh(wsh(sortedmulti(...)))
*/

// TODO: might be worth adopting the same descriptor template syntax proposed for BSMS (that is using key/** for the wallet path roots)

// TODO: add unit tests to this module


#define TOKEN_SH 0
#define TOKEN_WSH 1
#define TOKEN_MULTI 2
#define TOKEN_SORTEDMULTI 3

#define MAX_TOKEN_LENGTH (sizeof("sortedmulti") - 1)


int read_wallet_header(buffer_t *buffer, multisig_wallet_header_t *header) {
    if (!buffer_read_u8(buffer, &header->type)){
        return -1;
    }

    if (header->type != WALLET_TYPE_MULTISIG) {
        return -2;
    }

    // The remaining code assumes that the wallet's type is WALLET_TYPE_MULTISIG, currently the only supported one.

    if (!buffer_read_u8(buffer, &header->name_len)) {
        return -3;
    }

    if (header->name_len > MAX_WALLET_NAME_LENGTH) {
        return -4;
    }

    if (!buffer_read_bytes(buffer, (uint8_t *)header->name, header->name_len)) {
        return -5;
    }
    header->name[header->name_len] = '\0';
    return 0;
}



void hash_update_append_wallet_header(cx_hash_t *hash_context, multisig_wallet_header_t *header) {
    crypto_hash_update(hash_context, &header->type, 1);
    crypto_hash_update(hash_context, &header->name_len, 1);
    crypto_hash_update(hash_context, &header->name, header->name_len);
}

static bool is_digit(char c) {
    return '0' <= c && c <= '9';
}

static bool is_alpha(char c) {
    return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z');
}

static bool is_lowercase_hex(char c) {
    return is_digit(c) || ('a' <= c && c <= 'f');
}

static uint8_t lowercase_hex_to_int(char c) {
    return (uint8_t)(is_digit(c) ? c - '0' : c - 'a' + 10);
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
    char word[MAX_TOKEN_LENGTH+1];

    size_t word_len = read_word(buffer, word, MAX_TOKEN_LENGTH);
    word[word_len] = '\0';

    for (int i = 0; i < (int)sizeof(KNOWN_TOKENS); i++) {
        if (strncmp((const char *)PIC(KNOWN_TOKENS[i]), word, MAX_TOKEN_LENGTH) == 0) {
            return i;
        }
    }

    return -1;
}


/**
 * Parses an unsigned decimal number from buffer, stopping when either the buffer ends, the next
 * character is not a number, or the number is already too big. Leading zeros are allowed.
 * Returns a valid 0 on success, -1 on failure.
 * The read number is saved into *out on success.
 */
// TODO: disallow non-standard (e.g. extra leading zeros)
static int parse_unsigned_decimal(buffer_t *buffer, uint32_t *out) {
    if (!buffer_can_read(buffer, 1) || !is_digit(buffer->ptr[buffer->offset])) {
        PRINTF("parse_unsigned_decimal: couldn't read byte, or not a digit: %d\n", buffer->ptr[buffer->offset]);
        return -1;
    }

    uint32_t result = 0;
    while ((buffer_can_read(buffer, 1) && is_digit(buffer->ptr[buffer->offset]))) {
        uint8_t next_digit = buffer->ptr[buffer->offset] - '0';
        if (10 * result + next_digit < result) {
            PRINTF("parse_unsigned_decimal: overflow. Current: %d. Next digit: %d\n", result, next_digit);
            return -1; // overflow, integer too large
        }

        result = 10 * result + next_digit;

        buffer_seek_cur(buffer, 1);
    }
    *out = result;
    return 0;
}


int buffer_read_multisig_policy_map(buffer_t *buffer, multisig_wallet_policy_t *out) {
    int depth = 0;      // how many parentheses have been opened and not yet closed

    uint32_t n_keys = 0; // will be computed during parsing
    uint32_t threshold;

    bool sh_found = false;
    bool wsh_found = false;
    bool sorted = false;

    bool exit = false; // set to true once we finish parsing a 'multi' or 'sortedmulti'
    while (!exit) {
        // PARSING A FUNCTION HERE

        // We read the token, we'll do different parsing based on what token we find
        int token = parse_token(buffer);
        if (token == -1) {
            PRINTF("Exited while parsing token at offset %d\n", buffer->offset);
            return -1;
        }


        // the next caracter must be a '('
        if (!buffer_can_read(buffer, 1) || buffer->ptr[buffer->offset] != '(') {
            PRINTF("EXPECTED: (\n", token);
            return -1;
        } else {
            buffer_seek_cur(buffer, 1); // skip character
        }

        char c;
        switch (token) {
            case TOKEN_SH:
                if (depth != 0) {
                    return -1; // can only be top-level
                }
                sh_found = true;
                break;

            case TOKEN_WSH:
                if (wsh_found) {
                    return -1; // wsh cannot be inside another wsh
                }
                wsh_found = true;
                break;

            case TOKEN_MULTI:
            case TOKEN_SORTEDMULTI:
                sorted = token == TOKEN_SORTEDMULTI;

                if (parse_unsigned_decimal(buffer, &threshold) == -1) {
                    PRINTF("Error parsing threshold\n");
                    return -1; // failed to parse number
                }

                while (true) {
                    // If the next character is a ')', we exit leaving it in the buffer
                    if (buffer_can_read(buffer, 1) && buffer->ptr[buffer->offset] == ')') {
                        break;
                    }

                    if (!buffer_read_u8(buffer, (uint8_t *)&c) || c != ',') {
                        PRINTF("Unexpected char: %c. Was expecting: ,\n", c);
                        return -1;
                    }

                    // the next character must be '\t', followed by a decimal number equal to
                    // the current value of n_keys
                    if (!buffer_read_u8(buffer, (uint8_t *)&c) || c != '\t') {
                        PRINTF("Unexpected char: %c. Was expecting: \\t\n", c);
                        return -1;
                    }
                    uint32_t key_number;
                    if (parse_unsigned_decimal(buffer, &key_number) == -1 || key_number != n_keys) {
                        PRINTF("Failed parsing key number, or unexpected index. %u %u\n", key_number, n_keys);
                        return -1;
                    }

                    ++n_keys;
                }

                if (!(0 < threshold && threshold <= n_keys && n_keys <= MAX_MULTISIG_COSIGNERS)) {
                    return -1;
                }

                // Once we parsed a multi/sortedmulti, we only expect closing parentheses to be the rest of the
                // string being parsed. This will change once support to more general descriptors is added.
                exit = true;
                break;

            default:
                PRINTF("Uknown token"); // this should never happen
                return -1;
        }

        ++depth;
    }

    // We should now be left with exactly depth closing parentheses
    for (int i = 0; i < depth; i++) {
        char c;
        if (!buffer_read_u8(buffer, (uint8_t *)&c) || c != ')') {
            return -1;
        }
    }

    // Make sure we exhausted the buffer
    if (buffer_can_read(buffer, 1)) {
        return -1;
    }

    out->n_keys = n_keys;
    out->threshold = threshold;
    out->sorted = sorted;

    if (sh_found) {
        if (!wsh_found) {
            out->address_type = ADDRESS_TYPE_LEGACY;
        } else {
            out->address_type = ADDRESS_TYPE_SH_WIT;
        }
    } else if (wsh_found) {
        out->address_type = ADDRESS_TYPE_WIT;
    } else {
        PRINTF("Unexpected address type"); // should never happen
        return -1;
    }

    return 0;
}


// Reads a derivation step expressed in decimal, with the symbol ' to mark if hardened (h is not supported)
// Returns 0 on success, -1 on error.
static int buffer_read_derivation_step(buffer_t *buffer, uint32_t *out) {
    uint32_t der_step;
    if (parse_unsigned_decimal(buffer, &der_step) == -1 || der_step >= BIP32_FIRST_HARDENED_CHILD) {
        return -1;
    }

    *out = der_step;

    // Check if hardened
    if (buffer_can_read(buffer, 1) || buffer->ptr[buffer->offset] == '\'') {
        *out |= BIP32_FIRST_HARDENED_CHILD;
        buffer_seek_cur(buffer, 1); // skip the ' character
    }
    return 0;
}


// TODO: we are currently enforcing that the master key fingerprint (if present) is in lowercase hexadecimal digits,
//       and that the symbol for "hardened derivation" is "'".
//       This implies descriptors should be normalized on the client side.
int parse_policy_map_key_info(buffer_t *buffer, policy_map_key_info_t *out) {
    if (!buffer_can_read(buffer, 1)) {
        return -1;
    }

    if (buffer->ptr[buffer->offset] == '[') {
        out->has_key_origin = 1;

        buffer_seek_cur(buffer, 1); // skip 1 byte
        if (!buffer_can_read(buffer, 9)) { // at least 8 bytes + (closing parenthesis or '\')
            return -1;
        }
        for (int i = 0; i < 4; i++) {
            char num[2];
            buffer_read_bytes(buffer, (uint8_t *)num, 2);
            if (!is_lowercase_hex(num[0]) || !is_lowercase_hex(num[1])) {
                return -1;
            }
            out->master_key_fingerprint[i] = 16*lowercase_hex_to_int(num[0]) + lowercase_hex_to_int(num[1]);
        }

        // read all the given derivation steps
        out->master_key_derivation_len = 0;
        while (buffer->ptr[buffer->offset] == '/') {
            ++out->master_key_derivation_len;
            if (out->master_key_derivation_len > MAX_BIP32_PATH_STEPS) {
                return -1;
            }

            if (!buffer_read_derivation_step(buffer, &out->master_key_derivation[out->master_key_derivation_len])) {
                return -1;
            };
        }

        // the next character must be ']'
        uint8_t c;
        if (!buffer_read_u8(buffer, &c) || c != ']') {
            return -1;
        }
    }

    // consume the rest of the buffer into the xpub
    // TODO: should we check if bytes are correct, or at least in the right alphabet?
    int ext_pubkey_len = 0;
    while (ext_pubkey_len < MAX_SERIALIZED_PUBKEY_LENGTH && buffer_can_read(buffer, 1)) {
        buffer_read_u8(buffer, (uint8_t *)&out->ext_pubkey[ext_pubkey_len]);
        ++ext_pubkey_len;
    }
    out->ext_pubkey[ext_pubkey_len] = '\0';

    // Make sure that the buffer is indeed exhausted
    if (buffer_can_read(buffer, 1)) {
        return -1;
    }

    return 0;
}


void get_policy_wallet_id(multisig_wallet_header_t *wallet_header,
                          uint16_t policy_map_len,
                          const char policy_map[],
                          uint16_t n_keys,
                          const uint8_t keys_info_merkle_root[static 20],
                          uint8_t out[static 32])
{
    cx_sha256_t wallet_hash_context;
    cx_sha256_init(&wallet_hash_context);

    hash_update_append_wallet_header(&wallet_hash_context.header, wallet_header);

    crypto_hash_update_u16(&wallet_hash_context.header, policy_map_len);
    crypto_hash_update(&wallet_hash_context.header, policy_map, policy_map_len);

    crypto_hash_update_u16(&wallet_hash_context.header, n_keys);

    crypto_hash_update(&wallet_hash_context.header, keys_info_merkle_root, 20);
    crypto_hash_digest(&wallet_hash_context.header, out, 32);
}