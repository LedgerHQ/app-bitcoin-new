#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#define MAX_TX_LEN   510
#define ADDRESS_LEN  20
#define MAX_MEMO_LEN 465  // 510 - ADDRESS_LEN - 2*SIZE(U64) - SIZE(MAX_VARINT)

typedef enum {
    PARSING_OK = 1,
    NONCE_PARSING_ERROR = -1,
    TO_PARSING_ERROR = -2,
    VALUE_PARSING_ERROR = -3,
    MEMO_LENGTH_ERROR = -4,
    MEMO_PARSING_ERROR = -5,
    MEMO_ENCODING_ERROR = -6,
    WRONG_LENGTH_ERROR = -7
} parser_status_e;

typedef struct {
    uint64_t nonce;     /// nonce (8 bytes)
    uint64_t value;     /// amount value (8 bytes)
    uint8_t *to;        /// pointer to address (20 bytes)
    uint8_t *memo;      /// memo (variable length)
    uint64_t memo_len;  /// length of memo (8 bytes)
} transaction_t;
