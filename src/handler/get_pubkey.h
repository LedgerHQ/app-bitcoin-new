#pragma once

#include "../commands.h"

#define MAX_SERIALIZED_PUBKEY_LENGTH 113

typedef struct {
    char serialized_pubkey_str[MAX_SERIALIZED_PUBKEY_LENGTH];
} get_pubkey_state_t;

int handler_get_pubkey(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
);
