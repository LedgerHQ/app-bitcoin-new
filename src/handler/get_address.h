#pragma once

#include "../commands.h"

#define MAX_ADDRESS_LENGTH_STR 74 // segwit addresses can reach 74 characters

typedef struct {
    char address[MAX_ADDRESS_LENGTH_STR + 1];
    size_t address_len;
} get_address_state_t;

int handler_get_address(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
);
