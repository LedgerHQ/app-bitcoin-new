#pragma once

#include "../constants.h"
#include "../boilerplate/dispatcher.h"

typedef struct {
    machine_context_t ctx;
    char address[MAX_ADDRESS_LENGTH_STR + 1];
    size_t address_len;
} get_address_state_t;

void handler_get_address(dispatcher_context_t *dispatcher_context);
