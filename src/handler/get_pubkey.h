#pragma once

#include "../crypto.h"
#include "../common/bip32.h"
#include "../boilerplate/dispatcher.h"

typedef struct {
    machine_context_t ctx;
    char serialized_pubkey_str[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
} get_pubkey_state_t;

void handler_get_pubkey(dispatcher_context_t *dispatcher_context);
