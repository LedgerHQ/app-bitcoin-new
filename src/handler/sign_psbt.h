#pragma once

#include "../boilerplate/dispatcher.h"

#include "flows/get_merkle_preimage.h"

typedef struct {
    machine_context_t ctx;

    uint8_t preimage[64];

    union {
        get_merkle_preimage_state_t get_merkle_preimage;
    } subcontext;
} sign_psbt_state_t;

void handler_sign_psbt(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
);
