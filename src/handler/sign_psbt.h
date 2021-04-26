#pragma once

#include "../boilerplate/dispatcher.h"

#include "flows/check_merkle_tree_sorted.h"

typedef struct {
    machine_context_t ctx;

    size_t global_map_size;
    uint8_t global_keys_root[20];
    uint8_t global_values_root[20];

    size_t n_inputs;
    uint8_t inputs_root[20];
    size_t n_outputs;
    uint8_t outputs_root[20];

    union {
        check_merkle_tree_sorted_state_t check_merkle_tree_sorted;
    } subcontext;
} sign_psbt_state_t;

void handler_sign_psbt(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
);
