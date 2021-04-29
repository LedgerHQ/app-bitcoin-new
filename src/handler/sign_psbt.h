#pragma once

#include "../boilerplate/dispatcher.h"
#include "../common/merkle.h"

#include "flows/check_merkle_tree_sorted.h"
#include "flows/get_merkle_leaf_element.h"
#include "flows/get_merkleized_map.h"
#include "flows/get_merkleized_map_value.h"


typedef struct {
    machine_context_t ctx;

    merkleized_map_commitment_t global_map;

    size_t n_inputs;
    uint8_t inputs_root[20];
    size_t n_outputs;
    uint8_t outputs_root[20];

    int cur_input_index;
    merkleized_map_commitment_t cur_input_map;

    uint8_t tmp[80];  // temporary array to store keys requested in the PSBT maps

    uint8_t out[128]; // temporary array to store outputs

    union {
        check_merkle_tree_sorted_state_t check_merkle_tree_sorted;
        get_merkle_leaf_element_state_t get_merkle_leaf_element;
        get_merkleized_map_state_t get_merkleized_map;
        get_merkleized_map_value_state_t get_merkleized_map_value;
    } subcontext;
} sign_psbt_state_t;

void handler_sign_psbt(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
);
