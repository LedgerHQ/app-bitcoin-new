#include "string.h"

#include "check_merkle_tree_sorted.h"

#include "../../boilerplate/dispatcher.h"
#include "../../boilerplate/sw.h"
#include "../../common/merkle.h"
#include "../../crypto.h"
#include "../../constants.h"
#include "../client_commands.h"

// processors
static void receive_element(dispatcher_context_t *dc);


// other utility functions
static int compare_byte_arrays(const uint8_t array1[], size_t array1_len, const uint8_t array2[], size_t array2_len);


void flow_check_merkle_tree_sorted(dispatcher_context_t *dc) {
    check_merkle_tree_sorted_state_t *state = (check_merkle_tree_sorted_state_t *)dc->machine_context_ptr;

    PRINTF("%s %d: %s\n", __FILE__, __LINE__, __func__);

    state->cur_el_idx = 0;
    state->prev_el_len = 0;

    call_get_merkle_leaf_element(dc,
                                 &state->subcontext.get_merkle_leaf_element,
                                 receive_element,
                                 state->root,
                                 state->size,
                                 state->cur_el_idx,
                                 state->cur_el,
                                 sizeof(state->cur_el));
}

// Receives an element; checks if lexicographical order is correct 
static void receive_element(dispatcher_context_t *dc) {
    check_merkle_tree_sorted_state_t *state = (check_merkle_tree_sorted_state_t *)dc->machine_context_ptr;

    PRINTF("%s %d: %s\n", __FILE__, __LINE__, __func__);

    if (state->subcontext.get_merkle_leaf_element.result == false) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    state->cur_el_len = state->subcontext.get_merkle_leaf_element.element_len;

    if (state->cur_el_idx > 0
        && compare_byte_arrays(state->prev_el, state->prev_el_len, state->cur_el, state->cur_el_len) >= 0)
    {
        // elements are not in (strict) lexicographical order
        PRINTF("Not in lexicographical order.");

        state->result = false;
        return;
    }

    memcpy(state->prev_el, state->cur_el, state->cur_el_len);
    state->prev_el_len = state->cur_el_len;

    ++state->cur_el_idx;

    if (state->cur_el_idx < state->size) {
        dc->next(receive_element);
    } else {
        state->result = true;
    }
}



// Returns a negative number, 0 or a positive number if the first array is (respectively) lexicographically smaller,
// equal, or larger than the second.
// If one array is prefix than the other, then the shorter ones comes first in lexicographical order. 
static int compare_byte_arrays(const uint8_t array1[], size_t array1_len, const uint8_t array2[], size_t array2_len) {
    size_t min_len = array1_len < array2_len ? array1_len : array2_len;

    // it is unclear from the docs if memcmp(_, _, 0) is guaranteed to return 0; therefore we avoid relying on it here.
    int memcmp_result;
    if (min_len == 0 || (memcmp_result = memcmp(array1, array2, min_len) == 0)) {
        // One of the arrays is a prefix of the other; the shortest comes first
        if (array1_len < array2_len) return -1;
        else if (array1_len > array2_len) return 1;
        else return 0;
    }

    return memcmp_result;
}