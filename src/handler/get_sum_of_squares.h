#pragma once

#include "../commands.h"

void init_get_sum_of_squares_state(get_sum_of_squares_state_t *state, dispatcher_context_t *dispatcher_context);

/**
 * Handler for GET_SUM_OF_SQUARES command. Returns the sum of the squares
 * of all the numbers between 1 and n
 *
 * @return a non negative integer.
 *
 */
int handler_get_sum_of_squares(get_sum_of_squares_state_t *state, dispatcher_context_t *dispatcher_context);
