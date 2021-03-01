#pragma once

#include "boilerplate/dispatcher.h"
#include "constants.h"
#include "handler/get_sum_of_squares.h"

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_SUM_OF_SQUARES = 0x07, /// compute the sum of the squares up to a number (I know, right?)
} command_e;

/**
 * 
 */
typedef union {
    get_sum_of_squares_state_t get_sum_of_squares_state;
    // ...state for other interruptible commands would be added here
} command_state_t;