#pragma once

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_SUM_OF_SQUARES = 0x07, /// compute the sum of the squares up to a number (I know, right?)
} command_e;

typedef struct {
    uint32_t sum;
    uint16_t i;
    uint8_t n;
} get_sum_of_squares_state_t;



/**
 * 
 */
typedef union {
    get_sum_of_squares_state_t get_sum_of_squares_state;
    // ...state for other interruptible commands would be added here
} command_state_t;