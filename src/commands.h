#pragma once

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_SUM_OF_SQUARES = 0x07, /// compute the sum of the squares up to a number (I know, right?)

    CONTINUE = 0xFF            /// continue interrupted APDU
} command_e;

typedef struct {
    uint32_t sum;
    uint16_t i;
    uint8_t n;
} get_sum_of_squares_state_t;

typedef 

/**
 * Structure with the fields of APDU command that are saved for an interrupted command.
 */
typedef struct {
    command_e ins;  /// Instruction code
    uint8_t p1;     /// Instruction parameter 1
    uint8_t p2;     /// Instruction parameter 2
} interrupted_command_t;

typedef union {
    get_sum_of_squares_state_t get_sum_of_squares_state;
    // ...state for other interruptible commands would be added here
} command_state_t;