#pragma once

#include <stdint.h>

typedef struct swap_globals_s {
    uint64_t amount;
    uint64_t fees;
    char destination_address[65];
    /*Is swap mode*/
    unsigned char called_from_swap;
    unsigned char should_exit;
} swap_globals_t;

extern swap_globals_t G_swap_state;
