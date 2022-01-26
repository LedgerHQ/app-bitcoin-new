#pragma once

typedef struct swap_globals_s {
    /*Is swap mode*/
    unsigned char called_from_swap;
} swap_globals_t;

extern swap_globals_t G_swap_state;
