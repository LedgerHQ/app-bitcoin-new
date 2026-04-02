#pragma once

#ifdef HAVE_SWAP

#include <stdint.h>

enum {
    SWAP_MODE_STANDARD = 0,
    SWAP_MODE_CROSSCHAIN = 1,
    SWAP_MODE_ERROR = 0xFF,
};

typedef struct swap_globals_s {
    uint64_t amount;
    uint64_t fees;
    char destination_address[65];
    unsigned char should_exit;
    unsigned char mode;
    uint8_t payin_extra_id[1 + 32];
} swap_globals_t;

extern swap_globals_t G_swap_state;

#endif /* HAVE_SWAP */
