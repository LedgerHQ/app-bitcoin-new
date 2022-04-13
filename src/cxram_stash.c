#include <stdint.h>

#include "cxram_stash.h"
#include "cx_ram.h"

#ifndef G_cx
// The G_cx symbol is only defined in the sdk if compiled with certain libs are included.
// This makes sure that the symbol exists nonetheless.
union cx_u G_cx;
#endif

#ifdef USE_CXRAM_SECTION

uint8_t *get_cxram_buffer() {
    return (uint8_t *) &G_cx;
}

#endif
