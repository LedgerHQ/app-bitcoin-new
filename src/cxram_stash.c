#include <stdint.h>

#include "cxram_stash.h"
#include "cx_ram.h"

#ifndef USE_CXRAM_SECTION

uint8_t G_cxram_replacement_buffer[1024];

uint8_t *get_cxram_buffer() {
    return G_cxram_replacement_buffer;
}

#else

#ifndef G_cx
union cx_u G_cx;
#endif

uint8_t *get_cxram_buffer() {
    return (uint8_t *) &G_cx;
}

#endif
