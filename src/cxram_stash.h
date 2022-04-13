#pragma once

/*
 * Due to lack of available stack on NanoS, we make use of a 1K RAM region that is shared between
 * applications and bolos, and used as temporary memory for cryptographic computations.
 *
 * If USE_CXRAM_SECTION is not set, we don't define this functions; a local buffer in stack must be
 * used instead.
 */

/**
 * Returns the address of the 1K cxram section.
 */

#ifdef USE_CXRAM_SECTION
uint8_t *get_cxram_buffer();
#endif