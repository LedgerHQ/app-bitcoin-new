#pragma once

/*
 * Due to lack of available stack on NanoS, we make use of a 1K RAM region that is shared between
 * applications and bolos, and used as temporary memory for cryptographic computations.
 *
 * If USE_CXRAM_SECTION is not set, we define a 1K global buffer, and use that instead.
 */

/**
 * Returns the address of the 1K cxram section, or the global 1K replacement stash
 * if USE_CXRAM_SECTION is not set.
 */
uint8_t *get_cxram_buffer();