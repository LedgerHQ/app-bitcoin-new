// We're currently unable to compile the app's crypto.c in unit tests.
// This library mocks the functions currently used in other modules that are part of
// the unit tests.

#include <stdint.h>

void crypto_get_checksum(const uint8_t *in, uint16_t in_len, uint8_t out[static 4]);