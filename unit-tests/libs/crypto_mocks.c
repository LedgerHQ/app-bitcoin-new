#include <stdint.h>
#include "crypto_mocks.h"
#include "sha-256.h"

void crypto_get_checksum(const uint8_t *in, uint16_t in_len, uint8_t out[static 4]) {
    uint8_t buffer[32];
    calc_sha_256(buffer, in, in_len);
    calc_sha_256(buffer, buffer, 32);
    memmove(out, buffer, 4);
}
