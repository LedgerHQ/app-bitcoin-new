#pragma once

#include "crypto.h"

static inline bool is_p2wpkh(uint8_t script[], size_t script_len) {
    return script_len == 22 && script[0] == 0x00 && script[1] == 0x14;
}

static inline bool is_p2wsh(uint8_t script[], size_t script_len) {
    return script_len == 34 && script[0] == 0x00 && script[1] == 0x20;
}
