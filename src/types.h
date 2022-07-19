#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#include "constants.h"
#include "common/bip32.h"
#include "commands.h"
#include "context.h"

#define STORAGE_MAGIC 0xDEAD1337

typedef struct internalStorage_t {
    uint32_t magic;
    uint8_t wallet_registration_key[32];
} internalStorage_t;