#pragma once

#ifdef HAVE_SWAP

#include <stdbool.h>

/* SDK headers */
#include "bip32.h"
#include "constants.h"

#define MAX_BIP32_PATH_LENGTH (4 * MAX_BIP32_PATH_STEPS) + 1

typedef struct bip32_path {
    unsigned char length;
    unsigned int path[MAX_BIP32_PATH_STEPS];
} bip32_path_t;

bool parse_serialized_path(bip32_path_t* path,
                           unsigned char* serialized_path,
                           unsigned char serialized_path_length);

#endif /* HAVE_SWAP */
