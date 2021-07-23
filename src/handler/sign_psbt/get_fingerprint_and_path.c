#include <stdint.h>
#include <string.h>

#include "get_fingerprint_and_path.h"

#include "../lib/get_merkleized_map_value.h"

#include "../../common/read.h"

int get_fingerprint_and_path(dispatcher_context_t *dispatcher_context,
                             const merkleized_map_commitment_t *map,
                             const uint8_t *key,
                             int key_len,
                             uint32_t *out_fingerprint,
                             uint32_t out_bip32_path[static MAX_BIP32_PATH_STEPS])
{
    LOG_PROCESSOR(dispatcher_context, __FILE__, __LINE__, __func__);

    uint8_t fpt_der[4 + 4*MAX_BIP32_PATH_STEPS];

    int len = call_get_merkleized_map_value(dispatcher_context,
                                            map,
                                            key,
                                            key_len,
                                            fpt_der,
                                            sizeof(fpt_der));

    if (len < 4 || len % 4 != 0) {
        return -1;
    }

    int bip32_path_len = (len - 4)/4;

    if (bip32_path_len > MAX_BIP32_PATH_STEPS) {
        return -1;
    }

    *out_fingerprint = read_u32_le(fpt_der, 0);

    for (int i = 0; i < bip32_path_len; i++) {
        out_bip32_path[i] = read_u32_le(fpt_der, 4 + 4*i);
    }

    return bip32_path_len;
}

