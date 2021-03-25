#include <stdint.h>

#include "common/buffer.h"
#include "wallet.h"

#include "../crypto.h"

int read_wallet_header(buffer_t *buffer, multisig_wallet_header_t *header) {
    if (!buffer_read_u8(buffer, &header->type)){
        return -1;
    }

    if (header->type != WALLET_TYPE_MULTISIG) {
        return -2;
    }

    // The remaining code assumes that the wallet's type is WALLET_TYPE_MULTISIG, currently the only supported one.

    if (!buffer_read_u8(buffer, &header->name_len)) {
        return -3;
    }

    if (header->name_len > MAX_WALLET_NAME_LENGTH) {
        return -4;
    }

    if (!buffer_read_bytes(buffer, (uint8_t *)header->name, header->name_len)) {
        return -5;
    }
    header->name[header->name_len] = '\0';

    if (!buffer_read_u8(buffer, &header->threshold) ||
        !buffer_read_u8(buffer, &header->n_keys)
    ) {
        return -6;
    }

    if (header->threshold == 0 || header->n_keys == 0 || header->n_keys > 15 || header->threshold > header->n_keys) {
        return -7;
    }
    return 0;
}



void hash_update_append_wallet_header(cx_hash_t *hash_context, multisig_wallet_header_t *header) {
    crypto_hash_update(hash_context, &header->type, 1);
    crypto_hash_update(hash_context, &header->name_len, 1);
    crypto_hash_update(hash_context, &header->name, header->name_len);

    // The following assumes that the type is WALLET_TYPE_MULTISIG (only supported type so far)
    crypto_hash_update(hash_context, &header->threshold, 1);
    crypto_hash_update(hash_context, &header->n_keys, 1);
}