#include "sign_psbt_cache.h"

int derive_first_step_for_pubkey(const serialized_extended_pubkey_t *base_key,
                                 const policy_node_keyexpr_t *keyexpr,
                                 sign_psbt_cache_t *cache,
                                 bool is_change,
                                 serialized_extended_pubkey_t *out_pubkey) {
    uint32_t change_step = is_change ? keyexpr->num_second : keyexpr->num_first;

    // make sure a cache was provided, and the index is less than the size of the cache
    if (keyexpr->keyexpr_index >= MAX_CACHED_KEY_EXPRESSIONS || !cache) {
        // do not use the cache, derive the key directly
        return bip32_CKDpub(base_key, change_step, out_pubkey, NULL);
    }

    if (!cache->derived_child[keyexpr->keyexpr_index].is_child_pubkey_initialized[is_change]) {
        // key not in cache; compute it and store it in the cache
        if (0 > bip32_CKDpub(base_key,
                             change_step,
                             &cache->derived_child[keyexpr->keyexpr_index].child_pubkeys[is_change],
                             NULL))
            return -1;

        cache->derived_child[keyexpr->keyexpr_index].is_child_pubkey_initialized[is_change] = true;
    }

    // now that we are guaranteed that the key is in cache, we just copy it
    memcpy(out_pubkey,
           &cache->derived_child[keyexpr->keyexpr_index].child_pubkeys[is_change],
           sizeof(serialized_extended_pubkey_t));

    return 0;
}
