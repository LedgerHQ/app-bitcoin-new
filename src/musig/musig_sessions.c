#include <string.h>

#include "cx.h"

#include "musig_sessions.h"
#include "../crypto.h"

// TODO: persist in NVRAM instead
musig_session_t musig_sessions[MAX_N_MUSIG_SESSIONS];

bool musigsession_pop(uint8_t psbt_session_id[static 32], musig_session_t *out) {
    for (int i = 0; i < MAX_N_MUSIG_SESSIONS; i++) {
        if (memcmp(psbt_session_id, musig_sessions[i].id, 32) == 0) {
            if (out != NULL) {
                memcpy(out, &musig_sessions[i], sizeof(musig_session_t));
            }
            explicit_bzero(&musig_sessions[i], sizeof(musig_session_t));
            return true;
        }
    }
    return false;
}

static bool is_all_zeros(const uint8_t *array, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        if (array[i] != 0) {
            return false;
        }
    }
    return true;
}

void musigsession_init_randomness(musig_session_t *session) {
    cx_get_random_bytes(session->rand_root, 32);
}

void musigsession_store(uint8_t psbt_session_id[static 32], const musig_session_t *session) {
    // make sure that no session with the same id exists; delete it otherwise
    musigsession_pop(psbt_session_id, NULL);

    int i;
    for (i = 0; i < MAX_N_MUSIG_SESSIONS; i++) {
        if (is_all_zeros((uint8_t *) &musig_sessions[i], sizeof(musig_session_t))) {
            break;
        }
    }
    if (i >= MAX_N_MUSIG_SESSIONS) {
        // no free slot found, delete the first by default
        // TODO: should we use a LIFO structure? Could add a counter to musig_session_t
        i = 0;
    }
    // no free slot; replace the first slot
    explicit_bzero(&musig_sessions[i], sizeof(musig_session_t));
    memcpy(&musig_sessions[i], session, sizeof(musig_session_t));
}

void compute_rand_i_j(const uint8_t rand_root[static 32], int i, int j, uint8_t out[static 32]) {
    cx_sha256_t hash_context;
    cx_sha256_init(&hash_context);
    crypto_hash_update(&hash_context.header, rand_root, CX_SHA256_SIZE);
    crypto_hash_update_u32(&hash_context.header, (uint32_t) i);
    crypto_hash_update_u32(&hash_context.header, (uint32_t) j);
    crypto_hash_digest(&hash_context.header, out, 32);
}