#include <string.h>

#include "cx.h"

#include "musig_sessions.h"
#include "../crypto.h"

typedef struct {
    // Aligning by 4 is necessary due to platform limitations.
    // Aligning by 64 further guarantees that each session occupies exactly
    // a single NVRAM page, minimizing the number of writes.
    __attribute__((aligned(64))) musig_psbt_session_t sessions[MAX_N_MUSIG_SESSIONS];
} musig_persistent_storage_t;

const musig_persistent_storage_t N_musig_storage_real;
#define N_musig_storage (*(const volatile musig_persistent_storage_t *) PIC(&N_musig_storage_real))

static bool is_all_zeros(const uint8_t *array, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        if (array[i] != 0) {
            return false;
        }
    }
    return true;
}

static bool musigsession_pop(const uint8_t psbt_session_id[static 32], musig_psbt_session_t *out) {
    for (int i = 0; i < MAX_N_MUSIG_SESSIONS; i++) {
        if (memcmp(psbt_session_id, (const void *) N_musig_storage.sessions[i]._id, 32) == 0) {
            if (out != NULL) {
                memcpy(out,
                       (const void *) &N_musig_storage.sessions[i],
                       sizeof(musig_psbt_session_t));
            }
            uint8_t zeros[sizeof(musig_psbt_session_t)] = {0};
            nvm_write((void *) &N_musig_storage.sessions[i],
                      (void *) zeros,
                      sizeof(musig_psbt_session_t));

            return true;
        }
    }
    return false;
}

static void musigsession_init_randomness(musig_psbt_session_t *session) {
    // it is extremely important that the randomness is initialized with a cryptographically strong
    // random number generator
    cx_get_random_bytes(session->_rand_root, 32);
}

static void musigsession_store(const uint8_t psbt_session_id[static 32],
                               const musig_psbt_session_t *session) {
    // make sure that no session with the same id exists; delete it otherwise
    musigsession_pop(psbt_session_id, NULL);

    int i;
    for (i = 0; i < MAX_N_MUSIG_SESSIONS; i++) {
        if (is_all_zeros((uint8_t *) &N_musig_storage.sessions[i], sizeof(musig_psbt_session_t))) {
            break;
        }
    }
    if (i >= MAX_N_MUSIG_SESSIONS) {
        // no free slot found, delete the first by default
        // TODO: should we use a LIFO structure? Could add a counter to musig_psbt_session_t
        i = 0;
    }
    // replace the chosen slot
    nvm_write((void *) &N_musig_storage.sessions[i],
              (void *) session,
              sizeof(musig_psbt_session_t));
}

void compute_rand_i_j(const musig_psbt_session_t *psbt_session,
                      int i,
                      int j,
                      uint8_t out[static 32]) {
    // It is extremely important that different choices of the root of randomness, i and j always
    // produce a different result in out.
    // Failure would be catastrophic as it would cause nonce reuse, which in MuSig2 allows attackers
    // to recover the private key.

    cx_sha256_t hash_context;
    cx_sha256_init(&hash_context);
    crypto_hash_update(&hash_context.header, psbt_session->_rand_root, CX_SHA256_SIZE);
    crypto_hash_update_u32(&hash_context.header, (uint32_t) i);
    crypto_hash_update_u32(&hash_context.header, (uint32_t) j);
    crypto_hash_digest(&hash_context.header, out, 32);
}

void musigsession_initialize_signing_state(musig_signing_state_t *musig_signing_state) {
    memset(musig_signing_state, 0, sizeof(musig_signing_state_t));
}

const musig_psbt_session_t *musigsession_round1_initialize(
    uint8_t psbt_session_id[static 32],
    musig_signing_state_t *musig_signing_state) {
    // if an existing session for psbt_session_id exists, delete it
    if (musigsession_pop(psbt_session_id, NULL)) {
        // We wouldn't expect this: probably the client sent the same psbt for
        // round 1 twice, without adding the pubnonces to the psbt after the first round.
        // We delete the old session and start a fresh one, but we print a
        // warning if in debug mode.
        PRINTF("Session with the same id already existing\n");
    }

    if (memcmp(musig_signing_state->_round1._id, psbt_session_id, 32) != 0) {
        // first input/placeholder pair using this session: initialize the session
        memcpy(musig_signing_state->_round1._id, psbt_session_id, 32);
        musigsession_init_randomness(&musig_signing_state->_round1);
    }

    return &musig_signing_state->_round1;
}

const musig_psbt_session_t *musigsession_round2_initialize(
    uint8_t psbt_session_id[static 32],
    musig_signing_state_t *musig_signing_state) {
    if (memcmp(musig_signing_state->_round2._id, psbt_session_id, 32) != 0) {
        // get and delete the musig session from permanent storage
        if (!musigsession_pop(psbt_session_id, &musig_signing_state->_round2)) {
            // The PSBT contains a partial nonce, but we do not have the corresponding psbt
            // session in storage. Either it was deleted, or the pubnonces were not real. Either
            // way, we cannot continue.
            PRINTF("Missing MuSig2 session\n");
            return NULL;
        }
    }

    return &musig_signing_state->_round2;
}

void musigsession_commit(musig_signing_state_t *musig_signing_state) {
    uint8_t acc = 0;
    for (size_t i = 0; i < sizeof(musig_signing_state->_round1); i++) {
        acc |= musig_signing_state->_round1._id[i];
    }
    // If round 1 was not executed, then there is nothing to store.
    // This assumes that musigsession_initialize_signing_state, therefore the field is zeroed out
    // if it wasn't used.
    if (acc != 0) {
        musigsession_store(musig_signing_state->_round1._id, &musig_signing_state->_round1);
    }
}
