#pragma once

#include <stdbool.h>
#include "musig.h"

// the maximum number of musig sessions that are stored in permanent memory
#define MAX_N_MUSIG_SESSIONS 8

// TODO: rename to musig_psbt_session_t to avoid confusion with musig_session_context_t
typedef struct {
    uint8_t id[32];
    uint8_t rand_root[32];
} musig_session_t;

// volatile state for musig signing
typedef struct musig_signing_state_s {
    // a session created during round 1; if signing completes (and in no other case), it is moved to
    // the persistent storage
    musig_session_t round1;
    // a session that was removed from the persistent storage before any partial signature is
    // returned during round 2. It is deleted at the end of signing, and must _never_ be used again.
    musig_session_t round2;
} musig_signing_state_t;

extern musig_session_t musig_sessions[MAX_N_MUSIG_SESSIONS];

// TODO: docs
bool musigsession_pop(uint8_t psbt_session_id[static 32], musig_session_t *out);
void musigsession_init_randomness(musig_session_t *session);
void musigsession_store(uint8_t psbt_session_id[static 32], const musig_session_t *session);

void compute_rand_i_j(const uint8_t rand_root[static 32], int i, int j, uint8_t out[static 32]);
