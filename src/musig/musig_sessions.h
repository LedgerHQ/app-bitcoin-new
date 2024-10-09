#pragma once

#include <stdbool.h>
#include "musig.h"

#define MAX_N_MUSIG_SESSIONS 8

typedef struct {
    uint8_t id[32];
    uint8_t rand_root[32];
} musig_session_t;

extern musig_session_t musig_sessions[MAX_N_MUSIG_SESSIONS];

// TODO: docs
bool musigsession_pop(uint8_t psbt_session_id[static 32], musig_session_t *out);
void musigsession_init_randomness(musig_session_t *session);
void musigsession_store(uint8_t psbt_session_id[static 32], const musig_session_t *session);

void compute_rand_i_j(const uint8_t rand_root[static 32], int i, int j, uint8_t out[static 32]);
