#pragma once

#include "types.h"
#include "../common/buffer.h"

typedef struct {
    buffer_t read_buffer;
    bool is_continuation;
    bool interrupt;
} dispatcher_context_t;

/**
 * Dispatch APDU command received to the right handler.
 *
 * @param[in] cmd
 *   Structured APDU command (CLA, INS, P1, P2, Lc, Command data).
 *
 * @return zero or positive integer if success, negative integer otherwise.
 *
 */
int apdu_dispatcher(const command_t *cmd);
