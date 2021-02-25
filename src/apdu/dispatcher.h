#pragma once

#include "../types.h"
#include "../common/buffer.h"

/**
 * Parameter 2 for last APDU to receive.
 */
#define P2_LAST 0x00
/**
 * Parameter 2 for more APDU to receive.
 */
#define P2_MORE 0x80
/**
 * Parameter 1 for first APDU number.
 */
#define P1_START 0x00
/**
 * Parameter 1 for maximum APDU number.
 */
#define P1_MAX 0x03

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
