#pragma once

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "../types.h"

/**
 * Parse APDU command from byte buffer.
 *
 * @param[out] cmd
 *   Structured APDU command (CLA, INS, P1, P2, Lc, Command data).
 * @param[in]  buf
 *   Byte buffer with raw APDU command.
 * @param[in]  buf_len
 *   Length of byte buffer.
 *
 * @return true if success, false otherwise.
 *
 */
bool apdu_parser(command_t *cmd, uint8_t *buf, size_t buf_len);
