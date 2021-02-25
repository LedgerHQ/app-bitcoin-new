#pragma once

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t

#include "types.h"

/**
 * Serialize transaction in byte buffer.
 *
 * @param[in]  tx
 *   Pointer to input transaction structure.
 * @param[out] out
 *   Pointer to output byte buffer.
 * @param[in]  out_len
 *   Length of output byte buffer.
 *
 * @return number of bytes written if success, -1 otherwise.
 *
 */
int transaction_serialize(const transaction_t *tx, uint8_t *out, size_t out_len);
