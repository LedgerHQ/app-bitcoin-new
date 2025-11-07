#pragma once

#include <stdint.h>

#include "../constants.h"

// up to 5 chars for ticker, 1 space, up to 20 digits (20 = digits of 2^64), + 1 decimal separator
#define MAX_AMOUNT_LENGTH (5 + 1 + 20 + 1)

/**
 * Converts a 64-bits unsigned integer into a decimal rapresentation, where the `amount` is a
 * multiple of 1/100_000_000th. Trailing decimal zeros are not appended (and no decimal point is
 * present if the `amount` is a multiple of 100_000_000). The resulting string is prefixed with a
 * ticker name (up to 5 characters long), followed by a space.
 *
 * @param coin_name a zero-terminated ticker name, at most 5 characterso long (not including the
 * terminating 0)
 * @param amount the amount to format
 * @param out the output array which must be at least MAX_AMOUNT_LENGTH + 1 bytes long
 */
void format_sats_amount(const char *coin_name,
                        uint64_t amount,
                        char out[static MAX_AMOUNT_LENGTH + 1]);

/**
 * Formats output index string ("101 of 203").
 *
 * @param output_index current output index
 * @param n_outputs total number of outputs
 * @param out the output array which must fit to MAX_OUTPUT_INDEX_LENGTH + 1 bytes length
 */
void format_output_index(const unsigned int output_index,
                         const unsigned int n_outputs,
                         char out[static MAX_OUTPUT_INDEX_LENGTH + 1]);
