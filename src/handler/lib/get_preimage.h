#pragma once

#include "../../boilerplate/dispatcher.h"

/**
 * Given a sha256 hash, requests the corresponding pre-image to the host.
 *
 * Returns a negative number on error, or the preimage length on success. This function validates
 * that the SHA256 of the data provided by the host does indeed match the expected hash.
 */
int call_get_preimage(dispatcher_context_t *dispatcher_context,
                      const uint8_t hash[static 32],
                      uint8_t *out,
                      size_t out_len);
