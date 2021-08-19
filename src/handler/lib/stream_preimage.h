#pragma once

#include "../../boilerplate/dispatcher.h"

/**
 * Given the hash of a leaf of a Merkle tree, requests the corresponding pre-image to the host. The
 * data provided from the host is passed on to the given callback. The preimage send to the
 * callbacks does not include the 0x00 prefix. If len_callback is not NONE, it is called before the
 * other callback with the length of the preimage (not including the 0x00 prefix).
 *
 * Returns a negative number on error, or the preimage length on success. This function validates
 * that the SHA256 of the data provided by the host does indeed match the expected hash.
 */
int call_stream_preimage(dispatcher_context_t *dispatcher_context,
                         const uint8_t hash[static 32],
                         void (*len_callback)(size_t, void *),
                         void (*callback)(buffer_t *, void *),
                         void *callback_state);
