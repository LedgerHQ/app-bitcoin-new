#pragma once

#include "../../boilerplate/dispatcher.h"


/**
 * In this flow, the HWW sends a CCMD_GET_PREIMAGE command with a RIPEMD160 hash.
 * The client must respond with a the preimage, prefixed by its length as a varint.
 *
 * Returns a negative number on error, or the preimage length on success.
 * The preimage does not include the 0x00 prefix.
 */
int call_stream_preimage(dispatcher_context_t *dispatcher_context,
                         const uint8_t hash[static 20],
                         void (*callback)(buffer_t *, void *),
                         void *callback_state);
