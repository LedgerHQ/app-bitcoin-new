#pragma once

#include "../../boilerplate/dispatcher.h"


/**
 * In this flow, the HWW sends a CCMD_GET_PREIMAGE command with a RIPEMD160 hash.
 * The client must respond with a the preimage, prefixed by its length as a varint.
 *
 * Returns a negative number on error, or the preimage length on success.
 */
int call_stream_preimage(dispatcher_context_t *dispatcher_context,
                         const uint8_t hash[static 20],
                         dispatcher_callback_descriptor_t callback);
