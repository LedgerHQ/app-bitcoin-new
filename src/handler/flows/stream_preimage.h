#pragma once

#include "../../boilerplate/dispatcher.h"

/**
 * In this flow, the HWW sends a CCMD_GET_PREIMAGE command with a RIPEMD160 hash.
 * The client must respond with a the preimage (at most 252 bytes), prefixed by its length.
 * The flow fails with SW_WRONG_DATA_LENGTH if the response is too short.
 * The result will be true if the preimage is correct, false otherwise.
 */
void flow_stream_preimage(dispatcher_context_t *dispatcher_context);


/**
 * Convenience function to call the stream_preimage flow.
 * TODO: more precise docs
 */
int call_stream_preimage(dispatcher_context_t *dispatcher_context,
                         const uint8_t hash[static 20],
                         dispatcher_callback_descriptor_t callback);
