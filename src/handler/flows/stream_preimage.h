#pragma once

#include "../../boilerplate/dispatcher.h"

typedef struct {
    machine_context_t ctx;

    // input
    const uint8_t *hash;
    dispatcher_callback_descriptor_t callback;

    // outputs
    size_t preimage_len;

    // internal state
    cx_ripemd160_t hash_context;
    size_t bytes_remaining;
} stream_preimage_state_t;


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
static inline void call_stream_preimage(dispatcher_context_t *dispatcher_context,
                                            stream_preimage_state_t *flow_state,
                                            command_processor_t ret_proc,
                                            const uint8_t hash[static 20],
                                            dispatcher_callback_descriptor_t callback)
{
    flow_state->hash = hash;
    flow_state->callback = callback;

    dispatcher_context->start_flow(
        flow_stream_preimage,
        (machine_context_t *)flow_state,
        ret_proc
    );
}
