#pragma once

#include "os.h"
#include "cx.h"

#include "../../boilerplate/dispatcher.h"

typedef struct {
    machine_context_t ctx;

    // input
    uint8_t hash[20];
    uint8_t *out_ptr;
    size_t out_ptr_len;

    // outputs
    size_t preimage_len;
    bool result; // true if the hash is correct, false otherwise
} get_merkle_preimage_state_t;


/**
 * In this flow, the HWW sends a CCMD_GET_PREIMAGE command with a RIPEMD160 hash.
 * The client must respond with a the preimage (at most 254 bytes), prefixed by its length.
 * The flow fails with SW_WRONG_DATA_LENGTH if the response is too short.
 * The result will be true if the preimage is correct, false otherwise.
 */
void flow_get_merkle_preimage(dispatcher_context_t *dispatcher_context);


/**
 * Convenience function to call the get_merkle_preimage flow.
 * TODO: more precise docs
 */
static inline void call_get_merkle_preimage(dispatcher_context_t *dispatcher_context,
                                            get_merkle_preimage_state_t *flow_state,
                                            command_processor_t ret_proc,
                                            const uint8_t hash[static 20],
                                            uint8_t *out_ptr,
                                            size_t out_ptr_len)
{
    memcpy(flow_state->hash, hash, 20);
    flow_state->out_ptr = out_ptr;
    flow_state->out_ptr_len = out_ptr_len;

    dispatcher_context->start_flow(
        flow_get_merkle_preimage,
        (machine_context_t *)flow_state,
        ret_proc
    );
}
