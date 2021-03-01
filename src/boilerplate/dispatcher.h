#pragma once

#include "types.h"
#include "common/buffer.h"

/**
 * TODO: docs
 */
typedef struct {
    buffer_t read_buffer;
    bool is_continuation;
    bool interrupt;
} dispatcher_context_t;


// TODO: continue brainstorming on a nice interface.
// A command descriptor should contain:
//   - a command handler, that can access all the input and the global state
//   - a command processor, that encodes the state machine (only for interruptible commands)
// For simple 1-round commands, the global state should not be used (or used only as temporary storage);
// there is no command processor.
// For interruptible commands, the command handler initialize the global state; it can return a status word and
// response, and no processor will be called in that case. Otherwise, the command processor is called, which
// implements the state machines, and must respect specific constraints in the way it's written.
// TODO: document this.

// Args: p1, p2, Lc, pointer to read_buffer, pointer to global state
typedef int (*command_handler_t)(uint8_t, uint8_t, uint8_t, dispatcher_context_t *, void *);
// Args: pointer to global state
typedef int (*command_processor_t)(dispatcher_context_t *, void *);

/**
 * Describes a command that can be processed by the dispatcher.
 */
typedef struct {
    command_handler_t handler;
    command_processor_t processor; // it can be NULL
    uint8_t cla;
    uint8_t ins;
} command_descriptor_t;

/**
 * Dispatch APDU command received to the right handler.
 * @param[in] command_descriptors
 *   Array of command descriptors.
 * @param[in] n_descriptors
 *   Length of the command_descriptors array.
 * @param[in] cmd
 *   Structured APDU command (CLA, INS, P1, P2, Lc, Command data).
 *
 * @return zero or positive integer if success, negative integer otherwise.
 *
 */
int apdu_dispatcher(command_descriptor_t const command_descriptors[], int n_descriptors, const command_t *cmd);
