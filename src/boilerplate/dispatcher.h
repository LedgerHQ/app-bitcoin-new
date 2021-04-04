#pragma once

#include "types.h"
#include "common/buffer.h"


// TODO: continue brainstorming on a nice interface.
// A command descriptor should contain:
//   - a command handler, that can access all the input and the global state
//   - a command processor, that encodes the state machine (only for interruptible commands)
// For simple 1-round commands, the global state should not be used (or used only as temporary storage);
// there is no command processor.
// For interruptible commands, the command handler initializes the global state; it can return a status word and
// response, and no processor will be called in that case. Otherwise, the command processor is called, which
// implements the state machines, and must respect specific constraints in the way it's written.
// TODO: document this.


// Forward declaration
struct dispatcher_context_s;
typedef struct dispatcher_context_s dispatcher_context_t;

// Args: p1, p2, Lc, pointer to dispatcher context
typedef void (*command_handler_t)(uint8_t, uint8_t, uint8_t, dispatcher_context_t *);
// Args: pointer to dispatcher context
typedef void (*command_processor_t)(dispatcher_context_t *);


/**
 * TODO: docs
 */
struct dispatcher_context_s {
    buffer_t read_buffer;
    bool is_running; // Set to true once a command is started, false once a response is sent back. 
    bool is_continuation; // Set to true before a command processor is called in case of continuation. false otherwise.
                          // A command handler might set it to false once the continuation is processed to signal the
                          // return to normal execution; the dispatcher ignores its value after calling a command
                          // handler or processor. 
    command_processor_t continuation; // will be set by a command handler or processor that interrupts the execution
};


/**
 * Describes a command that can be processed by the dispatcher.
 */
typedef struct {
    command_handler_t handler;
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
