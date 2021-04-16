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


typedef struct machine_context_s {
    struct machine_context_s *parent_context;
    command_processor_t next_processor;
} machine_context_t;


/**
 * TODO: docs
 */
struct dispatcher_context_s {
    machine_context_t *machine_context_ptr;
    buffer_t read_buffer;

    void (*pause)();
    void (*run)();
    void (*next)(command_processor_t next_processor);
    void (*send_response)(void *rdata, size_t rdata_len, uint16_t sw);
    void (*send_sw)(uint16_t sw);
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
 * TODO: update docs with new params
 *
 * @return zero or positive integer if success, negative integer otherwise.
 *
 */
int apdu_dispatcher(command_descriptor_t const cmd_descriptors[],
                    int n_descriptors,
                    machine_context_t *top_context,
                    size_t top_context_size,
                    void (*termination_cb)(void),
                    const command_t *cmd) ;
