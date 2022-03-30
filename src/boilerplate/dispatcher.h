#pragma once

#include "os.h"

#include "apdu_parser.h"

#include "common/buffer.h"

// TODO: continue brainstorming on a nice interface.
// A command descriptor should contain:
//   - a command handler, that can access all the input and the global state
//   - a command processor, that encodes the state machine (only for interruptible commands)
// For simple 1-round commands, the global state should not be used (or used only as temporary
// storage); there is no command processor. For interruptible commands, the command handler
// initializes the global state; it can return a status word and response, and no processor will be
// called in that case. Otherwise, the command processor is called, which implements the state
// machines, and must respect specific constraints in the way it's written.
// TODO: document this.

// Forward declaration
struct dispatcher_context_s;
typedef struct dispatcher_context_s dispatcher_context_t;

typedef void (*command_processor_t)(dispatcher_context_t *);

typedef void (*command_handler_t)(dispatcher_context_t *, uint8_t p2);

typedef struct machine_context_s {
    struct machine_context_s *parent_context;
    command_processor_t next_processor;
} machine_context_t;

typedef void (*dispatcher_callback_t)(machine_context_t *, buffer_t *);

typedef struct {
    void *state;
    dispatcher_callback_t fn;
} dispatcher_callback_descriptor_t;

static inline dispatcher_callback_descriptor_t make_callback(void *state,
                                                             dispatcher_callback_t fn) {
    return (dispatcher_callback_descriptor_t){.state = state, .fn = fn};
}

/**
 * TODO: docs
 */
struct dispatcher_context_s {
    machine_context_t *machine_context_ptr;
    buffer_t read_buffer;

    void (*pause)();
    void (*run)();
    void (*next)(command_processor_t next_processor);
    void (*add_to_response)(const void *rdata, size_t rdata_len);
    void (*finalize_response)(uint16_t sw);
    void (*send_response)(void);
    void (*start_flow)(command_processor_t first_processor,
                       machine_context_t *subcontext,
                       command_processor_t return_processor);
    int (*process_interruption)(dispatcher_context_t *dispatcher_context);
};

static inline void SEND_SW(struct dispatcher_context_s *dc, uint16_t sw) {
    dc->finalize_response(sw);
    dc->send_response();
}

static inline void SET_RESPONSE(struct dispatcher_context_s *dc,
                                void *rdata,
                                size_t rdata_len,
                                uint16_t sw) {
    dc->add_to_response(rdata, rdata_len);
    dc->finalize_response(sw);
}

static inline void SEND_RESPONSE(struct dispatcher_context_s *dc,
                                 void *rdata,
                                 size_t rdata_len,
                                 uint16_t sw) {
    dc->add_to_response(rdata, rdata_len);
    dc->finalize_response(sw);
    dc->send_response();
}

// TODO: instead of exposing a method like send_response, it might be more efficient to expose the
// response buffer,
//       so that one could use the buffer_write_* methods directly.
//       On the other hand, buth the read_buffer and the write buffer would point to the same shared
//       global space (part of G_io_apdu_buffer). Therefore, one would have to make sure that no
//       read happens after writes happen, and it would probably be better if the dispatcher
//       enforces this, by making it impossible to accidentally read the read_buffer after writes
//       happened. One way could be have a function get_output_buffer() in the dispatcher context,
//       that returns the output buffer but it first zeroes the read_buffer.

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
 */
void apdu_dispatcher(command_descriptor_t const cmd_descriptors[],
                     int n_descriptors,
                     machine_context_t *top_context,
                     size_t top_context_size,
                     void (*termination_cb)(void),
                     const command_t *cmd);

// Debug utilities

#if DEBUG == 0
#define LOG_PROCESSOR(dc, file, line, func)
#else
// Print current filename, line number and function name.
// Indents according to the nesting depth for subprocessors.
static inline void print_dispatcher_info(dispatcher_context_t *dc,
                                         const char *file,
                                         int line,
                                         const char *func) {
    machine_context_t *ctx = dc->machine_context_ptr;
    while (ctx->parent_context != NULL) {
        PRINTF("----");
        ctx = ctx->parent_context;
    }
    PRINTF("->%s %d: %s\n", file, line, func);
}

#define LOG_PROCESSOR(dc, file, line, func) print_dispatcher_info(dc, file, line, func)
#endif
