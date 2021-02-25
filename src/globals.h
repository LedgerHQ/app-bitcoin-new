#pragma once

#include <stdint.h>

#include "ux.h"

#include "io.h"
#include "types.h"
#include "constants.h"

/**
 * Global buffer for interactions between SE and MCU.
 */
extern uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

/**
 * Global variable with the lenght of APDU response to send back.
 */
extern uint32_t G_output_len;

/**
 * Global structure to perform asynchronous UX aside IO operations.
 */
extern ux_state_t G_ux;

/**
 * Global structure with the parameters to exchange with the BOLOS UX application.
 */
extern bolos_ux_params_t G_ux_params;

/**
 * Global enumeration with the state of IO (READY, RECEIVING, WAITING).
 */
extern io_state_e G_io_state;

/**
 * Global context for user requests.
 */
extern global_ctx_t G_context;

/**
 * State of the current APDU interaction, if any.
 */
extern command_state_t G_command_state;

/**
 * If non-zero, the code of the current interrupted APDU, whose state is saved in G_command_state.
 */
extern interrupted_command_t G_interrupted_command;

