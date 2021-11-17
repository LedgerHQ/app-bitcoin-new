#pragma once

#include <stdint.h>

#include "ux.h"

#include "boilerplate/io.h"
#include "commands.h"
#include "constants.h"
#include "context.h"

/**
 * Global buffer for interactions between SE and MCU.
 */
extern uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

/**
 * Global variable with the length of APDU response to send back.
 */
extern uint16_t G_output_len;

/**
 * Global structure to perform asynchronous UX aside IO operations.
 */
extern ux_state_t G_ux;

/**
 * Global structure with the parameters to exchange with the BOLOS UX application.
 */
extern bolos_ux_params_t G_ux_params;

/**
 * Cryptocurrency constants.
 */
extern global_context_t *G_coin_config;

/**
 * State of the current APDU interaction, if any.
 */
extern command_state_t G_command_state;
