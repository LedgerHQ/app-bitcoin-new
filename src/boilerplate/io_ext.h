#pragma once

#include <stdint.h>

/* SDK headers */
#include "buffer.h"
#include "ux.h"

/* Local headers */
#include "os_io_seproxyhal.h"

/**
 * Global variable with the length of APDU response to send back.
 */
extern uint16_t G_output_len;

/**
 * IO callback called when an interrupt based channel has received
 * data to be processed.
 *
 * @return 1 if success, 0 otherwise.
 *
 */
uint8_t ioe_event(uint8_t channel);

uint16_t ioe_exchange_al(uint8_t channel, uint16_t tx_len);

#define INTERRUPTION_TIMEOUT_TICKS 50
#define PROCESSING_TIMEOUT_TICKS   10

/**
 * Instructs io_event to reset the app if INTERRUPTION_TIMEOUT_TICKS tick events are received before
 * ioe_clear_interruption_timeout is called. Used to cause an app reset if the client stop
 * responding while an APDU is being processed.
 */
void ioe_start_interruption_timeout();

/**
 * Removes the timeout started from ioe_start_interruption_timeout.
 */
void ioe_clear_interruption_timeout();

/**
 * Instructs io_event to show the "Processing..." screen if PROCESSING_TIMEOUT_TICKS tick events are
 * received before ioe_clear_interruption_timeout is called.
 */
void ioe_start_processing_timeout();

/**
 * Removes the timeout started from io_start_processing_timeout.
 */
void ioe_clear_processing_timeout();

/**
 * Clears both the interruption and processing timeouts, and sets G_was_processing_screen_shown to
 * false.
 */
void ioe_reset_timeouts();

/**
 * Shows the "Processing..." screen.
 */
void ioe_show_processing_screen();

/**
 * Append data to the APDU response buffer (G_io_apdu_buffer).
 *
 * @param[in] rdata
 *   Pointer to the data to append.
 * @param[in] rdata_len
 *   Length of data to append.
 */
void ioe_add_to_response(const void *rdata, size_t rdata_len);

/**
 * Finalize the APDU response by appending the status word.
 * Must be called after all ioe_add_to_response() calls are done.
 *
 * @param[in] sw
 *   Status word of APDU response.
 */
void ioe_finalize_response(uint16_t sw);

/**
 * Send the previously prepared APDU response via io_exchange.
 * The response must have been built with ioe_add_to_response()/ioe_finalize_response()
 * before calling this function.
 *
 * @return zero or positive integer if success, -1 otherwise.
 */
int ioe_send_response(void);

/**
 * Send APDU response containing only a status word (no data).
 *
 * @param[in] sw
 *   Status word of APDU response.
 *
 * @return zero or positive integer if success, -1 otherwise.
 */
int ioe_send_sw(uint16_t sw);
