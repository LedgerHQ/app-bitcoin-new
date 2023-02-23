#pragma once

#include <stdint.h>

#include "ux.h"
#include "os_io_seproxyhal.h"

#include "common/buffer.h"

#ifdef HAVE_BAGL
void io_seproxyhal_display(const bagl_element_t *element);
#endif  // HAVE_BAGL

/**
 * IO callback called when an interrupt based channel has received
 * data to be processed.
 *
 * @return 1 if success, 0 otherwise.
 *
 */
uint8_t io_event(uint8_t channel);

uint16_t io_exchange_al(uint8_t channel, uint16_t tx_len);

#define INTERRUPTION_TIMEOUT_TICKS 50
#define PROCESSING_TIMEOUT_TICKS   10

/**
 * Instructs io_event to reset the app if INTERRUPTION_TIMEOUT_TICKS tick events are received before
 * io_clear_interruption_timeout is called. Used to cause an app reset if the client stop responding
 * while an APDU is being processed.
 */
void io_start_interruption_timeout();

/**
 * Removes the timeout started from io_start_interruption_timeout.
 */
void io_clear_interruption_timeout();

/**
 * Instructs io_event to show the "Processing..." screen if PROCESSING_TIMEOUT_TICKS tick events are
 * received before io_clear_interruption_timeout is called.
 */
void io_start_processing_timeout();

/**
 * Removes the timeout started from io_start_processing_timeout.
 */
void io_clear_processing_timeout();

/**
 * Clears both the interruption and processing timeouts, and sets G_was_processing_screen_shown to
 * false.
 */
void io_reset_timeouts();

/**
 * TODO: docs
 */
void io_reset_response();

/**
 * TODO: docs
 */
void io_add_to_response(const void *rdata, size_t rdata_len);

/**
 * TODO: docs
 */
void io_finalize_response(uint16_t sw);

/* TODO: docs */
void io_set_response(const void *rdata, size_t rdata_len, uint16_t sw);

/* TODO: docs */
int io_confirm_response(void);

/**
 * Send APDU response (response data + status word) by filling G_io_apdu_buffer.
 *
 * @param[in] rdata
 *   Pointer to the response.
 * @param[in] rdata_len
 *   Length of response.
 * @param[in] sw
 *   Status word of APDU response.
 *
 * @return zero or positive integer if success, -1 otherwise.
 *
 */
int io_send_response(void *rdata, size_t rdata_len, uint16_t sw);

/**
 * Send APDU response (only status word) by filling G_io_apdu_buffer.
 *
 * @param[in] sw
 *   Status word of APDU response.
 *
 * @return zero or positive integer if success, -1 otherwise.
 *
 */
int io_send_sw(uint16_t sw);
