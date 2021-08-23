#pragma once

#include <stdint.h>

#include "ux.h"
#include "os_io_seproxyhal.h"

#include "common/buffer.h"

void io_seproxyhal_display(const bagl_element_t *element);

/**
 * IO callback called when an interrupt based channel has received
 * data to be processed.
 *
 * @return 1 if success, 0 otherwise.
 *
 */
uint8_t io_event(uint8_t channel);

uint16_t io_exchange_al(uint8_t channel, uint16_t tx_len);

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
