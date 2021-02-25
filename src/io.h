#pragma once

#include <stdint.h>

#include "ux.h"
#include "os_io_seproxyhal.h"

#include "types.h"
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
 * Receive APDU command in G_io_apdu_buffer and update G_output_len.
 *
 * @return zero or positive integer if success, -1 otherwise.
 *
 */
int io_recv_command(void);

/* TODO: docs */
int io_set_response(const buffer_t *rdata, uint16_t sw);

/* TODO: docs */
int io_confirm_response(void);

/**
 * Send APDU response (response data + status word) by filling
 * G_io_apdu_buffer.
 *
 * @param[in] rdata
 *   Buffer with APDU response data.
 * @param[in] sw
 *   Status word of APDU response.
 *
 * @return zero or positive integer if success, -1 otherwise.
 *
 */
int io_send_response(const buffer_t *rdata, uint16_t sw);

/**
 * Send APDU response (only status word) by filling
 * G_io_apdu_buffer.
 *
 * @param[in] sw
 *   Status word of APDU response.
 *
 * @return zero or positive integer if success, -1 otherwise.
 *
 */
int io_send_sw(uint16_t sw);
