/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2021 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "os.h"
#include "ux.h"
#ifdef HAVE_NBGL
#include "nbgl_touch.h"
#include "nbgl_use_case.h"
#endif  // HAVE_NBGL

#include "io.h"
#include "globals.h"
#include "sw.h"
#include "common/buffer.h"
#include "common/write.h"

#include "dispatcher.h"
#include "../swap/swap_globals.h"

uint16_t G_output_len = 0;

// Counter incremented at every tick
// The initial value does not matter, as only the difference between timeframes is used.
uint16_t G_ticks;

struct {
    bool interruption : 1;
    bool processing : 1;
} G_is_timeout_active;

// set to true when the "Processing..." screen is shown, in order for the dispatcher to know if the
// UX is not in idle state at the end of a command handler.
bool G_was_processing_screen_shown;

uint16_t G_interruption_timeout_start_tick;
uint16_t G_processing_timeout_start_tick;

#ifdef HAVE_BAGL
UX_STEP_NOCB(ux_processing_flow_1_step, pn, {&C_icon_processing, "Processing..."});
UX_FLOW(ux_processing_flow, &ux_processing_flow_1_step);

void io_seproxyhal_display(const bagl_element_t *element) {
    io_seproxyhal_display_default((bagl_element_t *) element);
}
#endif  // HAVE_BAGL

void io_start_interruption_timeout() {
    G_interruption_timeout_start_tick = G_ticks;
    G_is_timeout_active.interruption = true;
}

void io_clear_interruption_timeout() {
    G_is_timeout_active.interruption = false;
}

void io_start_processing_timeout() {
    G_processing_timeout_start_tick = G_ticks;
    G_is_timeout_active.processing = true;
}

void io_clear_processing_timeout() {
    G_is_timeout_active.processing = false;
}

void io_reset_timeouts() {
    io_clear_interruption_timeout();
    io_clear_processing_timeout();
    G_was_processing_screen_shown = false;
}

uint8_t io_event(uint8_t channel) {
    (void) channel;

    switch (G_io_seproxyhal_spi_buffer[0]) {
        case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
#ifdef HAVE_BAGL
            UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
#endif  // HAVE_BAGL
            break;
        case SEPROXYHAL_TAG_STATUS_EVENT:
            if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&  //
                !(U4BE(G_io_seproxyhal_spi_buffer, 3) &      //
                  SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
                THROW(EXCEPTION_IO_RESET);
            }
            __attribute__((fallthrough));
        case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
#ifdef HAVE_BAGL
            UX_DISPLAYED_EVENT({});
#endif  // HAVE_BAGL
#ifdef HAVE_NBGL
            UX_DEFAULT_EVENT();
#endif  // HAVE_NBGL
            break;
#ifdef HAVE_NBGL
        case SEPROXYHAL_TAG_FINGER_EVENT:
            UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
            break;
#endif  // HAVE_NBGL
        case SEPROXYHAL_TAG_TICKER_EVENT:
            ++G_ticks;

            if (G_is_timeout_active.processing &&
                G_ticks - G_processing_timeout_start_tick >= PROCESSING_TIMEOUT_TICKS) {
                io_clear_processing_timeout();

                if (!G_was_processing_screen_shown) {
                    G_was_processing_screen_shown = true;
#ifdef HAVE_BAGL
                    ux_flow_init(0, ux_processing_flow, NULL);
#endif  // HAVE_BAGL
#ifdef HAVE_NBGL

                    if (!G_swap_state.called_from_swap) {
                        nbgl_useCaseSpinner("Processing");
                    }
#endif  // HAVE_NBGL
                }
            }

            if (G_is_timeout_active.interruption &&
                G_ticks - G_interruption_timeout_start_tick >= INTERRUPTION_TIMEOUT_TICKS) {
                io_clear_interruption_timeout();

                // TODO: It would be better to have the dispatcher be notified somehow.
                //       This would require some tampering with the io_exchange in
                //       process_interruption.
                THROW(EXCEPTION_IO_RESET);
            }

            UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {});
            break;
        default:
            UX_DEFAULT_EVENT();
            break;
    }

    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    return 1;
}

uint16_t io_exchange_al(uint8_t channel, uint16_t tx_len) {
    switch (channel & ~(IO_FLAGS)) {
        case CHANNEL_KEYBOARD:
            break;
        case CHANNEL_SPI:
            if (tx_len) {
                io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

                if (channel & IO_RESET_AFTER_REPLIED) {
                    halt();
                }

                return 0;
            } else {
                return io_seproxyhal_spi_recv(G_io_apdu_buffer, sizeof(G_io_apdu_buffer), 0);
            }
        default:
            THROW(INVALID_PARAMETER);
    }

    return 0;
}

void io_add_to_response(const void *rdata, size_t rdata_len) {
    if (G_output_len >= IO_APDU_BUFFER_SIZE - 2) {
        G_output_len = IO_APDU_BUFFER_SIZE;
        write_u16_be(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, SW_WRONG_RESPONSE_LENGTH);
    } else if (G_output_len + rdata_len > IO_APDU_BUFFER_SIZE - 2) {
        io_add_to_response(rdata, IO_APDU_BUFFER_SIZE - 2 - rdata_len);
        io_finalize_response(SW_WRONG_RESPONSE_LENGTH);
    } else {
        memmove(G_io_apdu_buffer + G_output_len, rdata, rdata_len);
        G_output_len += rdata_len;
    }
}

void io_finalize_response(uint16_t sw) {
    if (G_output_len >= IO_APDU_BUFFER_SIZE - 2) {
        G_output_len = IO_APDU_BUFFER_SIZE;
        write_u16_be(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, SW_WRONG_RESPONSE_LENGTH);
    } else {
        write_u16_be(G_io_apdu_buffer, G_output_len, sw);
        G_output_len += 2;
    }
}

void io_reset_response() {
    G_output_len = 0;
}

void io_set_response(const void *rdata, size_t rdata_len, uint16_t sw) {
    io_reset_response();
    if (rdata != NULL) {
        io_add_to_response(rdata, rdata_len);
    }
    io_finalize_response(sw);
}

int io_confirm_response() {
    int ret;

    ret = io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, G_output_len);
    G_output_len = 0;

    return ret;
}

int io_send_response(void *rdata, size_t rdata_len, uint16_t sw) {
    io_set_response(rdata, rdata_len, sw);
    return io_confirm_response();
}

int io_send_sw(uint16_t sw) {
    return io_send_response(NULL, 0, sw);
}
