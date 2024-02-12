
/*******************************************************************************
 *   Ledger Nano S - Secure firmware
 *   (c) 2022 Ledger
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
 ********************************************************************************/

// Inspired from ledger-secure-sdk/lib_ux/src/ux_layout_paging.c

#ifdef HAVE_BAGL

#include "os_helpers.h"
#include "os_math.h"
#include "os_pic.h"
#include "os_print.h"
#include "os_utils.h"
#include "ux.h"
#include <string.h>
#include "os.h"
#include "ux_layout_common.h"
#include "display.h"

const bagl_element_t *ux_layout_paging_prepro_common_streaming(const bagl_element_t *element,
                                                               const char *title,
                                                               const char *text) {
    // copy element before any mod
    memmove(&G_ux.tmp_element, element, sizeof(bagl_element_t));

    switch (element->component.userid) {
        case 0x01:
            // no step before AND no pages before
            if (ux_flow_is_first() && G_ux.layout_paging.current == 0) {
                return NULL;
            }
            break;

        case 0x02:
            if (ux_flow_is_last() && G_ux.layout_paging.current == G_ux.layout_paging.count - 1) {
                return NULL;
            }
            break;

        case 0x10:
            // We set the boldness of the text.
            // display
            if (title) {
                SPRINTF(G_ux.string_buffer, "%s", STRPIC(title));
            } else {
                SPRINTF(G_ux.string_buffer,
                        "%d/%d",
                        G_ux.layout_paging.current + 1,
                        G_ux.layout_paging.count);
            }

            G_ux.tmp_element.component.font_id =
                ((G_ux.layout_paging.format & PAGING_FORMAT_BN) == PAGING_FORMAT_BN)
                    ? (BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER)
                    : (BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER);
            G_ux.tmp_element.text = G_ux.string_buffer;
            break;

        case 0x11:
        case 0x12:
        case 0x13: {
            unsigned int lineidx = (element->component.userid & 0xF) - 1;
            if (lineidx < UX_LAYOUT_PAGING_LINE_COUNT && G_ux.layout_paging.lengths[lineidx]) {
                SPRINTF(G_ux.string_buffer,
                        "%.*s",
                        // avoid overflow
                        MIN(sizeof(G_ux.string_buffer) - 1, G_ux.layout_paging.lengths[lineidx]),
                        (text ? STRPIC(text) : G_ux.externalText) +
                            G_ux.layout_paging.offsets[lineidx]);
                G_ux.tmp_element.text = G_ux.string_buffer;

                G_ux.tmp_element.component.font_id =
                    ((G_ux.layout_paging.format & PAGING_FORMAT_NB) == PAGING_FORMAT_NB)
                        ? (BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER)
                        : (BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER);
            }
            break;
        }
    }
    return &G_ux.tmp_element;
}

static void ux_layout_paging_next(ux_layout_paging_redisplay_t redisplay) {
    if (G_ux.layout_paging.current == G_ux.layout_paging.count - 1) {
        ux_flow_next();
    } else {
        // display next page, count the number of char to fit in the next page
        G_ux.layout_paging.current++;
        redisplay(G_ux.stack_count - 1);
    }
}

static void ux_layout_paging_prev(ux_layout_paging_redisplay_t redisplay) {
    if (G_ux.layout_paging.current == 0) {
        ux_flow_prev();
    } else {
        // display previous page, count the number of char to fit in the previous page
        G_ux.layout_paging.current--;
        redisplay(G_ux.stack_count - 1);
    }
}

STATIC_IF_NOT_INDEXED unsigned int ux_layout_paging_button_callback_common_streaming(
    unsigned int button_mask,
    unsigned int button_mask_counter,
    ux_layout_paging_redisplay_t redisplay) {
    UNUSED(button_mask_counter);
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT:
            if (G_ux.layout_paging.current == 0) {
                decrease_streaming_index();
                ux_flow_validate();
            } else {
                ux_layout_paging_prev(redisplay);
            }
            break;
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
            if (G_ux.layout_paging.count == 0 ||
                G_ux.layout_paging.count - 1 == G_ux.layout_paging.current) {
                increase_streaming_index();
                ux_flow_validate();
            } else {
                ux_layout_paging_next(redisplay);
            }
            break;
        case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT:
            increase_streaming_index();
            ux_flow_validate();
            break;
    }
    return 0;
}

static const bagl_element_t *ux_layout_paging_prepro_by_addr(const bagl_element_t *element) {
    // don't display if null
    const void *params = ux_stack_get_current_step_params();
    if (NULL == params) {
        return NULL;
    }
    const char *title;
    const char *text;

#if defined(HAVE_INDEXED_STRINGS)
    UX_LOC_STRINGS_INDEX index = ((const ux_loc_layout_params_t *) params)->index;
    title = get_ux_loc_string(index);
    text = get_ux_loc_string(index + 1);
#else   // defined(HAVE_INDEXED_STRINGS)
    title = ((const ux_layout_paging_params_t *) params)->title;
    text = ((const ux_layout_paging_params_t *) params)->text;
#endif  // defined(HAVE_INDEXED_STRINGS)
    return ux_layout_paging_prepro_common_streaming(element, title, text);
}

void ux_layout_paging_init_common_streaming(unsigned int stack_slot,
                                            const char *text,
                                            ux_layout_paging_redisplay_t redisplay) {
    bagl_font_id_e font_id;

    // At this very moment, we don't want to get rid of the format, but keep
    // the one which has just been set (in case of direction backward or forward).
    unsigned int backup_format = G_ux.layout_paging.format;

    // depending flow browsing direction, select the correct page to display
    switch (ux_flow_direction()) {
        case FLOW_DIRECTION_BACKWARD:
            ux_layout_paging_reset();
            // ask the paging to start at the last page.
            // This step must be performed after the 'ux_layout_paging_reset' call,
            // thus we cannot mutualize the call with the one in the 'forward' case.
            G_ux.layout_paging.current = -1UL;
            break;
        case FLOW_DIRECTION_FORWARD:
            // open the first page
            ux_layout_paging_reset();
            break;
        case FLOW_DIRECTION_START:
            // shall already be at the first page
            break;
    }

    G_ux.layout_paging.format = backup_format;

    // store params
    ux_stack_init(stack_slot);

    // compute number of chars to display from the params complete string
    if ((text == NULL) && (G_ux.externalText == NULL)) {
        text = "";  // empty string to avoid disrupting the ux flow.
    }

    // Use the correct font, to be able to compute correctly text width:
    if (G_ux.layout_paging.format & PAGING_FORMAT_NB) {
        font_id = BAGL_FONT_OPEN_SANS_EXTRABOLD_11px;
    } else {
        font_id = BAGL_FONT_OPEN_SANS_REGULAR_11px;
    }

    // count total number of pages
    G_ux.layout_paging.count =
        ux_layout_paging_compute(text, -1UL, &G_ux.layout_paging, font_id);  // at least one page

    // perform displaying the last page as requested (-1UL in prevstep hook does this)
    if (G_ux.layout_paging.count && G_ux.layout_paging.current > G_ux.layout_paging.count - 1UL) {
        G_ux.layout_paging.current = G_ux.layout_paging.count - 1;
    }

    redisplay(stack_slot);
}

void ux_layout_paging_redisplay_by_addr_streaming(unsigned int stack_slot);
STATIC_IF_NOT_INDEXED unsigned int ux_layout_paging_button_callback_by_addr_streaming(
    unsigned int button_mask,
    unsigned int button_mask_counter) {
    return ux_layout_paging_button_callback_common_streaming(
        button_mask,
        button_mask_counter,
        ux_layout_paging_redisplay_by_addr_streaming);
}

void ux_layout_paging_redisplay_common(unsigned int stack_slot,
                                       const char *text,
                                       button_push_callback_t button_callback,
                                       bagl_element_callback_t prepro);

void ux_layout_paging_redisplay_by_addr_streaming(unsigned int stack_slot) {
    const char *text;
    const void *params = ux_stack_get_current_step_params();
    if (NULL == params) {
        return;
    }
#if defined(HAVE_INDEXED_STRINGS)
    text = get_ux_loc_string(((const ux_loc_layout_params_t *) params)->index + 1);
#else   // defined(HAVE_INDEXED_STRINGS)
    text = ((const ux_layout_paging_params_t *) params)->text;
#endif  // defined(HAVE_INDEXED_STRINGS)
    ux_layout_paging_redisplay_common(stack_slot,
                                      text,
                                      ux_layout_paging_button_callback_by_addr_streaming,
                                      ux_layout_paging_prepro_by_addr);
}

void ux_layout_custom_init(unsigned int stack_slot) {
    G_ux.layout_paging.format = PAGING_FORMAT_BN;
    const ux_layout_paging_params_t *params =
        (const ux_layout_paging_params_t *) ux_stack_get_step_params(stack_slot);
    ux_layout_paging_init_common_streaming(stack_slot,
                                           params->text,
                                           ux_layout_paging_redisplay_by_addr_streaming);
}

#endif  // HAVE_BAGL
