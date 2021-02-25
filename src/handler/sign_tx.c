/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
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

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "os.h"
#include "cx.h"

#include "sign_tx.h"
#include "../sw.h"
#include "../globals.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../common/buffer.h"
#include "../transaction/types.h"
#include "../transaction/deserialize.h"

int handler_sign_tx(buffer_t *cdata, uint8_t chunk, bool more) {
    if (chunk == 0) {  // first APDU, parse BIP32 path
        explicit_bzero(&G_context, sizeof(G_context));
        G_context.req_type = CONFIRM_TRANSACTION;
        G_context.state = STATE_NONE;

        if (!buffer_read_u8(cdata, &G_context.bip32_path_len) ||
            !buffer_read_bip32_path(cdata,
                                    G_context.bip32_path,
                                    (size_t) G_context.bip32_path_len)) {
            return io_send_sw(SW_WRONG_DATA_LENGTH);
        }

        return io_send_sw(SW_OK);
    } else {  // parse transaction
        if (G_context.req_type != CONFIRM_TRANSACTION) {
            return io_send_sw(SW_BAD_STATE);
        }

        if (more) {  // more APDUs with transaction part
            if (G_context.tx_info.raw_tx_len + cdata->size > MAX_TRANSACTION_LEN &&  //
                !buffer_move(cdata,
                             G_context.tx_info.raw_tx + G_context.tx_info.raw_tx_len,
                             cdata->size)) {
                return io_send_sw(SW_WRONG_TX_LENGTH);
            }

            G_context.tx_info.raw_tx_len += cdata->size;

            return io_send_sw(SW_OK);
        } else {  // last APDU, let's parse and sign
            if (G_context.tx_info.raw_tx_len + cdata->size > MAX_TRANSACTION_LEN ||  //
                !buffer_move(cdata,
                             G_context.tx_info.raw_tx + G_context.tx_info.raw_tx_len,
                             cdata->size)) {
                return io_send_sw(SW_WRONG_TX_LENGTH);
            }

            G_context.tx_info.raw_tx_len += cdata->size;

            buffer_t buf = {.ptr = G_context.tx_info.raw_tx,
                            .size = G_context.tx_info.raw_tx_len,
                            .offset = 0};

            parser_status_e status = transaction_deserialize(&buf, &G_context.tx_info.transaction);
            PRINTF("Parsing status: %d.\n", status);
            if (status != PARSING_OK) {
                return io_send_sw(SW_TX_PARSING_FAIL);
            }

            G_context.state = STATE_PARSED;

            cx_sha3_t keccak256;
            cx_keccak_init(&keccak256, 256);
            cx_hash((cx_hash_t *) &keccak256,
                    CX_LAST,
                    G_context.tx_info.raw_tx,
                    G_context.tx_info.raw_tx_len,
                    G_context.tx_info.m_hash,
                    sizeof(G_context.tx_info.m_hash));

            PRINTF("Hash: %.*H\n", sizeof(G_context.tx_info.m_hash), G_context.tx_info.m_hash);

            return ui_display_transaction();
        }
    }

    return 0;
}
