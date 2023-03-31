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

#include "boilerplate/dispatcher.h"
#include "boilerplate/sw.h"
#include "../commands.h"
#include "../crypto.h"

#include "handlers.h"

void handler_get_master_fingerprint(dispatcher_context_t *dc, uint8_t protocol_version) {
    (void) protocol_version;

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        SEND_SW(dc, SW_SECURITY_STATUS_NOT_SATISFIED);
        return;
    }

    uint8_t master_pubkey[33];
    if (!crypto_get_compressed_pubkey_at_path((uint32_t[]){}, 0, master_pubkey, NULL)) {
        SEND_SW(dc, SW_BAD_STATE);  // should never happen
        return;
    }

    uint8_t master_fingerprint_be[4];
    write_u32_be(master_fingerprint_be, 0, crypto_get_key_fingerprint(master_pubkey));

    SEND_RESPONSE(dc, master_fingerprint_be, sizeof(master_fingerprint_be), SW_OK);
}
