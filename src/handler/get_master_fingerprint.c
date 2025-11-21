/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2025 Ledger SAS.
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

#include "os_seed.h"

#include "boilerplate/dispatcher.h"
#include "boilerplate/sw.h"
#include "../commands.h"
#include "../crypto.h"

#include "handlers.h"

void handler_get_master_fingerprint(dispatcher_context_t *dc, uint8_t protocol_version) {
    (void) protocol_version;

    uint8_t master_key_identifier[CX_RIPEMD160_SIZE] = {0};

    if (os_perso_get_master_key_identifier(master_key_identifier, CX_RIPEMD160_SIZE) != CX_OK) {
        SEND_SW(dc, SW_BAD_STATE);  // should never happen
        return;
    }

    SEND_RESPONSE(dc, master_key_identifier, 4, SW_OK);
}
