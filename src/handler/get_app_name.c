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

#include <stdint.h>  // uint*_t

#include "get_app_name.h"
#include "../constants.h"
#include "../globals.h"
#include "../io.h"
#include "../sw.h"
#include "../types.h"
#include "common/buffer.h"

int handler_get_app_name() {
    _Static_assert(APPNAME_LEN < MAX_APPNAME_LEN, "APPNAME must be at most 64 characters!");

    buffer_t rdata = {.ptr = (uint8_t *) PIC(APPNAME), .size = APPNAME_LEN, .offset = 0};

    return io_send_response(&rdata, SW_OK);
}
