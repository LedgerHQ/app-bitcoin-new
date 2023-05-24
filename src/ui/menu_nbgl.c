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

#ifdef HAVE_NBGL
#include "nbgl_use_case.h"

#include "../globals.h"
#include "menu.h"

static const char* const infoTypes[] = {"Version", "Developer", "Copyright"};
static const char* const infoContents[] = {APPVERSION, "Ledger", "(c) 2023 Ledger"};

static bool navigation_cb(uint8_t page, nbgl_pageContent_t* content) {
    UNUSED(page);
    content->type = INFOS_LIST;
    content->infosList.nbInfos = 3;
    content->infosList.infoTypes = (const char**) infoTypes;
    content->infosList.infoContents = (const char**) infoContents;
    return true;
}

static void exit(void) {
    os_sched_exit(-1);
}

void ui_menu_main_flow_bitcoin(void) {
    nbgl_useCaseHome("Bitcoin", &C_Bitcoin_64px, NULL, false, ui_menu_about, exit);
}

void ui_menu_main_flow_bitcoin_testnet(void) {
    nbgl_useCaseHome("Bitcoin Test",
                     &C_Bitcoin_64px,
                     "This app enables signing\ntransactions on all the Bitcoin\ntest networks.",
                     false,
                     ui_menu_about,
                     exit);
}

void ui_menu_about(void) {
    nbgl_useCaseSettings("Bitcoin", 0, 1, false, ui_menu_main, navigation_cb, NULL);
}

void ui_menu_about_testnet(void) {
    nbgl_useCaseSettings("Bitcoin Test", 0, 1, false, ui_menu_main, navigation_cb, NULL);
}
#endif  // HAVE_NBGL
