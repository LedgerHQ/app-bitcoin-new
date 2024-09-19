/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2024 Ledger SAS.
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

#define SETTING_INFO_NB 3
static const char* const INFO_TYPES[SETTING_INFO_NB] = {"Version", "Developer", "Copyright"};
static const char* const INFO_CONTENTS[SETTING_INFO_NB] = {APPVERSION, "Blooo", "(c) 2024 Blooo"};

static const nbgl_contentInfoList_t infoList = {
    .nbInfos = SETTING_INFO_NB,
    .infoTypes = INFO_TYPES,
    .infoContents = INFO_CONTENTS,
};

static void exit(void) {
    os_sched_exit(-1);
}

void ui_menu_main_flow_bitcoin(void) {
    nbgl_useCaseHomeAndSettings(APPNAME,
                                &C_Bitcoin_64px,
                                NULL,
                                INIT_HOME_PAGE,
                                NULL,
                                &infoList,
                                NULL,
                                exit);
}

void ui_menu_main_flow_bitcoin_testnet(void) {
    nbgl_useCaseHomeAndSettings(
        "Bitcoin Testnet",
        &C_Bitcoin_64px,
        "This app enables signing\ntransactions on all the Bitcoin\ntest networks.",
        INIT_HOME_PAGE,
        NULL,
        &infoList,
        NULL,
        exit);
}

#endif  // HAVE_NBGL
