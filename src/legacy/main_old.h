#pragma once

#include "btchip_context.h"
#include "swap_lib_calls.h"

struct libargs_s {
    unsigned int id;
    unsigned int command;
    btchip_altcoin_config_t *coin_config;
    union {
        check_address_parameters_t *check_address;
        create_transaction_parameters_t *create_transaction;
        get_printable_amount_parameters_t *get_printable_amount;
    };
};

void ui_idle(void);

void library_main(struct libargs_s *args);

void app_dispatch(void);