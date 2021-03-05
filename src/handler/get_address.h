#pragma once

#include "../commands.h"

int handler_get_address(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context,
    void *state
);
