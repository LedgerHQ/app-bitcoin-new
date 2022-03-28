#pragma once

#include "../boilerplate/dispatcher.h"

typedef struct {
    machine_context_t ctx;
} get_master_fingerprint_t;

void handler_get_master_fingerprint(dispatcher_context_t *dispatcher_context, uint8_t p2);
