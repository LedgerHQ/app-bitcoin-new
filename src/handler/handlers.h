#pragma once

#include "../boilerplate/dispatcher.h"

void handler_get_extended_pubkey(dispatcher_context_t *dispatcher_context, uint8_t p2);
void handler_get_master_fingerprint(dispatcher_context_t *dispatcher_context, uint8_t p2);
void handler_get_wallet_address(dispatcher_context_t *dispatcher_context, uint8_t p2);
void handler_register_wallet(dispatcher_context_t *dispatcher_context, uint8_t p2);
void handler_sign_message(dispatcher_context_t *dispatcher_context, uint8_t p2);
void handler_sign_psbt(dispatcher_context_t *dispatcher_context, uint8_t p2);
