#pragma once

#include <stdbool.h>  // bool
#include "../boilerplate/dispatcher.h"

#include "../common/wallet.h"
#include "./display.h"
#include "./display_utils.h"
#include "../constants.h"
#include "../globals.h"
#include "../boilerplate/io.h"
#include "../boilerplate/sw.h"
#include "../common/bip32.h"
#include "../common/format.h"
#include "../common/script.h"
#include "../constants.h"

#define MAX_TITLE_LENGTH 32   // TODO
#define MAX_TEXT_LENGTH  128  // TODO

// TODO: docs

typedef struct {
    char title[MAX_TITLE_LENGTH];
    char text[MAX_TEXT_LENGTH];
} ui_title_and_text_state_t;

// TODO: hard to keep track of what globals are used in the same flows
//       (especially since the same flow step can be shared in different flows)

typedef struct {
    ui_title_and_text_state_t title_and_text;

    const char *bip32_path_str;
    size_t bip32_path_str_len;
    const char *pubkey;
    size_t pubkey_len;
} ui_path_and_pubkey_state_t;

typedef struct {
    ui_title_and_text_state_t title_and_text;

    const char *bip32_path_str;
    size_t bip32_path_str_len;
    const char *hash_hex;
    size_t hash_hex_len;
} ui_path_and_hash_state_t;

// wallet-related flows might sometimes use a subset of the fields
typedef struct {
    ui_title_and_text_state_t title_and_text;

    const char *wallet_name;
    size_t wallet_name_len;
    const char *descriptor_template;
    size_t descriptor_template_len;
    const char *address;
    size_t address_len;
} ui_wallet_state_t;

typedef struct {
    ui_title_and_text_state_t title_and_text;

    const char *pubkey;
    size_t pubkey_len;
    const char *signer_index;
    size_t signer_index_len;
} ui_cosigner_pubkey_and_index_state_t;

typedef struct {
    ui_title_and_text_state_t title_and_text;

    const char *index;
    size_t index_len;
    const char *address_or_description;
    size_t address_or_description_len;
    const char *amount;
    size_t amount_len;
} ui_validate_output_state_t;

typedef struct {
    ui_title_and_text_state_t title_and_text;

    const char *fee;
    size_t fee_len;
} ui_validate_transaction_state_t;

/**
 * Union of all the states for each of the UI screens, in order to save memory.
 */
typedef union {
    ui_title_and_text_state_t title_and_text;  // TODO: meta

    ui_path_and_pubkey_state_t path_and_pubkey;
    ui_path_and_hash_state_t path_and_hash;
    ui_wallet_state_t wallet;
    ui_cosigner_pubkey_and_index_state_t cosigner_pubkey_and_index;
    ui_validate_output_state_t validate_output;
    ui_validate_transaction_state_t validate_transaction;
} ui_state_t;
extern ui_state_t g_ui_state;

/**
 * Callback to reuse action with approve/reject in step FLOW.
 */
typedef void (*action_validate_cb)(dispatcher_context_t *dispatcher_context, bool);

/**
 * Display the derivation path and pubkey, and asks the confirmation to export.
 *
 * TODO: docs
 */
bool ui_display_pubkey(dispatcher_context_t *context,
                       const char *bip32_path_str,
                       bool is_path_suspicious,
                       const char *pubkey);

// TODO: docs
bool ui_display_message_hash(dispatcher_context_t *context,
                             const char *bip32_path_str,
                             const char *message_hash);

bool ui_display_address(dispatcher_context_t *dispatcher_context,
                        const char *address,
                        bool is_path_suspicious,
                        const char *bip32_path_str);

bool ui_display_register_wallet(dispatcher_context_t *context,
                                const policy_map_wallet_header_t *wallet_header,
                                const char *policy_descriptor);

bool ui_display_policy_map_cosigner_pubkey(dispatcher_context_t *dispatcher_context,
                                           const char *pubkey,
                                           uint8_t cosigner_index,
                                           uint8_t n_keys,
                                           bool is_internal);

bool ui_display_wallet_address(dispatcher_context_t *context,
                               const char *wallet_name,
                               const char *address);

bool ui_display_unusual_path(dispatcher_context_t *context, const char *bip32_path_str);

bool ui_authorize_wallet_spend(dispatcher_context_t *context, const char *wallet_name);

bool ui_warn_external_inputs(dispatcher_context_t *context);

bool ui_warn_unverified_segwit_inputs(dispatcher_context_t *context);

bool ui_warn_nondefault_sighash(dispatcher_context_t *context);

bool ui_validate_output(dispatcher_context_t *context,
                        int index,
                        int total_count,
                        const char *address_or_description,
                        const char *coin_name,
                        uint64_t amount);

bool ui_validate_transaction(dispatcher_context_t *context, const char *coin_name, uint64_t fee);

void set_ux_flow_response(bool approved);

void ui_display_pubkey_flow(void);

void ui_display_pubkey_suspicious_flow(void);

void ui_sign_message_flow(void);

void ui_display_register_wallet_flow(void);

void ui_display_policy_map_cosigner_pubkey_flow(void);

void ui_display_receive_in_wallet_flow(void);

void ui_display_canonical_wallet_address_flow(void);

void ui_display_spend_from_wallet_flow(void);

void ui_display_warning_external_inputs_flow(void);

void ui_display_unverified_segwit_inputs_flows(void);

void ui_display_nondefault_sighash_flow(void);

void ui_display_output_address_amount_flow(int index);

void ui_display_output_address_amount_no_index_flow(int index);

void ui_accept_transaction_flow(void);

void ui_display_transaction_prompt(const int external_outputs_total_count);

bool ui_post_processing_confirm_wallet_registration(dispatcher_context_t *context, bool success);

bool ui_post_processing_confirm_wallet_spend(dispatcher_context_t *context, bool success);

bool ui_post_processing_confirm_transaction(dispatcher_context_t *context, bool success);

bool ui_post_processing_confirm_message(dispatcher_context_t *context, bool success);

#ifdef HAVE_NBGL
bool ui_transaction_prompt(dispatcher_context_t *context, const int external_outputs_total_count);
void ui_display_post_processing_confirm_message(bool success);
void ui_display_post_processing_confirm_wallet_registation(bool success);
void ui_display_post_processing_confirm_transaction(bool success);
void ui_display_post_processing_confirm_wallet_spend(bool success);
#endif
