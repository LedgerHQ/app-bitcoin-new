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

#define MESSAGE_CHUNK_SIZE        64  // Protocol specific
#define MESSAGE_CHUNK_PER_DISPLAY 2   // This could be changed depending on screen sizes
#define MESSAGE_MAX_DISPLAY_SIZE \
    (MESSAGE_CHUNK_SIZE * MESSAGE_CHUNK_PER_DISPLAY + 2 * sizeof("...") - 1)

typedef struct tx_ux_warning_s {
    bool missing_nonwitnessutxo : 1;
    bool non_default_sighash : 1;
    bool external_inputs : 1;
    bool high_fee : 1;
} tx_ux_warning_t;

typedef enum {
    PUBKEY_TYPE_INTERNAL = 0,    // a key controlled by the wallet policy
    PUBKEY_TYPE_EXTERNAL = 1,    // a key not controlled by the wallet policy
    PUBKEY_TYPE_UNSPENDABLE = 2  // the provably unspendable public key defined in BIP-341
} key_type_e;

// TODO: hard to keep track of what globals are used in the same flows
//       (especially since the same flow step can be shared in different flows)

typedef struct {
    char bip32_path_str[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1];
} ui_path_state_t;

typedef struct {
    char bip32_path_str[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1];
    char pubkey[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
} ui_path_and_pubkey_state_t;

typedef struct {
    char bip32_path_str[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1];
    char address[MAX_ADDRESS_LENGTH_STR + 1];
} ui_path_and_address_state_t;

typedef struct {
    char bip32_path_str[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1];
    char message[MESSAGE_MAX_DISPLAY_SIZE];
} ui_path_and_message_state_t;

typedef struct {
    char wallet_name[MAX_WALLET_NAME_LENGTH + 1];

    // no flows show together both a policy map and an address, therefore we share memory
    union {
        char descriptor_template[MAX_DESCRIPTOR_TEMPLATE_LENGTH + 1];
        char address[MAX_ADDRESS_LENGTH_STR + 1];
    };
} ui_wallet_state_t;

// maximum length of the description of a cosigner in a wallet policy
#define MAX_KEY_LABEL_LENGTH sizeof("Key @999, unspendable")

typedef struct {
    const char *wallet_name;
    const char *descriptor_template;
    size_t n_keys;
    char keys_label[MAX_N_KEYS_IN_WALLET_POLICY][MAX_KEY_LABEL_LENGTH];
    const char *keys_info[MAX_N_KEYS_IN_WALLET_POLICY];
} ui_register_wallet_policy_state_t;

typedef struct {
    char pubkey[MAX_POLICY_KEY_INFO_LEN + 1];
    char signer_index[sizeof("Key @999 <theirs>")];
} ui_cosigner_pubkey_and_index_state_t;

typedef struct {
    char index[sizeof("output #999")];
    char address_or_description[MAX(MAX_ADDRESS_LENGTH_STR + 1, MAX_OPRETURN_OUTPUT_DESC_SIZE)];
    char amount[MAX_AMOUNT_LENGTH + 1];
} ui_validate_output_state_t;

typedef struct {
    char fee[MAX_AMOUNT_LENGTH + 1];
} ui_validate_transaction_state_t;

typedef struct {
    bool has_wallet_policy;
    bool is_self_transfer;
    char wallet_policy_name[MAX_WALLET_NAME_LENGTH + 1];
    char address_or_description[MAX(MAX_ADDRESS_LENGTH_STR + 1, MAX_OPRETURN_OUTPUT_DESC_SIZE)];
    char amount[MAX_AMOUNT_LENGTH + 1];
    char fee[MAX_AMOUNT_LENGTH + 1];
    tx_ux_warning_t warnings;
} ui_validate_transaction_simplified_state_t;

typedef struct {
    char spender[MAX_ADDRESS_LENGTH_STR + 1];
    char value[MAX_AMOUNT_LENGTH + 1];
    char redeemer[MAX_ADDRESS_LENGTH_STR + 1];
    char bip32_path_str[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1];
    char message[MESSAGE_MAX_DISPLAY_SIZE];
} ui_validate_withdraw_state_t;

/**
 * Union of all the states for each of the UI screens, in order to save memory.
 */
typedef union {
    ui_path_and_pubkey_state_t path_and_pubkey;
    ui_path_and_address_state_t path_and_address;
    ui_path_and_message_state_t path_and_message;
    ui_wallet_state_t wallet;
    ui_cosigner_pubkey_and_index_state_t cosigner_pubkey_and_index;
    ui_validate_output_state_t validate_output;
    ui_validate_transaction_state_t validate_transaction;
    ui_validate_withdraw_state_t validate_withdraw;
#ifdef HAVE_NBGL
    ui_register_wallet_policy_state_t register_wallet_policy;
    ui_validate_transaction_simplified_state_t validate_transaction_simplified;
#endif
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

bool ui_display_path_and_message_content(dispatcher_context_t *context,
                                         const char *path_str,
                                         const char *message_content);

bool ui_display_message_path_hash_and_confirm(dispatcher_context_t *context,
                                              const char *path_str,
                                              const char *message_hash);

bool ui_display_message_confirm(dispatcher_context_t *context);

bool ui_display_address(dispatcher_context_t *dispatcher_context,
                        const char *address,
                        bool is_path_suspicious,
                        const char *bip32_path_str);

#ifdef HAVE_BAGL
bool ui_display_register_wallet(dispatcher_context_t *context,
                                const policy_map_wallet_header_t *wallet_header,
                                const char *policy_descriptor);

bool ui_display_policy_map_cosigner_pubkey(dispatcher_context_t *dispatcher_context,
                                           const char *pubkey,
                                           uint8_t cosigner_index,
                                           uint8_t n_keys,
                                           key_type_e key_type);
#endif

#ifdef HAVE_NBGL
bool ui_display_register_wallet_policy(
    dispatcher_context_t *context,
    const policy_map_wallet_header_t *wallet_header,
    const char *descriptor_template,
    const char (*keys_info)[MAX_N_KEYS_IN_WALLET_POLICY][MAX_POLICY_KEY_INFO_LEN + 1],
    const key_type_e (*keys_type)[MAX_N_KEYS_IN_WALLET_POLICY]);
#endif

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

bool ui_warn_high_fee(dispatcher_context_t *context);

bool ui_validate_transaction(dispatcher_context_t *context,
                             const char *coin_name,
                             uint64_t fee,
                             bool is_self_transfer);

#ifdef HAVE_NBGL
bool ui_validate_transaction_simplified(dispatcher_context_t *context,
                                        const char *coin_name,
                                        const char *wallet_policy_name,  // can be NULL
                                        uint64_t amount,
                                        const char *address_or_description,
                                        tx_ux_warning_t warnings,
                                        uint64_t fee);
#endif

void set_ux_flow_response(bool approved);

void ui_display_pubkey_flow(void);

void ui_display_pubkey_suspicious_flow(void);

void ui_sign_message_path_hash_and_confirm_flow(void);

void ui_sign_message_content_flow(void);

void ui_sign_message_confirm_flow(void);

#ifdef HAVE_BAGL
void ui_display_register_wallet_flow(void);

void ui_display_policy_map_cosigner_pubkey_flow(void);
#endif

void ui_display_receive_in_wallet_flow(void);

void ui_display_default_wallet_address_flow(void);

void ui_display_spend_from_wallet_flow(void);

void ui_display_warning_external_inputs_flow(void);

void ui_display_unverified_segwit_inputs_flows(void);

void ui_display_nondefault_sighash_flow(void);

void ui_display_output_address_amount_flow(int index);

void ui_display_output_address_amount_no_index_flow(int index);

void ui_warn_high_fee_flow(void);

void ui_accept_transaction_flow(bool is_self_transfer);

#ifdef HAVE_NBGL
void ui_display_register_wallet_policy_flow(void);
void ui_accept_transaction_simplified_flow(void);
#endif

void ui_display_transaction_prompt(void);

bool ui_post_processing_confirm_wallet_spend(dispatcher_context_t *context, bool success);

bool ui_post_processing_confirm_transaction(dispatcher_context_t *context, bool success);

bool ui_post_processing_confirm_message(dispatcher_context_t *context, bool success);

bool ui_post_processing_confirm_withdraw(dispatcher_context_t *context, bool success);

void ui_pre_processing_message(void);

void ui_display_withdraw_content_flow(void);
bool ui_validate_withdraw_data_and_confirm(dispatcher_context_t *context,
                                           const char *spender,
                                           const char *value,
                                           const char *redeemer);

#ifdef HAVE_NBGL
bool ui_transaction_prompt(dispatcher_context_t *context);
void ui_display_post_processing_confirm_message(bool success);
void ui_display_post_processing_confirm_transaction(bool success);
void ui_set_display_prompt(void);
#else
#define ux_layout_custom_params_t ux_layout_paging_params_t
void ux_layout_custom_init(unsigned int stack_slot);
#endif

uint8_t get_streaming_index(void);
void reset_streaming_index(void);
void increase_streaming_index(void);
void decrease_streaming_index(void);
