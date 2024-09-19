#ifdef HAVE_NBGL

#include <stdint.h>

#include "nbgl_use_case.h"
#include "./display.h"
#include "./menu.h"
#include "io.h"

#include <assert.h>

#define REVIEW_CONFIRM FIRST_USER_TOKEN + 1

static const char *confirmed_status;  // text displayed in confirmation page (after long press)
static const char *rejected_status;   // text displayed in rejection page (after reject confirmed)
static bool show_message_start_page;

#define N_UX_PAIRS 13

static nbgl_layoutTagValue_t pairs[N_UX_PAIRS];
static nbgl_layoutTagValueList_t pairList;

static nbgl_genericContents_t genericContent;
static nbgl_content_t contentList[4];

extern bool G_was_processing_screen_shown;

// ux_flow_response
static void ux_flow_response_false(void) {
    set_ux_flow_response(false);
}

static void ux_flow_response_true(void) {
    set_ux_flow_response(true);
}

// Statuses
static void status_operation_cancel(void) {
    ux_flow_response_false();
    nbgl_useCaseStatus(rejected_status, false, ui_menu_main);
}

static void status_transaction_cancel(void) {
    ux_flow_response_false();
    nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
}

static void status_message_cancel(void) {
    ux_flow_response_false();
    nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_REJECTED, ui_menu_main);
}

static void status_address_cancel(void) {
    ux_flow_response_false();
    nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_menu_main);
}

static void status_operation_callback(bool confirm) {
    if (confirm) {
        ux_flow_response_true();
        nbgl_useCaseStatus(confirmed_status, true, ui_menu_main);
    } else {
        status_operation_cancel();
    }
}

static void status_address_callback(bool confirm) {
    if (confirm) {
        ux_flow_response_true();
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_menu_main);
    } else {
        status_address_cancel();
    }
}

static void start_processing_transaction_callback(bool confirm) {
    if (confirm) {
        G_was_processing_screen_shown = true;
        nbgl_useCaseSpinner("Processing");
        ux_flow_response_true();
    } else {
        status_transaction_cancel();
    }
}

static void start_processing_message_callback(bool confirm) {
    if (confirm) {
        G_was_processing_screen_shown = true;
        nbgl_useCaseSpinner("Processing");
        ux_flow_response_true();
    } else {
        status_message_cancel();
    }
}

static void start_transaction_callback(bool confirm) {
    if (confirm) {
        ux_flow_response_true();
    } else {
        status_transaction_cancel();
    }
}

static void generic_content_callback(int token, uint8_t index, int page) {
    (void) index;
    (void) page;
    switch (token) {
        case REVIEW_CONFIRM:
            status_operation_callback(true);
            break;
        default:
            PRINTF("Unhandled token : %d", token);
    }
}

static void finish_transaction_flow(bool choice) {
    if (choice) {
        nbgl_useCaseReviewStreamingFinish("Sign transaction\nto send Bitcoin?",
                                          start_processing_transaction_callback);
    } else {
        status_transaction_cancel();
    }
}

void ui_accept_transaction_flow(bool is_self_transfer) {
    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.pairs = pairs;

    if (!is_self_transfer) {
        pairs[0].item = "Fees";
        pairs[0].value = g_ui_state.validate_transaction.fee;

        pairList.nbPairs = 1;
    } else {
        pairs[0].item = "Amount";
        pairs[0].value = "Self-transfer";

        pairs[1].item = "Fees";
        pairs[1].value = g_ui_state.validate_transaction.fee;

        pairList.nbPairs = 2;
    }

    nbgl_useCaseReviewStreamingContinue(&pairList, finish_transaction_flow);
}

#define COMBINE(a, b) a b

// create the string "0 <coind_id> (self-transfer)"
#define SELF_TRANSFER_DESCRIPTION COMBINE("0 ", COMBINE(COIN_COINID_SHORT, " (self-transfer)"))

void ui_accept_transaction_simplified_flow(void) {
    _Static_assert(N_UX_PAIRS >= 9, "Insufficient pairs for this flow");

    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.pairs = pairs;

    int n_pairs = 0;

    // Add warning screens for unverified inputs, external inputs or non-default sighash
    if (g_ui_state.validate_transaction_simplified.warnings.missing_nonwitnessutxo) {
        pairs[n_pairs++] = (nbgl_contentTagValue_t){
            .centeredInfo = true,
            .item = "Unverified inputs\nUpdate Ledger Live or\nthird party wallet software",
            .value = "",
            .valueIcon = &C_Important_Circle_64px};
    }
    if (g_ui_state.validate_transaction_simplified.warnings.external_inputs) {
        pairs[n_pairs++] =
            (nbgl_contentTagValue_t){.centeredInfo = true,
                                     .item = "There are external inputs\nReject if not sure",
                                     .value = "",
                                     .valueIcon = &C_Important_Circle_64px};
    }
    if (g_ui_state.validate_transaction_simplified.warnings.non_default_sighash) {
        pairs[n_pairs++] =
            (nbgl_contentTagValue_t){.centeredInfo = true,
                                     .item = "Non-default sighash\nReject if not sure",
                                     .value = "",
                                     .valueIcon = &C_Important_Circle_64px};
    }

    if (g_ui_state.validate_transaction_simplified.has_wallet_policy) {
        pairs[n_pairs++] = (nbgl_layoutTagValue_t){
            .item = "From",
            .value = g_ui_state.validate_transaction_simplified.wallet_policy_name,
        };
    }

    if (!g_ui_state.validate_transaction_simplified.is_self_transfer) {
        pairs[n_pairs++] = (nbgl_layoutTagValue_t){
            .item = "Amount",
            .value = g_ui_state.validate_transaction_simplified.amount,
        };

        pairs[n_pairs++] = (nbgl_layoutTagValue_t){
            .item = "To",
            .value = g_ui_state.validate_transaction_simplified.address_or_description,
        };
    } else {
        pairs[n_pairs++] =
            (nbgl_layoutTagValue_t){.item = "Amount", .value = SELF_TRANSFER_DESCRIPTION};
    }

    pairs[n_pairs++] = (nbgl_layoutTagValue_t){
        .item = "Fees",
        .value = g_ui_state.validate_transaction_simplified.fee,
    };

    if (g_ui_state.validate_transaction_simplified.warnings.high_fee) {
        pairs[n_pairs++] = (nbgl_contentTagValue_t){.centeredInfo = true,
                                                    .item = "Fees are above 10%\n of total amount",
                                                    .value = "",
                                                    .valueIcon = &C_Important_Circle_64px};
    }

    pairList.nbPairs = n_pairs;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pairList,
                       &C_Bitcoin_64px,
                       "Review transaction\nto send Bitcoin",
                       NULL,
                       "Sign transaction\nto send Bitcoin?",
                       start_transaction_callback);
}

void ui_display_transaction_prompt(void) {
    nbgl_useCaseReviewStreamingStart(TYPE_TRANSACTION,
                                     &C_Bitcoin_64px,
                                     "Review transaction\nto send Bitcoin",
                                     NULL,
                                     start_transaction_callback);
}

void ui_display_output_address_amount_flow(int index) {
    snprintf(g_ui_state.validate_output.index,
             sizeof(g_ui_state.validate_output.index),
             "#%d",
             index);

    pairs[0].item = "Output";
    pairs[0].value = g_ui_state.validate_output.index;

    pairs[1].item = "Amount";
    pairs[1].value = g_ui_state.validate_output.amount;

    pairs[2].item = "Address";
    pairs[2].value = g_ui_state.validate_output.address_or_description;

    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 3;
    pairList.pairs = pairs;

    nbgl_useCaseReviewStreamingContinue(&pairList, start_transaction_callback);
}

void ui_display_output_address_amount_no_index_flow(int index) {
    (void) index;

    pairs[0].item = "Amount";
    pairs[0].value = g_ui_state.validate_output.amount;

    pairs[1].item = "Address";
    pairs[1].value = g_ui_state.validate_output.address_or_description;

    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 2;
    pairList.pairs = pairs;

    nbgl_useCaseReviewStreamingContinue(&pairList, start_transaction_callback);
}

// Continue light notify callback
void ui_display_pubkey_flow(void) {
    confirmed_status = "Public key\napproved";
    rejected_status = "Public key rejected";

    pairs[0].item = "Path";
    pairs[0].value = g_ui_state.path_and_pubkey.bip32_path_str;

    pairs[1].item = "Public key";
    pairs[1].value = g_ui_state.path_and_pubkey.pubkey;

    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 2;
    pairList.pairs = pairs;

    nbgl_useCaseReviewLight(TYPE_OPERATION,
                            &pairList,
                            &C_Bitcoin_64px,
                            "Confirm public key",
                            NULL,
                            "Approve public key",
                            status_operation_callback);
}

void ui_display_receive_in_wallet_flow(void) {
    // Setup list
    pairs[0].item = "Account name";
    pairs[0].value = g_ui_state.wallet.wallet_name;

    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 1;
    pairList.pairs = pairs;

    nbgl_useCaseAddressReview(g_ui_state.wallet.address,
                              &pairList,
                              &C_Bitcoin_64px,
                              "Verify Bitcoin\naddress",
                              NULL,
                              status_address_callback);
}

#ifdef HAVE_NBGL

void ui_display_register_wallet_policy_flow(void) {
    _Static_assert(N_UX_PAIRS >= 3 + MAX_N_KEYS_IN_WALLET_POLICY,
                   "Insufficient pairs for this flow");

    confirmed_status = "Account registered";
    rejected_status = "Account rejected";

    int n_pairs = 0;

    pairList.nbMaxLinesForValue = 0;
    pairList.pairs = pairs;

    pairs[n_pairs++] = (nbgl_layoutTagValue_t){
        .item = "Account name",
        .value = g_ui_state.register_wallet_policy.wallet_name,
    };

    pairs[n_pairs++] = (nbgl_layoutTagValue_t){
        .item = "Descriptor template",
        .value = g_ui_state.register_wallet_policy.descriptor_template,
    };

    pairs[n_pairs++] = (nbgl_contentTagValue_t){.centeredInfo = true,
                                                .item = "Review co-signer\npublic keys",
                                                .value = ""};

    for (size_t i = 0; i < g_ui_state.register_wallet_policy.n_keys; i++) {
        pairs[n_pairs++] =
            (nbgl_layoutTagValue_t){.item = g_ui_state.register_wallet_policy.keys_label[i],
                                    .value = g_ui_state.register_wallet_policy.keys_info[i]};
    }

    pairList.nbPairs = n_pairs;

    nbgl_useCaseReviewLight(TYPE_OPERATION,
                            &pairList,
                            &C_Bitcoin_64px,
                            "Review account\nto register",
                            NULL,
                            "Register account?",
                            status_operation_callback);
}

#endif  // HAVE_NBGL

void ui_display_pubkey_suspicious_flow(void) {
    confirmed_status = "Public key\napproved";
    rejected_status = "Public key rejected";

    pairs[0].item = "Path";
    pairs[0].value = g_ui_state.path_and_pubkey.bip32_path_str;

    pairs[1].item = "Public key";
    pairs[1].value = g_ui_state.path_and_pubkey.pubkey;

    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 2;
    pairList.pairs = pairs;

    contentList[0].type = CENTERED_INFO;
    contentList[0].content.centeredInfo.icon = &C_Bitcoin_64px;
    contentList[0].content.centeredInfo.text1 = "Confirm public key";
    contentList[0].content.centeredInfo.text2 = NULL;
    contentList[0].content.centeredInfo.text3 = NULL;
    contentList[0].content.centeredInfo.style = LARGE_CASE_BOLD_INFO;
    contentList[0].content.centeredInfo.offsetY = 0;
    contentList[0].contentActionCallback = NULL;

    contentList[1].type = CENTERED_INFO;
    contentList[1].content.centeredInfo.icon = &C_Important_Circle_64px;
    contentList[1].content.centeredInfo.text1 = "WARNING";
    contentList[1].content.centeredInfo.text2 = "The derivation path\nis unusual";
    contentList[1].content.centeredInfo.text3 = NULL;
    contentList[1].content.centeredInfo.style = LARGE_CASE_BOLD_INFO;
    contentList[1].content.centeredInfo.offsetY = 0;
    contentList[1].contentActionCallback = NULL;

    contentList[2].type = TAG_VALUE_LIST;
    memcpy(&contentList[2].content.tagValueList, &pairList, sizeof(nbgl_layoutTagValueList_t));
    contentList[2].contentActionCallback = NULL;

    contentList[3].type = INFO_BUTTON;
    contentList[3].content.infoButton.text = "Approve public key";
    contentList[3].content.infoButton.icon = &C_Bitcoin_64px;
    contentList[3].content.infoButton.buttonText = "Approve";
    contentList[3].content.infoButton.buttonToken = REVIEW_CONFIRM;
    contentList[3].content.infoButton.tuneId = TUNE_TAP_CASUAL;
    contentList[3].contentActionCallback = generic_content_callback;

    genericContent.callbackCallNeeded = false;
    genericContent.contentsList = contentList;
    genericContent.nbContents = 4;

    nbgl_useCaseGenericReview(&genericContent, "Cancel", status_operation_cancel);
}

static void message_finish_callback(bool confirm) {
    if (confirm) {
        nbgl_useCaseReviewStreamingFinish("Sign message?", start_processing_message_callback);
    } else {
        status_message_cancel();
    }
}

static void message_display_content_continue(bool confirm) {
    if (confirm) {
        increase_streaming_index();
        ux_flow_response_true();
    } else {
        status_message_cancel();
    }
}

static void message_display_content(bool confirm) {
    if (confirm) {
        pairList.pairs = pairs;
        pairList.nbPairs = 0;

        if (get_streaming_index() == 0) {
            pairs[0].item = "Path";
            pairs[0].value = g_ui_state.path_and_message.bip32_path_str;
            pairList.nbPairs = 1;
        }

        pairs[pairList.nbPairs].item = "Message content";
        pairs[pairList.nbPairs].value = g_ui_state.path_and_message.message;

        pairList.wrapping = true;
        pairList.nbPairs++;

        nbgl_useCaseReviewStreamingContinue(&pairList, message_display_content_continue);
    } else {
        status_message_cancel();
    }
}

static void message_display_path(bool confirm) {
    if (confirm) {
        pairs[0].item = "Path";
        pairs[0].value = g_ui_state.path_and_message.bip32_path_str;

        pairs[1].item = "Message hash";
        pairs[1].value = g_ui_state.path_and_message.message;

        pairList.nbPairs = 2;
        pairList.pairs = pairs;

        nbgl_useCaseReviewStreamingContinue(&pairList, message_finish_callback);
    } else {
        status_message_cancel();
    }
}

void ui_sign_message_content_flow(void) {
    if (show_message_start_page == true) {
        show_message_start_page = false;
        nbgl_useCaseReviewStreamingStart(TYPE_MESSAGE,
                                         &C_Bitcoin_64px,
                                         "Review message",
                                         NULL,
                                         message_display_content);
    } else {
        message_display_content(true);
    }
}

void ui_sign_message_path_hash_and_confirm_flow(void) {
    nbgl_useCaseReviewStreamingStart(TYPE_MESSAGE,
                                     &C_Bitcoin_64px,
                                     "Review message",
                                     NULL,
                                     message_display_path);
}

void ui_sign_message_confirm_flow(void) {
    nbgl_useCaseReviewStreamingFinish("Sign message?", start_processing_message_callback);
}

void ui_display_withdraw_content_flow(void) {
    pairList.pairs = pairs;
    pairList.nbPairs = 2;

    pairs[0].item = "Redeemer Address";
    pairs[0].value = g_ui_state.validate_withdraw.redeemer_address;
    pairs[1].item = "Value";
    pairs[1].value = g_ui_state.validate_withdraw.value;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pairList,
                       &C_Bitcoin_64px,
                       "Review transaction\nto withdraw Bitcoin",
                       NULL,
                       "Sign transaction\nto withdraw Bitcoin?",
                       start_transaction_callback);
}

void ui_set_display_prompt(void) {
    show_message_start_page = true;
}

void ui_display_spend_from_wallet_flow(void) {
    confirmed_status = "Account name\nconfirmed";
    rejected_status = "Account name rejected";

    // Setup data to display
    pairs[0].item = "Account name";
    pairs[0].value = g_ui_state.wallet.wallet_name;

    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 1;
    pairList.pairs = pairs;

    nbgl_useCaseReviewLight(TYPE_OPERATION,
                            &pairList,
                            &C_Bitcoin_64px,
                            "Spend from\nknown account",
                            NULL,
                            "Confirm account name",
                            status_operation_callback);
}

// Address flow
void ui_display_default_wallet_address_flow(void) {
    nbgl_useCaseAddressReview(g_ui_state.wallet.address,
                              NULL,
                              &C_Bitcoin_64px,
                              "Verify Bitcoin\naddress",
                              NULL,
                              status_address_callback);
}

// Warning Flows
void ui_warn_high_fee_flow(void) {
    nbgl_useCaseChoice(&C_Important_Circle_64px,
                       "Warning",
                       "Fees are above 10%\n of total amount",
                       "Continue",
                       "Reject",
                       start_transaction_callback);
}

void ui_display_warning_external_inputs_flow(void) {
    nbgl_useCaseChoice(&C_Important_Circle_64px,
                       "Warning",
                       "There are external inputs",
                       "Continue",
                       "Reject if not sure",
                       start_transaction_callback);
}

void ui_display_unverified_segwit_inputs_flows(void) {
    nbgl_useCaseChoice(&C_Important_Circle_64px,
                       "Warning",
                       "Unverified inputs\nUpdate Ledger Live or\nthird party wallet software",
                       "Continue",
                       "Reject if not sure",
                       start_transaction_callback);
}

void ui_display_nondefault_sighash_flow(void) {
    nbgl_useCaseChoice(&C_Important_Circle_64px,
                       "Warning",
                       "Non-default sighash",
                       "Continue",
                       "Reject if not sure",
                       start_transaction_callback);
}

// Statuses
void ui_display_post_processing_confirm_message(bool success) {
    if (success) {
        ux_flow_response_true();
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_SIGNED, ui_menu_main);
    } else {
        ux_flow_response_false();
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_REJECTED, ui_menu_main);
    }
}
void ui_display_post_processing_confirm_withdraw(bool success) {
    if (success) {
        ux_flow_response_true();
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    } else {
        ux_flow_response_false();
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}

void ui_display_post_processing_confirm_transaction(bool success) {
    if (success) {
        ux_flow_response_true();
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    } else {
        ux_flow_response_false();
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}
#endif  // HAVE_NBGL
