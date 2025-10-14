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

/* Graphical resources (GA) used by the application and NBGL */
#ifdef SCREEN_SIZE_WALLET
const char GA_SIGN_TRANSACTION[] = "Sign transaction\nto send Bitcoin?";
const char GA_SIGN_MESSAGE[] = "Sign message?";
const char GA_REGISTER_ACCOUNT[] = "Register account?";
#else
const char GA_SIGN_TRANSACTION[] = "Sign transaction";
const char GA_SIGN_MESSAGE[] = "Sign message";
const char GA_REGISTER_ACCOUNT[] = "Register account";
#endif /* #ifdef SCREEN_SIZE_WALLET */

#ifdef SCREEN_SIZE_WALLET
const char GA_SECURITY_RISK_TITLE[] = "Security risk detected";
const char GA_WARN_HIGH_FEES_TITLE[] = "High fees warning";
const char GA_RISK_EXTERNAL_INPUTS[] =
    "This transaction has external inputs, and could spend more than you think.";
const char GA_RISK_NON_STD_SIGHASH[] =
    "This transaction uses non-standard signing rules (modified sighash), and could spend more "
    "than you think.";
const char GA_WARN_HIGH_FEES[] =
    "You're about to review a transaction with fees above 10\% of the total amount.";

#else
const char GA_SECURITY_RISK_TITLE[] = "Security risk";
const char GA_WARN_HIGH_FEES_TITLE[] = "High fees warning";
const char GA_RISK_EXTERNAL_INPUTS[] = "There are external inputs\nReject if not sure";
const char GA_RISK_NON_STD_SIGHASH[] = "Non-default sighash";
const char GA_WARN_HIGH_FEES[] = "Fees are above 10%\n of total amount";
#endif

const char GA_BACK_TO_SAFETY[] = "Back to safety";
const char GA_CONTINUE_ANYWAY[] = "Continue anyway";
const char GA_RISK_UNVERIFIED_INPUTS[] = "Unverified inputs\nUpdate your wallet software";
const char GA_REVIEW_TRANSACTION[] = "Review transaction\nto send Bitcoin";
const char GA_REVIEW_MESSAGE[] = "Review message";
const char GA_LOADING_TRANSACTION[] = "Loading transaction";
const char GA_LOADING_MESSAGE[] = "Loading message";

#define N_UX_PAIRS 36

static nbgl_layoutTagValue_t pairs[N_UX_PAIRS];
static unsigned int n_pairs;
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
        nbgl_useCaseSpinner(ui_get_processing_screen_text());
        ux_flow_response_true();
    } else {
        status_transaction_cancel();
    }
}

static void start_processing_message_callback(bool confirm) {
    if (confirm) {
        G_was_processing_screen_shown = true;
        nbgl_useCaseSpinner(ui_get_processing_screen_text());
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

static void start_transaction_callback_inverted(bool confirm) {
    if (!confirm) {
        ux_flow_response_true();
    } else {
        status_transaction_cancel();
    }
}

static void generic_content_callback(int token, uint8_t index, int page) {
    UNUSED(index);
    UNUSED(page);
    switch (token) {
        case REVIEW_CONFIRM:
            status_operation_callback(true);
            break;
        default:
            PRINTF("Unhandled token : %d", token);
    }
}

#define COMBINE(a, b) a b

// create the string "0 <coind_id> (self-transfer)"
#define SELF_TRANSFER_DESCRIPTION COMBINE("0 ", COMBINE(COIN_COINID_SHORT, " (self-transfer)"))

void ui_accept_transaction_simplified_flow_init(void) {
    /* 3 warnings + 1 From + MAX_EXT_OUTPUT_NUMBER*3 + 1 Fees + 1 High fees */
    _Static_assert(N_UX_PAIRS >= (3 + 1 + MAX_EXT_OUTPUT_NUMBER * 3 + 1 + 1),
                   "Insufficient pairs for this flow");
    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.pairs = pairs;
    n_pairs = 0;

    ui_validate_transaction_simplified_state_t *state =
        (ui_validate_transaction_simplified_state_t *) &g_ui_state;

    // Add warning screens for unverified inputs, external inputs or non-default sighash
#ifdef SCREEN_SIZE_WALLET
    /* SCREEN_SIZE_WALLET */
    if (state->warnings.missing_nonwitnessutxo) {
        pairs[n_pairs++] = (nbgl_contentTagValue_t){.item = GA_SECURITY_RISK_TITLE,
                                                    .value = GA_RISK_UNVERIFIED_INPUTS,
                                                    .centeredInfo = true,
                                                    .valueIcon = &ICON_APP_WARNING};
    }
    if (state->warnings.external_inputs) {
        pairs[n_pairs++] = (nbgl_contentTagValue_t){.item = GA_SECURITY_RISK_TITLE,
                                                    .value = GA_RISK_EXTERNAL_INPUTS,
                                                    .centeredInfo = true,
                                                    .valueIcon = &ICON_APP_WARNING};
    }
    if (state->warnings.non_default_sighash) {
        pairs[n_pairs++] = (nbgl_contentTagValue_t){.item = GA_SECURITY_RISK_TITLE,
                                                    .value = GA_RISK_NON_STD_SIGHASH,
                                                    .centeredInfo = true,
                                                    .valueIcon = &ICON_APP_WARNING};
    }
#else
    /* Nano X or Nano S Plus device */
    if (state->warnings.missing_nonwitnessutxo) {
        pairs[n_pairs++] = (nbgl_contentTagValue_t){.item = GA_SECURITY_RISK_TITLE,
                                                    .value = "",
                                                    .centeredInfo = true,
                                                    .valueIcon = &ICON_APP_WARNING};
        pairs[n_pairs++] = (nbgl_contentTagValue_t){.item = GA_RISK_UNVERIFIED_INPUTS,
                                                    .value = "",
                                                    .centeredInfo = true};
    }
    if (state->warnings.external_inputs) {
        pairs[n_pairs++] = (nbgl_contentTagValue_t){.item = GA_SECURITY_RISK_TITLE,
                                                    .value = "",
                                                    .centeredInfo = true,
                                                    .valueIcon = &ICON_APP_WARNING};
        pairs[n_pairs++] = (nbgl_contentTagValue_t){.item = GA_RISK_EXTERNAL_INPUTS,
                                                    .value = "",
                                                    .centeredInfo = true};
    }
    if (state->warnings.non_default_sighash) {
        pairs[n_pairs++] = (nbgl_contentTagValue_t){.item = GA_SECURITY_RISK_TITLE,
                                                    .value = "",
                                                    .centeredInfo = true,
                                                    .valueIcon = &ICON_APP_WARNING};
        pairs[n_pairs++] = (nbgl_contentTagValue_t){.item = GA_RISK_NON_STD_SIGHASH,
                                                    .value = "",
                                                    .centeredInfo = true};
    }
#endif /* #ifdef SCREEN_SIZE_WALLET */

    if (state->has_wallet_policy) {
        pairs[n_pairs++] = (nbgl_layoutTagValue_t){
            .item = "From",
            .value = state->wallet_policy_name,
        };
    }
}

void ui_accept_transaction_simplified_flow_add(void) {
    ui_validate_transaction_simplified_state_t *state =
        (ui_validate_transaction_simplified_state_t *) &g_ui_state;

    unsigned int output_index = state->output_index;
    if (!state->is_self_transfer) {
        if (state->n_outputs > 1) {
            pairs[n_pairs++] =
                (nbgl_layoutTagValue_t){.item = "Transaction output",
                                        .value = state->output_index_str[output_index],
                                        .forcePageStart = true};
        }
        pairs[n_pairs++] = (nbgl_layoutTagValue_t){.item = "Amount",
                                                   .value = state->amount[output_index],
                                                   .forcePageStart = false};

        pairs[n_pairs++] = (nbgl_layoutTagValue_t){
            .item = "To",
            .value = state->address_or_description[output_index],
        };
    } else {
        pairs[n_pairs++] =
            (nbgl_layoutTagValue_t){.item = "Amount", .value = SELF_TRANSFER_DESCRIPTION};
    }
}

void ui_accept_transaction_simplified_flow_start(void) {
    ui_validate_transaction_simplified_state_t *state =
        (ui_validate_transaction_simplified_state_t *) &g_ui_state;

    if (state->warnings.high_fee) {
        pairs[n_pairs++] = (nbgl_contentTagValue_t){.item = GA_WARN_HIGH_FEES_TITLE,
                                                    .value = GA_WARN_HIGH_FEES,
                                                    .centeredInfo = true,
                                                    .valueIcon = &ICON_APP_IMPORTANT};
    }

    pairs[n_pairs++] = (nbgl_layoutTagValue_t){.item = "Fees",
                                               .value = state->fee,
                                               .forcePageStart = state->n_outputs > 1 ? 1 : 0};

    pairList.nbPairs = n_pairs;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pairList,
                       &ICON_APP_ACTION,
                       GA_REVIEW_TRANSACTION,
                       NULL,
                       GA_SIGN_TRANSACTION,
                       start_transaction_callback);
}

void ui_display_transaction_prompt(void) {
    nbgl_useCaseReviewStreamingStart(TYPE_TRANSACTION,
                                     &ICON_APP_ACTION,
                                     GA_REVIEW_TRANSACTION,
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
    UNUSED(index);

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

static void finish_transaction_flow(bool choice) {
    if (choice) {
        nbgl_useCaseReviewStreamingFinish(GA_SIGN_TRANSACTION,
                                          start_processing_transaction_callback);
    } else {
        status_transaction_cancel();
    }
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
                            &ICON_APP_ACTION,
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
                              &ICON_APP_ACTION,
                              "Verify Bitcoin\naddress",
                              NULL,
                              status_address_callback);
}

void ui_display_register_wallet_policy_flow(void) {
    _Static_assert(N_UX_PAIRS >= 3 + MAX_N_KEYS_IN_WALLET_POLICY,
                   "Insufficient pairs for this flow");

    confirmed_status = "Account registered";
    rejected_status = "Account rejected";

    n_pairs = 0;

    pairList.nbMaxLinesForValue = 0;
    pairList.pairs = pairs;

    pairs[n_pairs++] = (nbgl_layoutTagValue_t){
        .item = "Account name",
        .value = g_ui_state.register_wallet_policy.wallet_name,
    };

    pairs[n_pairs++] = (nbgl_layoutTagValue_t){
#ifdef SCREEN_SIZE_WALLET
        .item = "Descriptor template",
#else
        .item = "Wallet policy",
#endif
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
                            &ICON_APP_ACTION,
                            "Review account\nto register",
                            NULL,
                            GA_REGISTER_ACCOUNT,
                            status_operation_callback);
}

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
    contentList[0].content.centeredInfo.icon = &ICON_APP_ACTION;
    contentList[0].content.centeredInfo.text1 = "Confirm public key";
    contentList[0].content.centeredInfo.text2 = NULL;
#ifdef SCREEN_SIZE_WALLET
    contentList[0].content.centeredInfo.text3 = NULL;
    contentList[0].content.centeredInfo.style = LARGE_CASE_BOLD_INFO;
    contentList[0].content.centeredInfo.offsetY = 0;
#else
    contentList[0].content.centeredInfo.style = BOLD_TEXT1_INFO;
#endif
    contentList[0].contentActionCallback = NULL;

    contentList[1].type = CENTERED_INFO;
    contentList[1].content.centeredInfo.icon = &ICON_APP_IMPORTANT;
    contentList[1].content.centeredInfo.text1 = "WARNING";
    contentList[1].content.centeredInfo.text2 = "The derivation path\nis unusual";
#ifdef SCREEN_SIZE_WALLET
    contentList[1].content.centeredInfo.text3 = NULL;
    contentList[1].content.centeredInfo.style = LARGE_CASE_BOLD_INFO;
    contentList[1].content.centeredInfo.offsetY = 0;
#else
    contentList[1].content.centeredInfo.style = BOLD_TEXT1_INFO;
#endif
    contentList[1].contentActionCallback = NULL;

    contentList[2].type = TAG_VALUE_LIST;
    memcpy(&contentList[2].content.tagValueList, &pairList, sizeof(nbgl_layoutTagValueList_t));
    contentList[2].contentActionCallback = NULL;

    contentList[3].type = INFO_BUTTON;
    contentList[3].content.infoButton.text = "Approve public key";
    contentList[3].content.infoButton.icon = &ICON_APP_ACTION;
#ifdef SCREEN_SIZE_WALLET
    contentList[3].content.infoButton.buttonText = "Approve";
#else
    contentList[3].content.infoButton.buttonText = "";
#endif
    contentList[3].content.infoButton.buttonToken = REVIEW_CONFIRM;
#ifdef HAVE_PIEZO_SOUND
    contentList[3].content.infoButton.tuneId = TUNE_TAP_CASUAL;
#endif
    contentList[3].contentActionCallback = generic_content_callback;

    genericContent.callbackCallNeeded = false;
    genericContent.contentsList = contentList;
    genericContent.nbContents = 4;

    nbgl_useCaseGenericReview(&genericContent, "Cancel", status_operation_cancel);
}

static void message_finish_callback(bool confirm) {
    if (confirm) {
        nbgl_useCaseReviewStreamingFinish(GA_SIGN_MESSAGE, start_processing_message_callback);
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

#ifdef SCREEN_SIZE_WALLET
        pairs[pairList.nbPairs].item = "Message content";
#else
        pairs[pairList.nbPairs].item = "Message";
#endif
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
                                         &ICON_APP_ACTION,
                                         GA_REVIEW_MESSAGE,
                                         NULL,
                                         message_display_content);
    } else {
        message_display_content(true);
    }
}

void ui_sign_message_path_hash_and_confirm_flow(void) {
    nbgl_useCaseReviewStreamingStart(TYPE_MESSAGE,
                                     &ICON_APP_ACTION,
                                     GA_REVIEW_MESSAGE,
                                     NULL,
                                     message_display_path);
}

void ui_sign_message_confirm_flow(void) {
    nbgl_useCaseReviewStreamingFinish(GA_SIGN_MESSAGE, start_processing_message_callback);
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
                            &ICON_APP_ACTION,
                            "Spend from\nknown account",
                            NULL,
                            "Confirm account name",
                            status_operation_callback);
}

// Address flow
void ui_display_default_wallet_address_flow(void) {
    nbgl_useCaseAddressReview(g_ui_state.wallet.address,
                              NULL,
                              &ICON_APP_ACTION,
                              "Verify Bitcoin\naddress",
                              NULL,
                              status_address_callback);
}

// Warning Flows
void ui_warn_high_fee_flow(void) {
    nbgl_useCaseChoice(&ICON_APP_IMPORTANT,
                       GA_WARN_HIGH_FEES_TITLE,
                       GA_WARN_HIGH_FEES,
                       "Review anyway",
                       "Reject transaction",
                       start_transaction_callback);
}

void ui_display_warning_external_inputs_flow(void) {
    nbgl_useCaseChoice(&ICON_APP_WARNING,
                       GA_SECURITY_RISK_TITLE,
                       GA_RISK_EXTERNAL_INPUTS,
                       GA_BACK_TO_SAFETY,
                       GA_CONTINUE_ANYWAY,
                       start_transaction_callback_inverted);
}

void ui_display_unverified_segwit_inputs_flows(void) {
    nbgl_useCaseChoice(&ICON_APP_WARNING,
                       GA_SECURITY_RISK_TITLE,
                       GA_RISK_UNVERIFIED_INPUTS,
                       GA_BACK_TO_SAFETY,
                       GA_CONTINUE_ANYWAY,
                       start_transaction_callback_inverted);
}

void ui_display_nondefault_sighash_flow(void) {
    nbgl_useCaseChoice(&ICON_APP_WARNING,
                       GA_SECURITY_RISK_TITLE,
                       GA_RISK_NON_STD_SIGHASH,
                       GA_BACK_TO_SAFETY,
                       GA_CONTINUE_ANYWAY,
                       start_transaction_callback_inverted);
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

void ui_display_post_processing_confirm_transaction(bool success) {
    if (success) {
        ux_flow_response_true();
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    } else {
        ux_flow_response_false();
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}
