#ifdef HAVE_NBGL

#include <stdint.h>

#include "nbgl_use_case.h"
#include "./display.h"
#include "./menu.h"
#include "io.h"

#define REVIEW_CONFIRM FIRST_USER_TOKEN + 1

static const char *confirmed_status;  // text displayed in confirmation page (after long press)
static const char *rejected_status;   // text displayed in rejection page (after reject confirmed)
static bool show_message_start_page;  

static nbgl_layoutTagValue_t pairs[3];
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

static void ux_flow_response(bool confirm) {
    if (confirm) {
        ux_flow_response_true();
    } else {
        ux_flow_response_false();
    }
}

// Statuses
static void status_cancel(void) {
        ux_flow_response_false();
        nbgl_useCaseStatus(rejected_status, false, ui_menu_main);
}

static void status_confirm(void) {
        ux_flow_response_true();
        nbgl_useCaseStatus(confirmed_status, true, ui_menu_main);
}

static void status_confirmation_callback(bool confirm) {
    if (confirm) {
        status_confirm();
    } else {
        status_cancel();
    }
}

static void start_processing_callback(bool confirm) {
    if (confirm) {
        nbgl_useCaseSpinner("Processing");
        ux_flow_response_true();
    } else {
        status_cancel();
    }
}

static void start_callback(bool confirm) {
    if (confirm) {
        ux_flow_response_true();
    } else {
        status_cancel();
    }
}

static void generic_content_callback(int token, uint8_t index, int page) {
    (void) index;
    (void) page;
    switch (token) {
        case REVIEW_CONFIRM:
            status_confirmation_callback(true);
            break;
        default:
            PRINTF("Unhandled token : %d", token);
    }
}

static void finish_transaction_flow(bool choice) {
    if (choice) {
        nbgl_useCaseReviewStreamingFinish("Sign transaction\nto send Bitcoin?",
                                       start_processing_callback);
    }
    else {
        start_processing_callback(false);
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

    nbgl_useCaseReviewStreamingContinue(&pairList,
                                        finish_transaction_flow);
}

void ui_display_transaction_prompt(void) {
    confirmed_status = "TRANSACTION\nSIGNED";
    rejected_status = "Transaction rejected";
    
    nbgl_useCaseReviewStreamingStart(TYPE_TRANSACTION,
                                     &C_Bitcoin_64px,
                                     "Review transaction\nto send Bitcoin",
                                     NULL,
                                     start_callback);
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

    nbgl_useCaseReviewStreamingContinue(&pairList,
                                        start_callback);

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

    nbgl_useCaseReviewStreamingContinue(&pairList,
                                        start_callback);
}

// Continue light notify callback
void ui_display_pubkey_flow(void) {
    confirmed_status = "PUBLIC KEY\nAPPROVED";
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
    contentList[0].content.centeredInfo.icon    = &C_Bitcoin_64px;
    contentList[0].content.centeredInfo.text1   = "Confirm public key";
    contentList[0].content.centeredInfo.text2   = NULL;
    contentList[0].content.centeredInfo.text3   = NULL;
    contentList[0].content.centeredInfo.style   = LARGE_CASE_BOLD_INFO;
    contentList[0].content.centeredInfo.offsetY = 0;
    contentList[0].contentActionCallback        = NULL;

    contentList[1].type = TAG_VALUE_LIST;
    memcpy(&contentList[1].content.tagValueList, &pairList, sizeof(nbgl_layoutTagValueList_t));
    contentList[1].contentActionCallback = NULL;

    contentList[2].type = INFO_BUTTON;
    contentList[2].content.infoButton.text        = "Approve public key";
    contentList[2].content.infoButton.icon        = &C_Bitcoin_64px;
    contentList[2].content.infoButton.buttonText  = "Approve";
    contentList[2].content.infoButton.buttonToken = REVIEW_CONFIRM;
    contentList[2].content.infoButton.tuneId      = TUNE_TAP_CASUAL;
    contentList[2].contentActionCallback          = generic_content_callback;


    genericContent.callbackCallNeeded = false;
    genericContent.contentsList       = contentList;
    genericContent.nbContents         = 3;

    nbgl_useCaseGenericReview(&genericContent, "Cancel", status_cancel);
}

void ui_display_receive_in_wallet_flow(void) {
    confirmed_status = "ADDRESS\nCONFIRMED";
    rejected_status = "Address rejected";

    // Setup list
    pairs[0].item = "Wallet name";
    pairs[0].value = g_ui_state.wallet.wallet_name;

    pairs[1].item = "Wallet Address";
    pairs[1].value = g_ui_state.wallet.address;
    
    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 2;
    pairList.pairs = pairs;
    
    contentList[0].type = CENTERED_INFO;
    contentList[0].content.centeredInfo.icon    = &C_Bitcoin_64px;
    contentList[0].content.centeredInfo.text1   = "Receive\nin known wallet";
    contentList[0].content.centeredInfo.text2   = NULL;
    contentList[0].content.centeredInfo.text3   = NULL;
    contentList[0].content.centeredInfo.style   = LARGE_CASE_BOLD_INFO;
    contentList[0].content.centeredInfo.offsetY = 0;
    contentList[0].contentActionCallback        = NULL;

    contentList[1].type = TAG_VALUE_LIST;
    memcpy(&contentList[1].content.tagValueList, &pairList, sizeof(nbgl_layoutTagValueList_t));
    contentList[1].contentActionCallback = NULL;

    contentList[2].type = INFO_BUTTON;
    contentList[2].content.infoButton.text        = "Confirm address";
    contentList[2].content.infoButton.icon        = &C_Bitcoin_64px;
    contentList[2].content.infoButton.buttonText  = "Approve";
    contentList[2].content.infoButton.buttonToken = REVIEW_CONFIRM;
    contentList[2].content.infoButton.tuneId      = TUNE_TAP_CASUAL;
    contentList[2].contentActionCallback          = generic_content_callback;


    genericContent.callbackCallNeeded = false;
    genericContent.contentsList       = contentList;
    genericContent.nbContents         = 3;

    nbgl_useCaseGenericReview(&genericContent, "Cancel", status_cancel);
}

void ui_display_policy_map_cosigner_pubkey_flow(void) {
    confirmed_status = "COSIGNER\nREGISTERED";
    rejected_status = "Cosigner rejected";

    pairs[0].item = "Index";
    pairs[0].value = g_ui_state.cosigner_pubkey_and_index.signer_index;

    pairs[1].item = "Public key";
    pairs[1].value = g_ui_state.cosigner_pubkey_and_index.pubkey;
    
    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 2;
    pairList.pairs = pairs;
    
    contentList[0].type = CENTERED_INFO;
    contentList[0].content.centeredInfo.icon    = &C_Bitcoin_64px;
    contentList[0].content.centeredInfo.text1   = "Register cosigner";
    contentList[0].content.centeredInfo.text2   = NULL;
    contentList[0].content.centeredInfo.text3   = NULL;
    contentList[0].content.centeredInfo.style   = LARGE_CASE_BOLD_INFO;
    contentList[0].content.centeredInfo.offsetY = 0;
    contentList[0].contentActionCallback        = NULL;

    contentList[1].type = TAG_VALUE_LIST;
    memcpy(&contentList[1].content.tagValueList, &pairList, sizeof(nbgl_layoutTagValueList_t));
    contentList[1].contentActionCallback = NULL;

    contentList[2].type = INFO_BUTTON;
    contentList[2].content.infoButton.text        = "Confirm cosigner";
    contentList[2].content.infoButton.icon        = &C_Bitcoin_64px;
    contentList[2].content.infoButton.buttonText  = "Approve";
    contentList[2].content.infoButton.buttonToken = REVIEW_CONFIRM;
    contentList[2].content.infoButton.tuneId      = TUNE_TAP_CASUAL;
    contentList[2].contentActionCallback          = generic_content_callback;


    genericContent.callbackCallNeeded = false;
    genericContent.contentsList       = contentList;
    genericContent.nbContents         = 3;

    nbgl_useCaseGenericReview(&genericContent, "Cancel", status_cancel);
}

void ui_display_pubkey_suspicious_flow(void) {
    confirmed_status = "PUBLIC KEY\nAPPROVED";
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
    contentList[0].content.centeredInfo.icon    = &C_Bitcoin_64px;
    contentList[0].content.centeredInfo.text1   = "Confirm public key";
    contentList[0].content.centeredInfo.text2   = NULL;
    contentList[0].content.centeredInfo.text3   = NULL;
    contentList[0].content.centeredInfo.style   = LARGE_CASE_BOLD_INFO;
    contentList[0].content.centeredInfo.offsetY = 0;
    contentList[0].contentActionCallback        = NULL;

    contentList[1].type = CENTERED_INFO;
    contentList[1].content.centeredInfo.icon    = &C_Important_Circle_64px;
    contentList[1].content.centeredInfo.text1   = "WARNING";
    contentList[1].content.centeredInfo.text2   = "The derivation path\nis unusual";
    contentList[1].content.centeredInfo.text3   = NULL;
    contentList[1].content.centeredInfo.style   = LARGE_CASE_BOLD_INFO;
    contentList[1].content.centeredInfo.offsetY = 0;
    contentList[1].contentActionCallback        = NULL;

    contentList[2].type = TAG_VALUE_LIST;
    memcpy(&contentList[2].content.tagValueList, &pairList, sizeof(nbgl_layoutTagValueList_t));
    contentList[2].contentActionCallback = NULL;

    contentList[3].type = INFO_BUTTON;
    contentList[3].content.infoButton.text        = "Approve public key";
    contentList[3].content.infoButton.icon        = &C_Bitcoin_64px;
    contentList[3].content.infoButton.buttonText  = "Approve";
    contentList[3].content.infoButton.buttonToken = REVIEW_CONFIRM;
    contentList[3].content.infoButton.tuneId      = TUNE_TAP_CASUAL;
    contentList[3].contentActionCallback          = generic_content_callback;


    genericContent.callbackCallNeeded = false;
    genericContent.contentsList       = contentList;
    genericContent.nbContents         = 4;

    nbgl_useCaseGenericReview(&genericContent, "Cancel", status_cancel);
}

// Continue light processing callback
void ui_display_register_wallet_flow(void) {
    confirmed_status = "WALLET\nREGISTERED";
    rejected_status = "Wallet rejected";

    pairs[0].item = "Name";
    pairs[0].value = g_ui_state.wallet.wallet_name;

    pairs[1].item = "Policy map";
    pairs[1].value = g_ui_state.wallet.descriptor_template;
    
    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 2;
    pairList.pairs = pairs;

    contentList[0].type = CENTERED_INFO;
    contentList[0].content.centeredInfo.icon    = &C_Bitcoin_64px;
    contentList[0].content.centeredInfo.text1   = "Register wallet";
    contentList[0].content.centeredInfo.text2   = NULL;
    contentList[0].content.centeredInfo.text3   = NULL;
    contentList[0].content.centeredInfo.style   = LARGE_CASE_BOLD_INFO;
    contentList[0].content.centeredInfo.offsetY = 0;
    contentList[0].contentActionCallback        = NULL;

    contentList[1].type = TAG_VALUE_LIST;
    memcpy(&contentList[1].content.tagValueList, &pairList, sizeof(nbgl_layoutTagValueList_t));
    contentList[1].contentActionCallback = NULL;

    contentList[2].type = INFO_BUTTON;
    contentList[2].content.infoButton.text        = "Register wallet";
    contentList[2].content.infoButton.icon        = &C_Bitcoin_64px;
    contentList[2].content.infoButton.buttonText  = "Approve";
    contentList[2].content.infoButton.buttonToken = REVIEW_CONFIRM;
    contentList[2].content.infoButton.tuneId      = TUNE_TAP_CASUAL;
    contentList[2].contentActionCallback          = generic_content_callback;


    genericContent.callbackCallNeeded = false;
    genericContent.contentsList       = contentList;
    genericContent.nbContents         = 3;

    nbgl_useCaseGenericReview(&genericContent, "Cancel", status_cancel);
}

static void message_finish_callback(bool confirm) {
    if (confirm) {
        nbgl_useCaseReviewStreamingFinish("Sign message?", start_processing_callback);
    }
    else {
        status_cancel();
    }
}

static void message_display_content_continue(bool confirm) {
    if (confirm) {
        increase_streaming_index();
        ux_flow_response_true();
    }
    else {
        status_cancel();
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
    }
    else {
        status_cancel();
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
    }
    else {
        status_cancel();
    }
}

void ui_sign_message_content_flow(void) {
    confirmed_status = "MESSAGE\nSIGNED";
    rejected_status = "Message rejected";

    if (show_message_start_page == true) {
        show_message_start_page = false;
        nbgl_useCaseReviewStreamingStart(TYPE_MESSAGE,
                                         &C_Bitcoin_64px,
                                         "Review message",
                                         NULL,
                                         message_display_content);
    }
    else {
        message_display_content(true);
    }
}

void ui_sign_message_path_hash_and_confirm_flow(void) {
    confirmed_status = "MESSAGE\nSIGNED";
    rejected_status = "Message rejected";

    nbgl_useCaseReviewStreamingStart(TYPE_MESSAGE,
                                     &C_Bitcoin_64px,
                                     "Review message",
                                     NULL,
                                     message_display_path);
}

void ui_sign_message_confirm_flow(void) {
    nbgl_useCaseReviewStreamingFinish("Sign message?", start_processing_callback);
}

void ui_set_display_prompt(void) {
    show_message_start_page = true;
}

void ui_display_spend_from_wallet_flow(void) {
    confirmed_status = "WALLET NAME\nCONFIRMED";
    rejected_status = "Wallet name rejected";

    // Setup data to display
    pairs[0].item = "Wallet name";
    pairs[0].value = g_ui_state.wallet.wallet_name;

    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 1;
    pairList.pairs = pairs;

    contentList[0].type = CENTERED_INFO;
    contentList[0].content.centeredInfo.icon    = &C_Bitcoin_64px;
    contentList[0].content.centeredInfo.text1   = "Spend from\nknown wallet";
    contentList[0].content.centeredInfo.text2   = NULL;
    contentList[0].content.centeredInfo.text3   = NULL;
    contentList[0].content.centeredInfo.style   = LARGE_CASE_BOLD_INFO;
    contentList[0].content.centeredInfo.offsetY = 0;
    contentList[0].contentActionCallback        = NULL;

    contentList[1].type = TAG_VALUE_LIST;
    memcpy(&contentList[1].content.tagValueList, &pairList, sizeof(nbgl_layoutTagValueList_t));
    contentList[1].contentActionCallback = NULL;

    contentList[2].type = INFO_BUTTON;
    contentList[2].content.infoButton.text        = "Confirm wallet name";
    contentList[2].content.infoButton.icon        = &C_Bitcoin_64px;
    contentList[2].content.infoButton.buttonText  = "Approve";
    contentList[2].content.infoButton.buttonToken = REVIEW_CONFIRM;
    contentList[2].content.infoButton.tuneId      = TUNE_TAP_CASUAL;
    contentList[2].contentActionCallback          = generic_content_callback;


    genericContent.callbackCallNeeded = false;
    genericContent.contentsList       = contentList;
    genericContent.nbContents         = 3;

    nbgl_useCaseGenericReview(&genericContent, "Cancel", status_cancel);
}

// Address flow
void ui_display_default_wallet_address_flow(void) {
    confirmed_status = "ADDRESS\nVERIFIED";
    rejected_status = "Address verification\ncancelled";

    nbgl_useCaseAddressReview(g_ui_state.wallet.address,
                              NULL,
                              &C_Bitcoin_64px,
                              "Verify Bitcoin\naddress",
                              NULL,
                              status_confirmation_callback);
}

// Warning Flows
void ui_warn_high_fee_flow(void) {
    rejected_status = "Transaction rejected";
    nbgl_useCaseChoice(&C_Important_Circle_64px,
                       "Warning",
                       "Fees are above 10%\n of total amount",
                       "Continue",
                       "Reject",
                       start_callback);
}

void ui_display_warning_external_inputs_flow(void) {
    rejected_status = "Transaction rejected";
    nbgl_useCaseChoice(&C_Important_Circle_64px,
                       "Warning",
                       "There are external inputs",
                       "Continue",
                       "Reject if not sure",
                       start_callback);
}

void ui_display_unverified_segwit_inputs_flows(void) {
    rejected_status = "Transaction rejected";
    nbgl_useCaseChoice(&C_Important_Circle_64px,
                       "Warning",
                       "Unverified inputs\nUpdate Ledger Live or\nthird party wallet software",
                       "Continue",
                       "Reject if not sure",
                       start_callback);
}

void ui_display_nondefault_sighash_flow(void) {
    rejected_status = "Transaction rejected";
    nbgl_useCaseChoice(&C_Important_Circle_64px,
                       "Warning",
                       "Non-default sighash",
                       "Continue",
                       "Reject if not sure",
                       start_callback);
}

// Statuses
void ui_display_post_processing(bool success) {
    if (success) {
        nbgl_useCaseStatus(confirmed_status, true, ux_flow_response_true);
    } else {
        nbgl_useCaseStatus(rejected_status, false, ux_flow_response_false);
    }
}
#endif  // HAVE_NBGL
