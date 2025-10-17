import pytest

from ragger.navigator import NavInsID
from ragger.firmware import Firmware

from ragger_bitcoin.ragger_instructions import Instructions, MAX_EXT_OUTPUT_NUMBER


def message_instruction_approve(model: Firmware, save_screenshot=True) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.nano_skip_screen("Path", save_screenshot=save_screenshot)
        instructions.same_request("Sign message", save_screenshot=save_screenshot)
    else:
        instructions.review_message(save_screenshot=save_screenshot)
        instructions.confirm_message(save_screenshot=save_screenshot)

    return instructions


def message_instruction_approve_long(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.nano_skip_screen("Path")
        instructions.same_request("Loading message")
        instructions.new_request("Loading message")
        instructions.new_request("Loading message")
        instructions.new_request("Loading message")
        instructions.new_request("Sign message")
    else:
        instructions.review_message(page_count=5)
        instructions.confirm_message()
    return instructions


def message_instruction_reject(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Reject message")
    else:
        instructions.reject_message()

    return instructions


def pubkey_instruction_approve(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Approve")
    else:
        instructions.choice_confirm()
        instructions.status_dismiss("approved")
    return instructions


def pubkey_instruction_reject_early(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    # It does not make sense for Nano devices
    # as with them it is possible to reject only on the
    # last step.
    if model.name.startswith("nano"):
        pytest.skip()
    else:
        instructions.footer_cancel()
    return instructions


def pubkey_reject(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Cancel")
    else:
        instructions.choice_reject()
        instructions.status_dismiss("rejected", status_on_same_request=False)

    return instructions


def wallet_instruction_approve(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Confirm")
    else:
        instructions.address_confirm()
    return instructions


def register_wallet_instruction_approve(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Register account")
    else:
        instructions.choice_confirm()
        instructions.choice_confirm()
        instructions.choice_confirm()
    return instructions


def register_wallet_instruction_approve_no_save(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Register account", save_screenshot=False)
    else:
        instructions.choice_confirm(save_screenshot=False)
        instructions.choice_confirm(save_screenshot=False)
        instructions.choice_confirm(save_screenshot=False)
    return instructions


def register_wallet_instruction_approve_long(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Register account")
    else:
        instructions.choice_confirm()
        instructions.choice_confirm()
        instructions.choice_confirm()
        instructions.choice_confirm()
    return instructions


def register_wallet_instruction_approve_unusual(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Register account")
    else:
        instructions.choice_confirm()
        instructions.choice_confirm()
    return instructions


def register_wallet_instruction_reject(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Reject operation")
    else:
        instructions.choice_reject()
        instructions.status_dismiss("rejected", status_on_same_request=False)

    return instructions


def sign_psbt_instruction_tap(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        return instructions

    instructions.review_start(save_screenshot=False)
    return instructions


def sign_psbt_instruction_approve(model: Firmware, save_screenshot: bool = True, *, has_spend_from_wallet: bool = False, to_on_next_page: bool = False, fees_on_next_page: bool = False, has_unverifiedwarning: bool = False, has_sighashwarning: bool = False, has_feewarning: bool = False, has_external_inputs: bool = False) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        funcdict = {
          'new_request': instructions.new_request,
          'same_request': instructions.same_request
        }
        which_func = 'new_request'

        if has_sighashwarning:
            # This transaction uses non-standard signing rules- actually clicking "Continue anyway"
            funcdict[which_func]("Continue anyway", save_screenshot=save_screenshot)
            which_func = 'same_request'

        if has_external_inputs:
            # This transaction has external inputs- actually clicking "Continue anyway"
            funcdict[which_func]("Continue anyway", save_screenshot=save_screenshot)
            which_func = 'same_request'

        if has_unverifiedwarning:
            # Non-default sighash - actually clicking "Continue anyway"
            funcdict[which_func]("Continue anyway", save_screenshot=save_screenshot)
            which_func = 'same_request'

        funcdict[which_func]("Sign transaction", save_screenshot=save_screenshot)
    else:
        funcdict = {
          'new_request': instructions.new_request,
          'same_request': instructions.same_request
        }
        which_func = 'new_request'

        if has_sighashwarning:
            # This transaction uses non-standard signing rules- actually clicking "Continue anyway"
            instructions.choice_reject("Continue anyway")
            which_func = 'same_request'

        if has_external_inputs:
            # This transaction has external inputs- actually clicking "Continue anyway"
            instructions.choice_reject("Continue anyway")
            which_func = 'same_request'

        if has_unverifiedwarning:
            # Non-default sighash - actually clicking "Continue anyway"
            instructions.choice_reject("Continue anyway")
            which_func = 'same_request'

        funcdict[which_func]("Review", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                                 save_screenshot=save_screenshot)
        which_func = 'same_request'

        funcdict[which_func]("Amount", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                                  save_screenshot=save_screenshot)
        if to_on_next_page:
            funcdict[which_func]("To", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                                      save_screenshot=save_screenshot)
        if fees_on_next_page:
            funcdict[which_func]("Fees", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                                      save_screenshot=save_screenshot)
        if has_feewarning:
            funcdict[which_func](
                "High fees warning", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP, save_screenshot=save_screenshot)
        instructions.confirm_transaction(save_screenshot=save_screenshot)
    return instructions


def sign_psbt_instruction_approve_selftransfer(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Sign transaction")
    else:
        instructions.new_request(
            "Review", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP)
        instructions.same_request(
            "Amount", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP)
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_streaming(model: Firmware, output_count: int, save_screenshot: bool = True) -> Instructions:
    instructions = Instructions(model)
    if (output_count <= MAX_EXT_OUTPUT_NUMBER):
        return sign_psbt_instruction_approve(model, save_screenshot, has_feewarning = True);

    if model.name.startswith("nano"):
        instructions.new_request("Loading transaction")
        instructions.new_request("Sign transaction", save_screenshot=save_screenshot)
    else:
        instructions.review_start(
            output_count=output_count, save_screenshot=save_screenshot)
        instructions.review_fees(save_screenshot=save_screenshot)
        instructions.confirm_transaction(save_screenshot=save_screenshot)
    return instructions


def e2e_register_wallet_instruction(model: Firmware, n_keys) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Register account", save_screenshot=False)
    else:
        for _ in range(n_keys + 1):
            instructions.choice_confirm(save_screenshot=False)
            instructions.choice_confirm(save_screenshot=False)
    return instructions


def e2e_sign_psbt_instruction(model: Firmware) -> Instructions:
    return sign_psbt_instruction_approve(model, save_screenshot=False, has_spend_from_wallet=True)
