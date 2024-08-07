from ragger.navigator import NavInsID
from ragger.firmware import Firmware

from ragger_bitcoin.ragger_instructions import Instructions


def message_instruction_approve(model: Firmware, save_screenshot=True) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.nano_skip_screen("Path", save_screenshot=save_screenshot)
        instructions.same_request("Sign", save_screenshot=save_screenshot)
    else:
        instructions.review_message(save_screenshot=save_screenshot)
        instructions.confirm_message(save_screenshot=save_screenshot)

    return instructions


def message_instruction_approve_long(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.nano_skip_screen("Path")
        instructions.same_request("Processing")
        instructions.new_request("Processing")
        instructions.new_request("Processing")
        instructions.new_request("Processing")
        instructions.new_request("Sign")
    else:
        instructions.review_message(page_count=5)
        instructions.confirm_message()
    return instructions


def message_instruction_reject(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Reject")
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

    if model.name.startswith("nano"):
        instructions.new_request("Reject")
    else:
        instructions.footer_cancel()
    return instructions


def pubkey_reject(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.nano_skip_screen("Reject")
        instructions.same_request("Reject")
    else:
        instructions.choice_reject()
        instructions.status_dismiss("rejected", status_on_same_request=False)

    return instructions


def wallet_instruction_approve(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Approve")
    else:
        instructions.address_confirm()
    return instructions


def register_wallet_instruction_approve(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Approve")
        instructions.same_request("Approve")
        instructions.same_request("Approve")
    else:
        instructions.choice_confirm()
        instructions.choice_confirm()
        instructions.choice_confirm()
    return instructions


def register_wallet_instruction_approve_long(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Approve")
        instructions.same_request("Approve")
        instructions.same_request("Approve")
        instructions.same_request("Approve")
    else:
        instructions.choice_confirm()
        instructions.choice_confirm()
        instructions.choice_confirm()
        instructions.choice_confirm()
    return instructions


def register_wallet_instruction_approve_unusual(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Approve")
        instructions.same_request("Approve")
    else:
        instructions.choice_confirm()
        instructions.choice_confirm()
    return instructions


def register_wallet_instruction_reject(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Reject")
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


def sign_psbt_instruction_approve(model: Firmware, save_screenshot: bool = True, *, has_spend_from_wallet: bool = False, to_on_next_page: bool = False, fees_on_next_page: bool = False, has_unverifiedwarning: bool = False, has_sighashwarning: bool = False, has_feewarning: bool = False) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue", save_screenshot=save_screenshot)
        for has_step in [has_spend_from_wallet, has_unverifiedwarning, has_sighashwarning, has_feewarning]:
            if has_step:
                instructions.same_request(
                    "Continue", save_screenshot=save_screenshot)

        instructions.same_request("Sign", save_screenshot=save_screenshot)
    else:
        instructions.new_request("Review", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                                 save_screenshot=save_screenshot)
        if has_sighashwarning:
            instructions.same_request(
                "Non-default sighash", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP, save_screenshot=save_screenshot)

        if has_unverifiedwarning:
            instructions.same_request(
                "Unverified inputs", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP, save_screenshot=save_screenshot)

        instructions.same_request("Amount", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                                  save_screenshot=save_screenshot)
        if to_on_next_page:
            instructions.same_request("To", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                                      save_screenshot=save_screenshot)
        if fees_on_next_page:
            instructions.same_request("Fees", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP,
                                      save_screenshot=save_screenshot)

        if has_feewarning:
            instructions.same_request(
                "Fees are above", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP, save_screenshot=save_screenshot)
        instructions.confirm_transaction(save_screenshot=save_screenshot)
    return instructions


def sign_psbt_instruction_approve_selftransfer(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Sign")
    else:
        instructions.new_request(
            "Review", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP)
        instructions.same_request(
            "Amount", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP)
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_streaming(model: Firmware, output_count: int, save_screenshot: bool = True) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue")  # first output
        for output_index in range(1, output_count):
            if output_index < 2:
                instructions.same_request("Continue")
            else:
                instructions.new_request("Continue")
        instructions.same_request("Sign", save_screenshot=save_screenshot)
    else:
        instructions.review_start(
            output_count=output_count, save_screenshot=save_screenshot)
        instructions.review_fees(save_screenshot=save_screenshot)
        instructions.confirm_transaction(save_screenshot=save_screenshot)
    return instructions


def sign_psbt_instruction_approve_external_inputs(model: Firmware, output_count) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue")
        for output_index in range(output_count):
            if output_index < 2:
                instructions.same_request("Continue")
            else:
                instructions.new_request("Continue")
        instructions.same_request("Sign")
    else:
        instructions.review_start(output_count=output_count, has_warning=True)
        instructions.review_fees(fees_on_same_request=True)
        instructions.confirm_transaction()
    return instructions


def e2e_register_wallet_instruction(model: Firmware, n_keys) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Approve", save_screenshot=False)
        for _ in range(n_keys):
            instructions.same_request("Approve", save_screenshot=False)
    else:
        for _ in range(n_keys + 1):
            instructions.choice_confirm(save_screenshot=False)
            instructions.choice_confirm(save_screenshot=False)
    return instructions


def e2e_sign_psbt_instruction(model: Firmware) -> Instructions:
    return sign_psbt_instruction_approve(model, save_screenshot=False, has_spend_from_wallet=True)
