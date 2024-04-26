from ragger.navigator import NavInsID
from ragger.firmware import Firmware

from ragger_bitcoin.ragger_instructions import Instructions


def message_instruction_approve(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.nano_skip_screen("Path")
        instructions.same_request("Sign")
    else:
        instructions.review_message()
        instructions.confirm_message()

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
        instructions.new_request("Approve")
        instructions.new_request("Approve")
    else:
        instructions.choice_confirm()
        instructions.choice_confirm()
        instructions.choice_confirm()
    return instructions


def register_wallet_instruction_approve_long(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Approve")
        instructions.new_request("Approve")
        instructions.new_request("Approve")
        instructions.new_request("Approve")
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
        instructions.new_request("Approve")
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

    instructions.review_start()
    return instructions


def sign_psbt_instruction_approve_opreturn(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue")
        instructions.new_request("Sign")
    else:
        instructions.review_start()
        instructions.same_request("Address", NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_REVIEW_TAP)
        instructions.review_fees(fees_on_same_request=False)
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue")
        instructions.same_request("Sign")
    else:
        instructions.review_start()
        instructions.review_fees()
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_2(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue")
        instructions.new_request("Sign")
    else:
        instructions.review_start()
        instructions.review_fees(fees_on_same_request=False)
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_3(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.same_request("Sign")
    else:
        instructions.review_start()
        instructions.warning_accept()
        instructions.review_fees()
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_4(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.same_request("Sign")
    else:
        instructions.warning_accept()
        instructions.review_start()
        instructions.review_fees()
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_5(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Sign")
    else:
        instructions.review_start()
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_6(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.new_request("Sign")
    else:
        instructions.confirm_wallet()
        instructions.review_start()
        instructions.review_fees(fees_on_same_request=False)
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_7(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.same_request("Sign")
    else:
        instructions.confirm_wallet()
        instructions.review_start()
        instructions.review_fees()
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_8(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.same_request("Sign")
    else:
        instructions.confirm_wallet()
        instructions.warning_accept()
        instructions.review_start()
        instructions.review_fees()
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_9(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.same_request("Sign")
    else:
        instructions.review_start(output_count=2)
        instructions.review_fees()
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_external_inputs(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.same_request("Sign")
    else:
        instructions.warning_accept()
        instructions.review_start(output_count=5)
        instructions.review_fees()
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_external_inputs_2(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.same_request("Sign")
    else:
        instructions.warning_accept()
        instructions.review_start(output_count=4)
        instructions.review_fees()
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_10(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.new_request("Sign")
    else:
        instructions.warning_accept()
        instructions.review_start()
        instructions.review_fees(fees_on_same_request=False)
        instructions.confirm_transaction()
    return instructions


def e2e_register_wallet_instruction(model: Firmware, n_keys) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        for _ in range(n_keys + 1):
            instructions.new_request("Approve", save_screenshot=False)
    else:
        for _ in range(n_keys + 1):
            instructions.choice_confirm(save_screenshot=False)
            instructions.choice_confirm(save_screenshot=False)
    return instructions


def e2e_sign_psbt_instruction(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue", save_screenshot=False)
        instructions.new_request("Continue", save_screenshot=False)
        instructions.new_request("Sign", save_screenshot=False)
    else:
        instructions.confirm_wallet(save_screenshot=False)
        instructions.review_start(save_screenshot=False)
        instructions.review_fees(fees_on_same_request=False, save_screenshot=False)
        instructions.confirm_transaction(save_screenshot=False)
    return instructions
