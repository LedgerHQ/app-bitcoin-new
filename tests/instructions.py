from ragger.navigator import NavInsID
from ragger.firmware import Firmware

from ragger_bitcoin.ragger_instructions import Instructions


def message_instruction_approve(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.nano_skip_screen("Path")
        instructions.same_request("Sign")
    else:
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
        instructions.navigate_end_of_flow()
        instructions.navigate_end_of_flow()
        instructions.navigate_end_of_flow()
        instructions.navigate_end_of_flow()
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

    return instructions


def sign_psbt_instruction_tap(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        return instructions

    instructions.navigate_end_of_flow()
    return instructions


def sign_psbt_instruction_approve(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue")
        instructions.same_request("Sign")
    else:
        instructions.navigate_end_of_flow()
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_2(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue")
        instructions.new_request("Sign")
    else:
        instructions.navigate_end_of_flow()
        instructions.navigate_end_of_flow()
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_3(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.same_request("Sign")
    else:
        instructions.navigate_end_of_flow()
        instructions.navigate_end_of_flow()
        instructions.warning_accept()
        instructions.same_request_confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_4(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.same_request("Sign")
    else:
        instructions.warning_accept()
        instructions.navigate_end_of_flow()
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_5(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Sign")
    else:
        instructions.navigate_end_of_flow()
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
        instructions.navigate_end_of_flow()
        instructions.navigate_end_of_flow()
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
        instructions.navigate_end_of_flow()
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
        instructions.navigate_end_of_flow()
        instructions.confirm_transaction()
    return instructions


def sign_psbt_instruction_approve_9(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue")
        instructions.new_request("Continue")
        instructions.same_request("Sign")
    else:
        instructions.navigate_end_of_flow()
        instructions.navigate_end_of_flow()
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
        instructions.navigate_end_of_flow()
        instructions.navigate_end_of_flow()
        instructions.navigate_end_of_flow()
        instructions.navigate_end_of_flow()
        instructions.navigate_end_of_flow()
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
        instructions.navigate_end_of_flow()
        instructions.navigate_end_of_flow()
        instructions.navigate_end_of_flow()
        instructions.navigate_end_of_flow()
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
        instructions.navigate_end_of_flow()
        instructions.navigate_end_of_flow()
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
    return instructions


def e2e_sign_psbt_instruction(model: Firmware) -> Instructions:
    instructions = Instructions(model)

    if model.name.startswith("nano"):
        instructions.new_request("Continue", save_screenshot=False)
        instructions.new_request("Continue", save_screenshot=False)
        instructions.new_request("Sign", save_screenshot=False)
    else:
        instructions.confirm_wallet(save_screenshot=False)
        instructions.navigate_end_of_flow(save_screenshot=False)
        instructions.navigate_end_of_flow(save_screenshot=False)
        instructions.confirm_transaction(save_screenshot=False)
    return instructions
