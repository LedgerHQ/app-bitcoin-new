from ragger.firmware import Firmware
from ragger.navigator import NavInsID, Navigator
from pathlib import Path

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()


def test_dashboard(navigator: Navigator, firmware: Firmware, test_name: str):
    # Tests that the text shown in the dashboard screens are the expected ones

    if firmware.device.startswith("nano"):
        instructions = [
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK
        ]
    else:
        instructions = [
            NavInsID.USE_CASE_HOME_INFO,
            NavInsID.USE_CASE_SETTINGS_SINGLE_PAGE_EXIT
        ]

    navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions,
                                   screen_change_before_first_instruction=False)
