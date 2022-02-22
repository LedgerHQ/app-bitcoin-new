import pytest

from speculos.client import SpeculosClient


def test_dashboard(comm: SpeculosClient, is_speculos: bool, app_version: str):
    # Tests that the text shown in the dashboard screens are the expected ones

    if not is_speculos:
        pytest.skip("Requires speculos")

    comm.press_and_release("right")
    comm.wait_for_text_event("Version")
    comm.wait_for_text_event(app_version)

    comm.press_and_release("right")
    comm.wait_for_text_event("About")

    comm.press_and_release("right")
    comm.wait_for_text_event("Quit")

    comm.press_and_release("right")
    comm.wait_for_text_event("Bitcoin")
    comm.wait_for_text_event("is ready")
