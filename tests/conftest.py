from pathlib import Path

import pytest

from ledgercomm import Transport

from boilerplate_client.boilerplate_cmd import BoilerplateCommand
from boilerplate_client.button import ButtonTCP, ButtonFake


def pytest_addoption(parser):
    parser.addoption("--hid",
                     action="store_true")
    parser.addoption("--headless",
                     action="store_true")


@pytest.fixture(scope="module")
def sw_h_path():
    # path with tests
    conftest_folder_path: Path = Path(__file__).parent
    # sw.h should be in src/sw.h
    sw_h_path = conftest_folder_path.parent / "src" / "sw.h"

    if not sw_h_path.is_file():
        raise FileNotFoundError(f"Can't find sw.h: '{sw_h_path}'")

    return sw_h_path


@pytest.fixture(scope="session")
def hid(pytestconfig):
    return pytestconfig.getoption("hid")


@pytest.fixture(scope="session")
def headless(pytestconfig):
    return pytestconfig.getoption("headless")


@pytest.fixture(scope="module")
def button(headless):
    if headless:
        button_client = ButtonTCP(server="127.0.0.1", port=42000)
    else:
        button_client = ButtonFake()

    yield button_client

    button_client.close()


@pytest.fixture(scope="session")
def cmd(hid):
    transport = (Transport(interface="hid", debug=True)
                 if hid else Transport(interface="tcp",
                                       server="127.0.0.1",
                                       port=9999,
                                       debug=True))
    command = BoilerplateCommand(
        transport=transport,
        debug=True
    )

    yield command

    command.transport.close()
