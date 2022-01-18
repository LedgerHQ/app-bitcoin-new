import json

from typing import Union

from pathlib import Path

import pytest

from test_utils import SpeculosGlobals, default_settings

from ledger_bitcoin import Client, Chain, TransportClient, createClient

from speculos.client import SpeculosClient

import os
import re

# path with tests
conftest_folder_path: Path = Path(__file__).parent


ASSIGNMENT_RE = re.compile(r'^\s*([a-zA-Z_][a-zA-Z_0-9]*)\s*=\s*(.*)$', re.MULTILINE)


def pytest_addoption(parser):
    parser.addoption("--hid", action="store_true")
    parser.addoption("--headless", action="store_true")


@pytest.fixture
def hid(pytestconfig):
    return pytestconfig.getoption("hid")


@pytest.fixture
def headless(pytestconfig):
    return pytestconfig.getoption("headless")


@pytest.fixture
def enable_slow_tests(pytestconfig):
    return pytestconfig.getoption("enableslowtests")


@pytest.fixture
def settings(request) -> dict:
    try:
        return request.function.test_settings
    except AttributeError:
        return default_settings.copy()


@pytest.fixture
def comm(settings, hid) -> Union[TransportClient, SpeculosClient]:
    if hid:
        client = TransportClient("hid")
    else:
        os.environ['SPECULOS_APPNAME'] = 'Bitcoin Test:1.6.5'
        client = SpeculosClient(
            str(conftest_folder_path.joinpath("app-binaries/bitcoin-testnet-1.6.5.elf")),
            [
                '-l', f"Bitcoin:{str(conftest_folder_path.joinpath('app-binaries/bitcoin-1.6.5.elf'))}",
                '--sdk', '2.1'
            ]
        )
        client.start()

        if settings["automation_file"]:
            automation_file = conftest_folder_path.joinpath(settings["automation_file"])
            rules = json.load(open(automation_file))
            client.set_automation_rules(rules)

    yield client

    client.stop()


@pytest.fixture
def is_speculos(comm: Union[TransportClient, SpeculosClient]) -> bool:
    return isinstance(comm, SpeculosClient)


@pytest.fixture
def client(comm: Union[TransportClient, SpeculosClient]) -> Client:
    return createClient(comm, chain=Chain.TEST, debug=True)


@pytest.fixture
def speculos_globals(settings) -> SpeculosGlobals:
    return SpeculosGlobals(mnemonic=settings["mnemonic"])
