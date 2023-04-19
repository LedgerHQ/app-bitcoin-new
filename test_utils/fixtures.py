import pytest

from pathlib import Path
import re
import os
import json
from typing import Literal, Union

from . import default_settings, SpeculosGlobals

from bitcoin_client.ledger_bitcoin import TransportClient, Client, Chain, createClient

from speculos.client import SpeculosClient

"""
This module contains fixtures that are shared among several of the test suites.
The behavior of the fixtures can be altered by setting the following environment variables:

BITCOIN_NETWORK: "test" for testnet, "main" for mainnet. Default: "test"

BITCOIN_APP_BINARY: the full path and file name of the app's binary to use. Defaults to {repo_root_path}/bin/app.elf

BITCOIN_APP_LIB_BINARY: the full path and file name of binary to use as Bitcoin library in speculos.
                        If omitted no library is used in speculos.
"""


# root of the repository
repo_root_path: Path = Path(__file__).parent.parent

# path of the folder of the currently running test

ASSIGNMENT_RE = re.compile(
    r'^\s*([a-zA-Z_][a-zA-Z_0-9]*)\s*=\s*(.*)$', re.MULTILINE)


def get_app_version() -> str:
    makefile_path = repo_root_path / "Makefile"
    if not makefile_path.is_file():
        raise FileNotFoundError(f"Can't find file: '{makefile_path}'")

    makefile: str = makefile_path.read_text()

    assignments = {
        identifier: value for identifier, value in ASSIGNMENT_RE.findall(makefile)
    }

    return f"{assignments['APPVERSION_M']}.{assignments['APPVERSION_N']}.{assignments['APPVERSION_P']}"


def pytest_addoption(parser):
    parser.addoption("--hid", action="store_true")
    parser.addoption("--headless", action="store_true")
    parser.addoption("--enableslowtests", action="store_true")
    parser.addoption("--model", action="store", default="nanos")


@pytest.fixture(scope="module")
def sw_h_path():
    # sw.h should be in src/boilerplate/sw.h
    sw_h_path = repo_root_path / "src" / "boilerplate" / "sw.h"

    if not sw_h_path.is_file():
        raise FileNotFoundError(f"Can't find sw.h: '{sw_h_path}'")

    return sw_h_path


@pytest.fixture(scope="module")
def app_version() -> str:
    return get_app_version()


@pytest.fixture
def settings(request) -> dict:
    try:
        return request.function.test_settings
    except AttributeError:
        return default_settings.copy()


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
def model(pytestconfig):
    return pytestconfig.getoption("model")


@pytest.fixture(scope='session', autouse=True)
def root_directory(request):
    return Path(str(request.config.rootdir))


@pytest.fixture
def comm(settings, root_directory, hid, headless, model, app_version: str) -> Union[TransportClient, SpeculosClient]:
    if hid:
        client = TransportClient("hid")
    else:
        # We set the app's name before running speculos in order to emulate the expected
        # behavior of the SDK's GET_VERSION default APDU.
        # The app name is 'Bitcoin' or 'Bitcoin Test' for mainnet/testnet respectively.
        # We leave the speculos default 'app' to avoid relying on that value in tests.

        if not os.getenv("SPECULOS_APPNAME"):
            os.environ['SPECULOS_APPNAME'] = f'app:{app_version}'

        app_binary = os.getenv("BITCOIN_APP_BINARY", str(
            repo_root_path.joinpath("bin/app.elf")))

        app_lib_binary = os.getenv("BITCOIN_APP_LIB_BINARY", None)
        if app_lib_binary:
            lib_params = ['-l', f"Bitcoin:{app_lib_binary}"]

        else:
            lib_params = []

        client = SpeculosClient(
            app_binary,
            ['--model', model, '--seed', f'{settings["mnemonic"]}']
            + ["--display", "qt" if not headless else "headless"]
            + lib_params
        )
        client.start()

        if settings["automation_file"]:
            automation_file = root_directory.joinpath(
                settings["automation_file"])
            rules = json.load(open(automation_file))
            client.set_automation_rules(rules)

    yield client

    client.stop()


@pytest.fixture
def is_speculos(comm: Union[TransportClient, SpeculosClient]) -> bool:
    return isinstance(comm, SpeculosClient)


@pytest.fixture
def bitcoin_network() -> Union[Literal['main'], Literal['test']]:
    network = os.getenv("BITCOIN_NETWORK", "test")
    if network not in ["main", "test"]:
        raise ValueError(
            f'Invalid value for BITCOIN_NETWORK: {network}')
    return network


@pytest.fixture
def client(bitcoin_network: str, comm: Union[TransportClient, SpeculosClient]) -> Client:
    if bitcoin_network == "main":
        chain = Chain.MAIN
    elif bitcoin_network == "test":
        chain = Chain.TEST
    else:
        raise ValueError(
            f'Invalid value for BITCOIN_NETWORK: {bitcoin_network}')
    return createClient(comm, chain=chain, debug=True)


@pytest.fixture
def speculos_globals(settings: dict, bitcoin_network: str) -> SpeculosGlobals:

    return SpeculosGlobals(mnemonic=settings["mnemonic"], network=bitcoin_network)
