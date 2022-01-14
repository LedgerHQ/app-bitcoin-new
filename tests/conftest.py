from dataclasses import dataclass

import json

from typing import Union

from pathlib import Path

import pytest

from mnemonic import Mnemonic
from bip32 import BIP32

from bitcoin_client.ledger_bitcoin import TransportClient, Client, Chain, createClient
from bitcoin_client.ledger_bitcoin.common import hash160
from utils.slip21 import Slip21Node

from speculos.client import SpeculosClient

import os
import re

import random

mnemo = Mnemonic("english")

random.seed(0)  # make sure tests are repeatable

# path with tests
conftest_folder_path: Path = Path(__file__).parent

DEFAULT_SPECULOS_SEED = "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"

WALLET_POLICY_SLIP21_LABEL = b"LEDGER-Wallet policy"


ASSIGNMENT_RE = re.compile(r'^\s*([a-zA-Z_][a-zA-Z_0-9]*)\s*=\s*(.*)$', re.MULTILINE)


def get_app_version() -> str:
    makefile_path = conftest_folder_path.parent / "Makefile"
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


@pytest.fixture(scope="module")
def sw_h_path():
    # sw.h should be in src/boilerplate/sw.h
    sw_h_path = conftest_folder_path.parent / "src" / "boilerplate" / "sw.h"

    if not sw_h_path.is_file():
        raise FileNotFoundError(f"Can't find sw.h: '{sw_h_path}'")

    return sw_h_path


@pytest.fixture(scope="module")
def app_version() -> str:
    return get_app_version()


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
def comm(request, hid, app_version: str) -> Union[TransportClient, SpeculosClient]:
    if hid:
        client = TransportClient("hid")
    else:
        # We set the app's name before running speculos in order to emulate the expected
        # behavior of the SDK's GET_VERSION default APDU.
        # The app name is 'Bitcoin' or 'Bitcoin Test' for mainnet/testnet respectively.
        # We leave the speculos default 'app' to avoid relying on that value in tests.
        os.environ['SPECULOS_APPNAME'] = f'app:{app_version}'
        client = SpeculosClient(
            str(conftest_folder_path.parent.joinpath("bin/app.elf")),
            ['--sdk', '2.1']
        )
        client.start()

        try:
            automation_file = conftest_folder_path.joinpath(request.function.automation_file)
        except AttributeError:
            automation_file = None

        if automation_file:
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


class SpeculosGlobals:
    def __init__(self, network: str = "test"):
        self.mnemonic = DEFAULT_SPECULOS_SEED
        self.seed = mnemo.to_seed(self.mnemonic)
        bip32 = BIP32.from_seed(self.seed, network)
        self.master_extended_privkey = bip32.get_xpriv()
        self.master_extended_pubkey = bip32.get_xpub()
        self.master_key_fingerprint = int.from_bytes(hash160(bip32.pubkey)[0:4], byteorder="big")
        self.master_compressed_pubkey = bip32.pubkey.hex()
        slip21_root = Slip21Node.from_seed(self.seed)
        self.wallet_registration_key = slip21_root.derive_child(WALLET_POLICY_SLIP21_LABEL).key


@pytest.fixture
def speculos_globals() -> SpeculosGlobals:
    return SpeculosGlobals()
