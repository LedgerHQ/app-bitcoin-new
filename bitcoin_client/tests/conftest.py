from dataclasses import dataclass

import json

from typing import Union

from pathlib import Path

import pytest

from bitcoin_client.client import Client, HIDClient, createClient
from bitcoin_client.common import Chain

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
def comm(request, hid) -> Union[HIDClient, SpeculosClient]:
    if hid:
        client = HIDClient()
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

        try:
            automation_file = request.function.automation_file
        except AttributeError:
            automation_file = None

        if automation_file:
            rules = json.load(open(automation_file))
            client.set_automation_rules(rules)

    yield client

    client.stop()


@pytest.fixture
def is_speculos(comm) -> bool:
    return isinstance(comm, SpeculosClient)


@ pytest.fixture
def client(comm) -> Client:
    return createClient(comm, Chain.TEST, False)


@ dataclass(frozen=True)
class SpeculosGlobals:
    seed = "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"
    # TODO: those are for testnet; we could compute them for any network from the seed
    master_extended_privkey = "tprv8ZgxMBicQKsPfDTA8ufnUdCDy8qXUDnxd8PYWprimNdtVSk4mBMdkAPF6X1cemMjf6LyznfhwbPCsxfiof4BM4DkE8TQtV3HBw2krSqFqHA"
    master_extended_pubkey = "tpubD6NzVbkrYhZ4YgUx2ZLNt2rLYAMTdYysCRzKoLu2BeSHKvzqPaBDvf17GeBPnExUVPkuBpx4kniP964e2MxyzzazcXLptxLXModSVCVEV1T"
    master_key_fingerprint = 0xF5ACC2FD
    master_compressed_pubkey = bytes.fromhex(
        "0251ec84e33a3119486461a44240e906ff94bf40cf807b025b1ca43332b80dc9db"
    )
    wallet_registration_key = bytes.fromhex(
        "7463d6d1a82f4647ead048c625ae0c27fe40b6d0d5f2d24104009ae9d3b7963c"
    )


@ pytest.fixture
def speculos_globals() -> SpeculosGlobals:
    return SpeculosGlobals()
