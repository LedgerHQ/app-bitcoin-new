import subprocess
import os
import socket
import time
from dataclasses import dataclass

from pathlib import Path

import pytest

from ledgercomm import Transport

from bitcoin_client.command import BitcoinCommand
from bitcoin_client.button import ButtonTCP, ButtonFake


def pytest_addoption(parser):
    parser.addoption("--hid",
                     action="store_true")
    parser.addoption("--headless",
                     action="store_true")


@pytest.fixture(scope="module")
def sw_h_path():
    # path with tests
    conftest_folder_path: Path = Path(__file__).parent
    # sw.h should be in src/boilerplate/sw.h
    sw_h_path = conftest_folder_path.parent / "src" / "boilerplate" / "sw.h"

    if not sw_h_path.is_file():
        raise FileNotFoundError(f"Can't find sw.h: '{sw_h_path}'")

    return sw_h_path


@pytest.fixture
def hid(pytestconfig):
    return pytestconfig.getoption("hid")


@pytest.fixture
def headless(pytestconfig):
    return pytestconfig.getoption("headless")


@pytest.fixture
def button(headless):
    if headless:
        button_client = ButtonTCP(server="127.0.0.1", port=42000)
    else:
        button_client = ButtonFake()

    yield button_client

    button_client.close()


@pytest.fixture
def device(request, hid):
    # If running on real hardware, nothing to do here
    if hid:
        yield
        return

    # Gets the speculos executable from the SPECULOS environment variable,
    # or hopes that "speculos.py" is in the $PATH if not set
    speculos_executable = os.environ.get("SPECULOS", "speculos.py")

    base_args = [
        speculos_executable, "../bin/app.elf",
        "--sdk", "2.0",
        # "--display", "headless"
    ]

    # Look for the automation_file attribute in the test function, if present
    try:
        automation_args = ["--automation", f"file:{request.function.automation_file}"]
    except AttributeError:
        automation_args = []

    speculos_proc = subprocess.Popen([*base_args, *automation_args])


    # Attempts to connect to speculos to make sure that it's ready when the test starts
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", 9999), timeout=1.0)
            connected = True
            break
        except ConnectionRefusedError:
            time.sleep(0.1)
            connected = False

    if not connected:
        raise RuntimeError("Unable to connect to speculos.")

    yield

    speculos_proc.terminate()
    speculos_proc.wait()


@pytest.fixture
def transport(device, hid):
    transport = (Transport(interface="hid", debug=True)
                 if hid else Transport(interface="tcp",
                                       server="127.0.0.1",
                                       port=9999,
                                       debug=True))
    yield transport
    transport.close()

@pytest.fixture
def cmd(transport):
    return BitcoinCommand(transport=transport, debug=False)

@dataclass(frozen=True)
class SpeculosGlobals:
    seed = "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"
    master_extended_privkey = "xprv9s21ZrQH143K4QDdULpHJyaEf1RKEhkxHaUReQSGHQ9Qhqzymp1tER1oBLqxePyRHepCzh3wnEoQR77ygSiEXzx9hVF7E8KEGqHLQqEmF9v"
    master_extended_pubkey = "xpub661MyMwAqRbcGtJ6aNMHg7WyD3FoeAUoeoQ2SnqsqjgPaeL8KML8nDLH2c6cFk1EhVDzaFSCDgtLSua2dW7k7Z8hYvbXDRgHmr32jBV1S12"
    master_compressed_pubkey = bytes.fromhex("0251ec84e33a3119486461a44240e906ff94bf40cf807b025b1ca43332b80dc9db")


@pytest.fixture
def speculos_globals():
    return SpeculosGlobals()