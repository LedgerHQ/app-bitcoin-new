import sys
import os

absolute_path = os.path.dirname(os.path.abspath(__file__))
relative_bitcoin_path = ('../bitcoin_client')
absolute_bitcoin_client_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../')
sys.path.append(os.path.join(absolute_path, relative_bitcoin_path))

import random
from typing import Tuple

from test_utils.fixtures import *
from test_utils.authproxy import AuthServiceProxy, JSONRPCException
from test_utils import segwit_addr

import shutil
import subprocess
from time import sleep
from decimal import Decimal
from pathlib import Path

from ledger_bitcoin import Chain
from ledger_bitcoin.common import sha256
import ledger_bitcoin._base58 as base58

from ragger.conftest import configuration
from ragger.backend.interface import BackendInterface
from ragger.backend import RaisePolicy
from ragger_bitcoin import createRaggerClient, RaggerClient

###########################
### CONFIGURATION START ###
###########################

# You can configure optional parameters by overriding the value of ragger.configuration.OPTIONAL_CONFIGURATION
# Please refer to ragger/conftest/configuration.py for their descriptions and accepted values

MNEMONIC = "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"
configuration.OPTIONAL.CUSTOM_SEED = MNEMONIC
configuration.OPTIONAL.BACKEND_SCOPE = "function"


#########################
### CONFIGURATION END ###
#########################
TESTS_ROOT_DIR = Path(__file__).parent

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest", )

random.seed(0)  # make sure tests are repeatable

# Make sure that the native client library is used with, as speculos would otherwise
# return a version number < 2.0.0 for the app
os.environ['SPECULOS_APPNAME'] = f'Bitcoin Test:{get_app_version()}'


BITCOIN_DIRNAME = os.getenv("BITCOIN_DIRNAME", "tests/.test_bitcoin")


rpc_url = "http://%s:%s@%s:%s" % (
    os.getenv("BTC_RPC_USER", "user"),
    os.getenv("BTC_RPC_PASSWORD", "passwd"),
    os.getenv("BTC_RPC_HOST", "127.0.0.1"),
    os.getenv("BTC_RPC_PORT", "18443")
)

utxos = list()
btc_addr = ""


def get_rpc() -> AuthServiceProxy:
    return AuthServiceProxy(rpc_url)


def get_wallet_rpc(wallet_name: str) -> AuthServiceProxy:
    return AuthServiceProxy(f"{rpc_url}/wallet/{wallet_name}")


def setup_node():
    global btc_addr

    # Check bitcoind is running while generating the address
    while True:
        rpc = get_rpc()
        try:
            print(rpc.createwallet(wallet_name="test_wallet", descriptors=True))
            btc_addr = rpc.getnewaddress()
            break

        except ConnectionError as e:
            sleep(1)
        except JSONRPCException as e:
            if "Loading wallet..." in str(e):
                sleep(1)

    # Mine enough blocks so coinbases are mature and we have enough funds to run everything
    rpc.generatetoaddress(105, btc_addr)


@pytest.fixture(scope="session")
def run_bitcoind():
    # Run bitcoind in a separate folder
    os.makedirs(BITCOIN_DIRNAME, exist_ok=True)

    bitcoind = os.getenv("BITCOIND", "/bitcoin/bin/bitcoind")

    shutil.copy(os.path.join(os.path.dirname(__file__), "bitcoin.conf"), BITCOIN_DIRNAME)
    subprocess.Popen([bitcoind, f"--datadir={BITCOIN_DIRNAME}"])

    # Make sure the node is ready, and generate some initial blocks
    setup_node()

    yield

    rpc = get_rpc()
    rpc.stop()

    shutil.rmtree(BITCOIN_DIRNAME)


@pytest.fixture(scope="session")
def rpc(run_bitcoind):
    return get_rpc()


@pytest.fixture(scope="session")
def rpc_test_wallet(run_bitcoind):
    return get_wallet_rpc("test_wallet")


def get_utxo():
    rpc = get_rpc()
    global utxos
    if not utxos:
        utxos = rpc.listunspent()

    if len(utxos) == 0:
        raise ValueError("There are no UTXOs.")

    utxo = utxos.pop(0)
    while utxo.get("amount") < Decimal("0.00002"):
        utxo = utxos.pop(0)

    return utxo


def seed_to_wif(seed: bytes):
    assert len(seed) == 32

    double_sha256 = sha256(sha256(b"\x80" + seed))
    return base58.encode(b"\x80" + seed + double_sha256[:4])


wallet_count = 0


def get_unique_wallet_name() -> str:
    global wallet_count

    result = f"mywallet-{wallet_count}"

    wallet_count += 1

    return result


def create_new_wallet() -> Tuple[str, str]:
    """Creates a new descriptor-enabled wallet in bitcoin-core. Each new wallet has an increasing counter as
    part of it's name in order to avoid conflicts. Returns the wallet name and the xpub (dropping the key origin
    information)."""

    wallet_name = get_unique_wallet_name()

    # TODO: derive seed from wallet_count, and use it to create a descriptor wallet (how?)
    #       this would help to have repeatable tests, generating always the same seeds

    get_rpc().createwallet(wallet_name=wallet_name, descriptors=True)
    wallet_rpc = get_wallet_rpc(wallet_name)

    all_descriptors = wallet_rpc.listdescriptors()["descriptors"]
    descriptor: str = next(filter(lambda d: d["desc"].startswith(
        "pkh") and "/0/*" in d["desc"], all_descriptors))["desc"]

    core_xpub_orig = descriptor[descriptor.index("(")+1: descriptor.index("/0/*")]
    core_xpub = core_xpub_orig[core_xpub_orig.find("]") + 1:]

    return wallet_name, core_xpub


def generate_blocks(n):
    return get_rpc().generatetoaddress(n, btc_addr)


def testnet_to_regtest_addr(addr: str) -> str:
    """Convenience function to reencode addresses from testnet format to regtest one (bech32 prefix is different)"""
    hrp, data, spec = segwit_addr.bech32_decode(addr)
    if hrp is None:
        return addr  # bech32m decoding failed; either legacy/unknown address type, or invalid address
    if (hrp != "tb"):
        raise ValueError("Not a valid testnet bech32m string")
    return segwit_addr.bech32_encode("bcrt", data, spec)


@pytest.fixture
def client(bitcoin_network: str, backend: BackendInterface) -> RaggerClient:
    if bitcoin_network == "main":
        chain = Chain.MAIN
    elif bitcoin_network == "test":
        chain = Chain.TEST
    else:
        raise ValueError(
            f'Invalid value for BITCOIN_NETWORK: {bitcoin_network}')

    backend.raise_policy = RaisePolicy.RAISE_CUSTOM
    backend.whitelisted_status = [0x9000, 0xE000]
    return createRaggerClient(backend, chain=chain, debug=True, screenshot_dir=TESTS_ROOT_DIR)
