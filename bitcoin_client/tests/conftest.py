import random
import os
from test_utils.fixtures import *

random.seed(0)  # make sure tests are repeatable

# path with tests
conftest_folder_path: Path = Path(__file__).parent

os.environ['SPECULOS_APPNAME'] = 'Bitcoin Test:1.6.5'
os.environ["BITCOIN_APP_BINARY"] = str(conftest_folder_path.joinpath("app-binaries/bitcoin-testnet-1.6.5.elf"))
os.environ["BITCOIN_APP_LIB_BINARY"] = str(conftest_folder_path.joinpath('app-binaries/bitcoin-1.6.5.elf'))
