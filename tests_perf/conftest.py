
from pathlib import Path
from test_utils.fixtures import *
import random
import sys
import os

absolute_path = os.path.dirname(os.path.abspath(__file__))
relative_bitcoin_path = ('../bitcoin_client')
absolute_bitcoin_client_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '../')
sys.path.append(os.path.join(absolute_path, relative_bitcoin_path))

from ledger_bitcoin import Chain  # noqa: E402

TESTS_ROOT_DIR = Path(__file__).parent

random.seed(0)  # make sure tests are repeatable
