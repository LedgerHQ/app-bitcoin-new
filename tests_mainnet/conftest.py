import random
import os
from test_utils.fixtures import *

os.environ["BITCOIN_NETWORK"] = "main"

random.seed(0)  # make sure tests are repeatable
