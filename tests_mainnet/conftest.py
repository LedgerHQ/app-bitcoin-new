import random
import os
from test_utils.fixtures import *

# Make sure that the native client library is used, as speculos would otherwise
# return a version number < 2.0.0 for the app
os.environ['SPECULOS_APPNAME'] = f'Bitcoin:{get_app_version()}'

os.environ["BITCOIN_NETWORK"] = "main"

random.seed(0)  # make sure tests are repeatable
