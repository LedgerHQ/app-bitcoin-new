# End-to-end tests using Bitcoin Testnet

These tests are implemented in Python and can be executed either using the [Speculos](https://github.com/LedgerHQ/speculos) emulator or a Ledger Nano S/X.

All the commands in this folder are meant to be ran from the `tests` folder, not from the root.

Python dependencies are listed in [requirements.txt](requirements.txt), install them using [pip](https://pypi.org/project/pip/)

```
pip install -r requirements.txt
```

## Launch with Speculos

In order to create the necessary binaries for the Bitcoin Testnet application, you can use the convenience scripts `prepare_tests_lib.sh` and `prepare_tests_native.sh`. The former compiles the Bitcoin mainnet version of the application to use as a library, then compiles the binary for the Bitcoin testnet version using the library (this is the mechanism used for the altcoins applications based on the legacy Bitcoin app). The latter natively compiles the Bitcoin application for testnet.

```
bash ./prepare_tests_lib.sh   # or bash ./prepare_tests_native.sh
```

Then run all the tests using:

```
pytest
```

You can delete the test binaries with

```
bash ./clean_tests.sh
```

## Launch with your Nano S/X

Compile and install the app on your device as normal.

To run the tests on your Ledger Nano S/X you also need to install an optional dependency

```
pip install ledgercomm[hid]
```

Be sure to have you device connected through USB (without any other software interacting with it) and run

```
pytest --hid
```

Please note that tests that require an automation file are meant for speculos, and will currently hang the test suite.