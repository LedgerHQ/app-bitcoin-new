# Benchmarks

The tests in this folder are meant to measure the performance of various app operations.

These tests are implemented in Python and can be executed either using the [Speculos](https://github.com/LedgerHQ/speculos) emulator or a Ledger Nano S+, Nano X, or Stax.

Python dependencies are listed in [requirements.txt](requirements.txt), install them using [pip](https://pypi.org/project/pip/) from the root of the repository:

```
pip install -r requirements.txt
```

## Build

The app must be built with the `AUTOAPPROVE_FOR_PERF_TESTS=1` parameter when calling `make`. This flag compiles the testnet app in a mode that requires no user interaction at all.

## Launch with Speculos

Performance measured in speculos is not a good proxy of the performance on a real device.

Simply run:

```
pytest
```

## Launch with your device

Compile and install the app on your device as normal.

To run the tests on your Ledger device, you also need to install an optional dependency

```
pip install ledgercomm[hid]
```

Be sure to have you device connected through USB and open on the bitcoin testnet app, sideloaded from the build above.

```
pytest --hid
```
