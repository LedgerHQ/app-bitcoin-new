# Ledger Bitcoin application client

## Overview

Client library for Ledger Bitcoin application.

Main repository and documentation: https://github.com/LedgerHQ/app-bitcoin-new

## Install

If you just want to communicate through TCP socket (for example with the Speculos emulator), there is no dependency:

```bash
$ pip install ledger_bitcoin
```

otherwise, [hidapi](https://github.com/trezor/cython-hidapi) must be installed as an extra dependency:

```bash
$ pip install ledger_bitcoin[hid]
```

## Getting started

### Library

```python
from ledger_bitcoin import createClient

# TODO

```