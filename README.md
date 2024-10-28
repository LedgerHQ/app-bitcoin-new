# Ledger Bitcoin Application

## Prerequisite

Be sure to have your environment correctly set up (see [Getting Started](https://developers.ledger.com/docs/nano-app/introduction/)) and [ledgerblue](https://pypi.org/project/ledgerblue/) installed.

If you want to benefit from [vscode](https://code.visualstudio.com/) integration, it's recommended to move the toolchain in `/opt` and set `BOLOS_ENV` environment variable as follows

```
BOLOS_ENV=/opt/bolos-devenv
```

and do the same with `BOLOS_SDK` environment variable

```
BOLOS_SDK=/opt/nanos-secure-sdk
```

## Compilation

```
make DEBUG=1  # compile optionally with PRINTF
make load     # load the app on the Nano using ledgerblue
```

## Documentation

For many use cases, the code examples provided in the following client libraries might be sufficient to get started:
- [Python client library](bitcoin_client)
- [JavaScript client library](bitcoin_client_js)
- [Rust client library](bitcoin_client_rs)

If you need to go deeper into the rabbit hole 🐇🕳️, refer to the following documents:
- [bitcoin.md](doc/bitcoin.md): Low-level documentation of the Bitcoin app's communication protocol and commands.
- [merkle.md](doc/merkle.md): Advanced details on techniques used in the Bitcoin app's secured and scalable communication protocol.
- [wallet.md](doc/wallet.md): Information on the types of scripts supported by the Ledger Bitcoin app and the security requirements for multi-user or multi-key spending policies.
- [debugging.md](doc/debugging.md): Guidance on how to diagnose and resolve issues.

## Client libraries

A [Python client library](bitcoin_client), a [TypeScript client library](bitcoin_client_js) and a [Rust client library](bitcoin_client_rs) are available in this repository.

## Tests & Continuous Integration

The flow processed in [GitHub Actions](https://github.com/features/actions) is the following:

- Code formatting with [clang-format](http://clang.llvm.org/docs/ClangFormat.html)
- Compilation of the application for Ledger Nano S in [ledger-app-builder](https://github.com/LedgerHQ/ledger-app-builder)
- Unit tests of C functions with [cmocka](https://cmocka.org/) (see [unit-tests/](unit-tests/))
- End-to-end tests with [Speculos](https://github.com/LedgerHQ/speculos) emulator (see [tests/](tests/))
- Code coverage with [gcov](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html)/[lcov](http://ltp.sourceforge.net/coverage/lcov.php) and upload to [codecov.io](https://about.codecov.io)
- Documentation generation with [doxygen](https://www.doxygen.nl)

It outputs 4 artifacts:

- `bitcoin-app-debug` within output files of the compilation process in debug mode
- `code-coverage` within HTML details of code coverage
- `documentation` within HTML auto-generated documentation
