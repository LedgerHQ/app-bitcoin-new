# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Dates are in `dd-mm-yyyy` format.

## [0.2.1] - 18-04-2023

### Changed
- Avoid using miniscript policies containing an `a:` fragment on versions below `2.1.2` of the bitcoin app.

## [0.2.0] - 3-04-2023

This release introduces a breaking change in the return type of the `sign_psbt`method.

### Added
- Added new `PartialSignature` data class together with support for taproot script signing, which is supported in version `2.1.2` of the bitcoin app.

## [0.1.2] - 09-01-2023

### Fixed
- Added missing dependency.

## [0.1.1] - 26-10-2022

### Changed

- Improved interface of TransportClient for better interoperability with HID.
- `sign_psbt` now accepts the psbt to be passed as `bytes` or `str`.

## [0.1.0] - 18-10-2022

### Changed

Upgraded library to version 2.1.0 of the app.

## [0.0.3] - 25-04-2022

### Changed

Imported upstream changes to auxiliary classes from bitcoin-core/HWI.

### Fixed

Solved incorrect handling of signature responses for transactions with more than 252 inputs.

## [0.0.2] - 09-02-2022

### Added

Support for Bitcoin Message Signing, for Ledger Nano app 2.0.2.

## [0.0.1] - 02-12-2021

### Added

First public release. 🎉
