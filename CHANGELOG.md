# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Dates are in `dd-mm-yyyy` format.

## [2.1.3] - 21-06-2023

### Changed

- Improved UX for self-transfers, that is, transactions where all the outputs are change outputs.
- Outputs containing a single `OP_RETURN` (without any data push) can now be signed in order to support [BIP-0322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki) implementations.


### Fixed

- Wrong address generation for miniscript policies containing an unusual `thresh(1,X)` fragment (that is, with threshold 1, and a single condition). This should not happen in practice, as the policy is redundant for just `X`. Client libraries have been updated to detect and prevent usage of these policies.
- Resolved a slight regression in signing performance introduced in v2.1.2.

## [2.1.2] - 03-04-2023

### Added

- 🥕 Initial support for taproot scripts; taproot trees support up to 8 leaves, and the only supported scripts in tapleaves are `pk`, `multi_a` and `sortedmulti_a`.

### Fixed

- Miniscript policies containing an `a:` fragment returned an incorrect address in versions `2.1.0` and `2.1.1` of the app. The **upgrade is strongly recommended** for users of miniscript wallets.
- The app will now reject showing or returning an address for a wallet policy if the `address_index` is larger than or equal to `2147483648`; previous version would return an address for a hardened derivation, which is undesirable.
- Nested segwit transactions (P2SH-P2WPKH and P2SH-P2WSH) can now be signed (with a warning) if the PSBT contains the witness-utxo but no non-witness-utxo. This aligns their behavior to other types of Segwitv0 transactions since version 2.0.6.

## [2.1.1] - 23-01-2023

### Changed

- Allow silent xpub exports at the `m/45'/coin_type'/account'` derivation paths.
- Allow silent xpub exports for any unhardened child of an allowed path.
- Allow up to 8 derivation steps for BIP-32 paths (instead of 6).

## [2.1.0] - 16-11-2022

### Added

- Miniscript support on SegWit.
- Improved support for wallet policies.
- Support for sighash flags.

### Changed

- Wallet policies now allow external keys with no key origin information.
- Wallet policies now allow multiple internal keys.

### Removed

- Support for legacy protocol (pre-2.0.0 version) and support for altcoins, now done via separate apps. Substantial binary size reduction as a consequence.

## [2.0.6] - 06-06-2022

### Added

- Support signing of segwit V0 transactions with unverified inputs for compatibility with software unable to provide the previous transaction.

### Fixed

- Fixed bug preventing signing transactions with external inputs (or with mixed script types).

## [2.0.5] - 03-05-2022

### Changed

- Technical release; restore compatibility with some client libraries that rely on deprecated legacy behavior.

## [2.0.4] - 28-03-2022

### Added

- Support for OP_RETURN outputs.
- Full support for app-exchange swaps.
- JS/TypeScript client library.

### Changed

- Increased max number of inputs during signing from 64 to 512; removed limit on the number of outputs.
- Various performance improvements.

### Fixed

- Fixed bug preventing signing segwit inputs in the presence of legacy inputs.

## [2.0.3] - 19-02-2022

### Fixed

Fix bug in visualization of large transaction amounts.

## [2.0.2] - 19-01-2022

### Added

Native support for Bitcoin Message Signing.

## [2.0.1] - 17-11-2021

### Changed

Thecnical release for Nano S Firmware v2.1.0. Small reduction in app size.

## [2.0.0] - 10-11-2021

### Added

First public release. 🎉
