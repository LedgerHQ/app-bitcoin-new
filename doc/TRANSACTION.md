# BOLOK Transaction Serialization

## Overview

The custom transaction serialization presented is for the purely fictitious BOLOK *chain* which has been inspired by other popular blockchain (see [Links](#links)).

## Amount units

The base unit in BOLOK *chain* is the BOL and the smallest unit used in raw transaction is the *bolino* or mBOL: 1 BOL = 1000 mBOL.

## Address format

BOLOK addresses are hexadecimal numbers, identifiers derived from the last 20 bytes of the Keccak-256 hash of the public key.

## Structure

### Transaction

| Field | Size (bytes) | Description |
| --- | :---: | --- |
| `nonce` | 8 | A sequence number used to prevent message replay |
| `to` | 20 | The destination address |
| `value` | 8 | The amount in mBOL to send to the destination address |
| `memo_len` | 1-9 | length of the memo as [varint](#variablelenghtinteger) |
| `memo` | var | A text ASCII-encoded of length `memo_len` to show your love |
| `v` | 1 | 0x01 if y-coordinate of R is odd, 0x00 otherwise |
| `r` | 32 | x-coordinate of R in ECDSA signature |
| `s` | 32 | x-coordinate of S in ECDSA signature |

### Variable length integer (varint)

Integer can be encoded depending on the represented value to save space.
Variable length integers always precede an array of a type of data that may vary in length.
Longer numbers are encoded in little endian.

| Value | Storage length (bytes) | Format |
| --- | :---: | --- |
| < 0xFD | 1 | uint8_t |
| <= 0xFFFF | 3 | 0xFD followed by the length as uint16_t |
| <= 0xFFFF FFFF | 5 | 0xFE followed by the length as uint32_t |
| - | 9 | 0xFF followed by the length as uint64_t |

### Signature

Deterministic ECDSA ([RFC 6979](https://tools.ietf.org/html/rfc6979)) is used to sign transaction on the [SECP-256k1](https://www.secg.org/sec2-v2.pdf#subsubsection.2.4.1) curve.
The signed message is `m = Keccak-256(nonce || to || value || memo_len || memo)`.

### Fee

You won't find any fee in the transaction structure because the BOLOK *chain* has constant fees.

## Links

- Bitcoin Transaction: https://en.bitcoin.it/wiki/Protocol_documentation#tx

- Ethereum Transaction: https://ethereum.github.io/yellowpaper/paper.pdf#subsection.4.2
