Bitcoin application : Technical Specifications

<!-- TODO: List all the technical limitation for each command (max limits, etc.) -->


## Framework

### APDUs

The messaging format of the app is compatible with the [APDU protocol](https://developers.ledger.com/docs/nano-app/application-structure/#apdu-interpretation-loop). The `P1` and `P2` fields are not used and must be set to `0` in all messages.

The main commands use `CLA = 0xE1`, unlike the legacy Bitcoin application that used `CLA = 0xE0`.

| CLA | INS | COMMAND NAME       | DESCRIPTION |
|-----|-----|--------------------|-------------|
|  E1 |  00 | GET_PUBKEY         | Return (and optionally show on screen) extended pubkey |
|  E1 |  01 | GET_ADDRESS        | Return (and optionally show on screen) an internal address |
|  E1 |  02 | REGISTER_WALLET    | Registers a wallet on the device (with user's approval) |
|  E1 |  03 | GET_WALLET_ADDRESS | Return and show on screen an address for a registered or default wallet |
|  E1 |  04 | SIGN_PSBT          | Signs a PSBT with a registered or default wallet |

The `CLA = 0xF8` is used for framework-specific (rather than app-specific) APDUs; at this time, only one command is present.

| CLA | INS | COMMAND NAME | DESCRIPTION |
|-----|-----|--------------|-------------|
|  F8 |  01 | CONTINUE     | Respond to an interruption and continue processing a command |

The `CONTINUE` command is sent as a response to a client command from the Hardware Wallet; the format and content on the response depends on the client command, and is documented below for each client command.

### Interactive commands

Several commands are executed via an interactive protocol that requires multiple rounds. At any time after receiving the command and before returning the commands final response (which is status word `0x9000` in case of success), the Hardware Wallet can respond with a special status word `SW_INTERRUPTED_EXECUTION` (`0xE000`), containing a request for the client in the response data. The first byte of the response is the *client command code*, identified what kind of request the Hardware Wallet is asking the client to perform. The client *must* comply with the request and send a special *CONTINUE* command `CLA = 0xF8` and `INS = 0x01`, with the appropriate response.

## Descriptors and wallet policies

The Bitcoin app uses a language similar to [output script descriptors](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md) in order to represent the wallets that can be used to sign transactions.
Wallets need to be registered on the device, with an interactive process that requires user's approval.

See [here](wallet.md) for detailed information on the wallet policy language.

## Wallet registration flow

## Status Words

<!-- TODO: not up to date -->

| SW     | SW name                      | Description |
|--------|------------------------------|-------------|
| 0x6985 | `SW_DENY`                    | Rejected by user |
| 0x6A86 | `SW_WRONG_P1P2`              | Either `P1` or `P2` is incorrect |
| 0x6A87 | `SW_WRONG_DATA_LENGTH`       | `Lc` or minimum APDU lenght is incorrect |
| 0x6D00 | `SW_INS_NOT_SUPPORTED`       | No command exists with `INS` |
| 0x6E00 | `SW_CLA_NOT_SUPPORTED`       | Bad `CLA` used for this application |
| 0xB000 | `SW_WRONG_RESPONSE_LENGTH`   | Wrong response lenght (buffer size problem) |
| 0xB001 | `SW_DISPLAY_BIP32_PATH_FAIL` | BIP32 path conversion to string failed |
| 0xB002 | `SW_DISPLAY_ADDRESS_FAIL`    | Address conversion to string failed |
| 0xB003 | `SW_DISPLAY_AMOUNT_FAIL`     | Amount conversion to string failed |
| 0xB004 | `SW_WRONG_TX_LENGTH`         | Wrong raw transaction lenght |
| 0xB005 | `SW_TX_PARSING_FAIL`         | Failed to parse raw transaction |
| 0xB006 | `SW_TX_HASH_FAIL`            | Failed to compute hash digest of raw transaction |
| 0xB007 | `SW_BAD_STATE`               | Security issue with bad state |
| 0xB008 | `SW_SIGNATURE_FAIL`          | Signature of raw transaction failed |
| 0xE000 | `SW_INTERRUPTED_EXECUTION`   | The command is interrupted, and requires the client's response |
| 0x9000 | `SW_OK`                      | Success |

<!-- TODO: add an introduction section explaining the comand reference notations (e.g. the Bitcoin style varint) -->

## Commands

### GET_PUBKEY

Returns an extended public key at the given derivation path.

#### Encoding

**Command**

| *CLA* | *INS* |
|-------|-------|
| E1    | 00    |

**Input data**

| Length | Name              | Description |
|--------|-------------------|-------------|
| `1`    | `display`         | `0` or `1`  |
| `1`    | `n`               | Number of derivation steps (maximum 6) |
| `4`    | `bip32_path[0]`   | First derivation step (big endian) |
| `4`    | `bip32_path[1]`   | Second derivation step (big endian) |
|        | ...               |             |
| `4`    | `bip32_path[n-1]` | `n`-th derivation step (big endian) |

**Output data**

| Length | Description |
|--------|-------------|
| `<variable>` | The full serialized extended public key as per BIP-32 |

#### Description

This command returns the extended public key for the given BIP 32 path.
If the `display` parameter is `1`, the result is also shown on the secure screen for verification.

The paths defined in [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki), [BIP-84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki) and [BIP-49](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki) are considered standard. 

If the path is not standard, a warning is shown on-screen; in that case, the pubkey is only returned after user's confirmation *even if tie `display` parameter is `0`*.


### GET_ADDRESS

Returns an address at a given derivation path.

#### Encoding

**Command**

| *CLA* | *INS* |
|-------|-------|
| E1    | 01    |

**Input data**

| Length | Name              | Description |
|--------|-------------------|-------------|
| `1`    | `display`         | `0` or `1`  |
| `1`    | `address_type`    | `1` (legacy), `2` (segwit) or `3` (nested segwit) |
| `1`    | `n`               | Number of derivation steps (maximum 6) |
| `4`    | `bip32_path[0]`   | First derivation step (big endian) |
| `4`    | `bip32_path[1]`   | Second derivation step (big endian) |
|        | ...               |             |
| `4`    | `bip32_path[n-1]` | `n`-th derivation step (big endian) |

**Output data**

| Length  | Description           |
|---------|-----------------------|
| `<var>` | The requested address |

#### Description

This command returns the address corresponding to the given BIP 32 path, for the specified address type. The address type must be either:
- `1` for a legacy address (P2PKH);
- `2` for a bech32 native SegWit address (P2SH);
- `3` for a nested SegWit address (P2SH-P2WPKH).

If the `display` parameter is `1`, the address is shown to the user for validation.

The paths defined in [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki), [BIP-84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki) and [BIP-49](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki) are considered standard.  

If the path is not standard, a warning is shown on-screen; in that case, the address is only returned after user's confirmation *even if tie `display` parameter is `0`.

### REGISTER_WALLET

Registers a wallet policy on the device, after validating it with the user.

#### Encoding

**Command**

| *CLA* | *INS* |
|-------|-------|
| E1    | 02    |

**Input data**

| Length          | Name            | Description |
|-----------------|-----------------|-------------|
| `<variable>`    | `policy_length` | The length of the policy (unsigned varint) |
| `policy_length` | `policy`        | The serialized wallet policy |

The `policy` is serialized as described [here](wallet.md). At this time, no policy can be longer than 252 bytes, therefore the `policy_length` field is always encoded as 1 byte.

**Output data**

| Length | Description                |
|--------|----------------------------|
| `32`   | The `wallet_id`            |
| `32`   | The `hmac` for this wallet |

#### Description

This command allows to register a wallet policy on the device. The wallet's name, descriptor template and each of the keys information is shown to the user.

After user's validation is completed successfully, the application returns the `wallet_id` (sha256 of the wallet serialization), and the `hmac` for this wallet.

#### Client commands

The client must respond to the `GET_PREIMAGE`, `GET_MERKLE_LEAF_PROOF` and `GET_MERKLE_LEAF_INDEX` queries related to the Merkle tree of the list of keys information.

The `GET_MORE_ELEMENTS` command must be handled.

### GET_WALLET_ADDRESS

Get a receive or change a address for a registered or default wallet, after validating it with the user using the trusted screen.

#### Encoding

**Command**

| *CLA* | *INS* |
|-------|-------|
| E1    | 03    |

**Input data**

| Length | Name            | Description |
|--------|-----------------|-------------|
| `32`   | `wallet_id`     | The id of the wallet |
| `32`   | `wallet_hmac`   | The hmac of a registered wallet, or exactly 32 0 bytes |
| `1`    | `change`        | `0` for a receive address, `1` for a change address |
| `4`    | `address_index` | The desired address index (big-endian) |


**Output data**

| Length      | Description     |
|-------------|-----------------|
| <variable>  | The wallet address for the given change/address_index |

#### Description

For a registered wallet, the hmac must be correct. Once that is validated, this command computes the address of the wallet for the given `change` and `address_index` choice.

For a default wallet, `hmac` must be equal to 32 bytes `0`.

<!-- TODO: once the path checking is added for default wallet, document it here -->

#### Client commands

`GET_PREIMAGE` must know and respond for the full serialized wallet policy whose sha256 hash is `wallet_id`.

The client must respond to the `GET_PREIMAGE`, `GET_MERKLE_LEAF_PROOF` and `GET_MERKLE_LEAF_INDEX` queries related to the Merkle tree of the list of keys information.

The `GET_MORE_ELEMENTS` command must be handled.

### SIGN_PSBT

Given a PSBTv2 and a registered wallet (or a standard one), sign all the inputs that are owned by that wallet.

#### Encoding

**Command**

| *CLA* | *INS* |
|-------|-------|
| E1    | 04    |

**Input data**

| Length  | Name                   | Description |
|---------|------------------------|-------------|
| `<var>` | `global_map_size`      | The number of key/value pairs of the global map of the psbt |
| `32`    | `global_map_keys_root` | The Merkle root of the keys of the global map |
| `32`    | `global_map_vals_root` | The Merkle root of the values of the global map |
| `<var>` | `n_inputs`             | The number of inputs of the psbt | 
| `32`    | `inputs_maps_root`     | The Merkle root of the vector of Merkleized map commitments for the input maps |
| `<var>` | `n_outputs`            | The number of outputs of the psbt | 
| `32`    | `outputs_maps_root`    | The Merkle root of the vector of Merkleized map commitments for the output maps |
| `32`    | `wallet_id`            | The id of the wallet |
| `32`    | `wallet_hmac`          | The hmac of a registered wallet, or exactly 32 0 bytes |

**Output data**

No output data; the signature are returned using the YIELD client command.

#### Description

Using the information in the PSBT and the wallet description, this command verifies what inputs are internal and what output matches the pattern for a change address. After validating all the external outputs and the transaction fee with the user, it signs each of the internal inputs; each signature is sent to the client using the YIELD command, encoded as `<input_index> <signature>`, where the `input_index` is a Bitcoin style varint (currently, always 1 byte).

For a registered wallet, the hmac must be correct.

For a default wallet, `hmac` must be equal to 32 bytes `0`.

<!-- TODO: once the path checking is added for default wallet, document it here -->

#### Client commands

`GET_PREIMAGE` must know and respond for the full serialized wallet policy whose sha256 hash is `wallet_id`.

The client must respond to the `GET_PREIMAGE`, `GET_MERKLE_LEAF_PROOF` and `GET_MERKLE_LEAF_INDEX` for all the Merkle trees in the input, including each of the Merkle trees for keys and values of the Merkleized map commitments of each of the inputs/outputs maps of the psbt.

The `GET_MORE_ELEMENTS` command must be handled.

The `YIELD` command must be processed in order to receive the signatures.

## Client commands

| CMD | COMMAND NAME          | DESCRIPTION |
|-----|-----------------------|-------------|
|  10 | YIELD                 | Receive some elements during command execution |
|  40 | GET_PREIMAGE          | Return the preimage corresponding to the given sha256 hash |
|  41 | GET_MERKLE_LEAF_PROOF | Returns the Merkle proof for a given leaf |
|  42 | GET_MERKLE_LEAF_INDEX | Returns the index of a leaf in a Merkle tree |
|  A0 | GET_MORE_ELEMENTS     | Receive more data that could not fit in the previous responses |

### YIELD

**Command code**: 0x10

The `YIELD` client command is sent to the client to communicate some result during the execution of a command. Currently only used during `SIGN_PSBT` in order to communicate each of the signatures. The format of the attached message is documented for each command that uses `YIELD`.

The client must respond with an empty message.

### 40 GET_PREIMAGE

**Command code**: 0x40

The `GET_PREIMAGE` command requests the client to reveal a SHA-256 preimage.

The request contains a single 32-byte hash.
<!-- TODO: could add a byte to specify the hash function; 0 for SHA-256, other values reserved for future usages -->

The response must contain:
- `<var>`: the length of the preimage, encoded as a Bitcoin-style varint
- `1` byte: a 1-byte unsigned integer `b`, the length of the prefix of the pre-image that is part of the response
- `b` bytes: corresponding to the first `b` bytes of the preimage.

If the pre-image is too long to be contained in a single response, the client should choose `b` to be as large as possible; subsequent bytes are enqueued as single-byte elements that the Hardware Wallet will request with one ore more `GET_MORE_ELEMENTS` requests.

### GET_MERKLE_LEAF_PROOF

**Command code**: 0x41

The `GET_MERKLE_LEAF_PROOF` command requests the hash of a given leaf of a Merkle tree, together with the Merkle proof.

The request contains:
- `32` bytes: the Merkle root hash
<!-- TODO: might change to varint -->
- `4` bytes: the tree size `n`, encoded as an unsigned 4-byte big-endian integer.
- `4` bytes: the leaf index `i`, encoded as an unsigned 4-byte big-endian integer.

The client must respond with:
- `32` bytes: the hash of the leaf with index `i` in the requested Merkle tree.
- `1` byte: the length of the Merkle proof
- `1` byte: the amount `p` of hashes of the proof that are contained in the response
- `32 * p` bytes: the concatenation of the first `p` hashes in the Merkle proof.

If the proof is too long to be contained in a single response, the client should choose `p` to be as large as possible; subsequent bytes are enqueued as 32-byte elements that the Hardware Wallet will request with one ore more `GET_MORE_ELEMENTS` requests.

### GET_MERKLE_LEAF_INDEX

**Command code**: 0x42

The `GET_MERKLE_LEAF_INDEX` requests the index of a leaf with a certain hash. if multiple leafs have the same hash, the client could respond with either.

The request contains:
- `32` bytes: the Merkle root hash
- `32` bytes: the leaf hash

The response contains:
- `1` byte: `1` if the leaf is found, `0` if matching leaf exists
- `<var>`: the index of the leaf, encoded as a Bitcoin-style varint

### GET_MORE_ELEMENTS

**Command code**: 0xA0

The `GET_MORE_ELEMENTS` command requests the client to return more elements that were enqueued by previous client commands (like `GET_PREIMAGE` and `GET_MERKLE_LEAF_PROOF`).

All of the elements in the queue must all be byte strings of the same length; the command fails otherwise. The client should return as many elements as it is possible to fit in the response, while leaving the remaining ones (if any) in the queue.

The request is empty.

The response contains:
- `1` byte: the number `n` of returned element
- `1` byte: the size `s` of each returned element
- `n * s` bytes: the concatenation of the `n` returned elements


## Security considerations

Some of the client commands are used to allow the client to reveal some information that is not known to the hardware wallet. This approach allows to create protocols that work with an amount of data that is too large to fit in a single APDU, or even in the limited RAM of a device like a Ledger Nano S.

In designing the interactive protocol, care is taken to avoid security risks associated with a malicious, possibly compromised client.

All the current commands use a commit-and-reveal approach: the APDU that starts the protocol (first message) commits to all the relevant data (for example, the entirety of the PSBT), by using hashes and/or Merkle trees. Any time the client is asked to reveal some committed information, the app does not consider it trusted:
- If a preimage is asked via `GET_PREIMAGE`, the hash is computed to validate that the correct preimage is returned by the client.
- If a Merkle proof is asked via `GET_MERKLE_LEAF_PROOF`, the proof is verified.
- If the index of a leaf is asked `GET_MERKLE_LEAF_INDEX`, the proof for that element is requested via `GET_MERKLE_LEAF_PROOF` and the proof verified, *even if the leaf value is known*.

Care needs to be taken as the client might lie by omission (for example, fail to revel that a leaf of a Merkle tree is present during a call to `GET_MERKLE_LEAF_INDEX`).