# Wallet policy

A _wallet policy_ is a structured representation of an account secured by a policy expressed with output script descriptors. It is composed by two parts:
a wallet descriptor template and the vector of key placeholder expressions.

A _wallet descriptor template_ follows language very similar to output descriptor, with a few differences; the biggest one is that each `KEY` expression with a key placeholder `KP` expression, that refers to one of the keys in the _keys information vector_, plus the additional derivation steps to use for that key. Contextually, the keys information vector contains all the relevant _xpubs_, and possibly their key origin information.

Each entry in the key information vector contains an _xpub_ (other types of keys supported in output script descriptors are not allowed), possible preceeded by the key origin information. The key origin information is compulsory for internal keys.

This section formally defines wallet policies, and how they relate to
output script descriptors.

## Formal definition

A _wallet policy_ is composed by a _wallet descriptor template_, together with a vector of _key information items_.

### Wallet descriptor template ====

A wallet descriptor template is a `SCRIPT` expression.

`SCRIPT` expressions:
- `sh(SCRIPT)` (top level only): P2SH embed the argument.
- `wsh(SCRIPT)` (top level or inside `sh` only): P2WSH embed the argument.
- `pkh(KP)` (not inside `tr`): P2PKH output for the given public key (use
`addr` if you only know the pubkey hash).
- `wpkh(KP)` (top level or inside `sh` only): P2WPKH output for the given
compressed pubkey.
- `multi(k,KP_1,KP_2,...,KP_n)` (not inside `tr`): k-of-n multisig script using OP_CHECKMULTISIG.
- `sortedmulti(k,KP_1,KP_2,...,KP_n)` (not inside `tr`): k-of-n multisig script with keys
sorted lexicographically in the resulting script.
- `multi_a(k,KP_1,KP_2,...,KP_n)` (only inside `tr`): k-of-n multisig script.
- `sortedmulti_a(k,KP_1,KP_2,...,KP_n)` (only inside `tr`): k-of-n multisig script with keys
sorted lexicographically in the resulting script.
- `tr(KP)` or `tr(KP,TREE)`: P2TR output with the specified key placeholder internal key, and optionally a tree of script paths.
- any valid [miniscript](https://bitcoin.sipa.be/miniscript) template (only inside top-level `wsh`, or in `TREE`).

`TREE` expressions:
- any `SCRIPT`expression.
- An open brace `{`, a `TREE` expression, a comma `,`, a `TREE` expression, and a closing brace `}`.

`KP` expressions (key placeholders) consist of
- a single character `@`
- followed by a non-negative decimal number, with no leading zeros (except
for `@0`).
- possibly followed by either:
  - the string  `/**`, or
  - a string of the form `/<NUM;NUM>/*`, for two distinct decimal numbers
`NUM` representing unhardened derivations.

The `/**` in the placeholder template represents commonly used paths for
receive/change addresses, and is equivalent to `<0;1>`.

The placeholder `@i` for some number *i* represents the *i*-th key in the
vector of key origin information (which must be of size at least *i* + 1,
or the wallet policy is invalid).

### Keys information vector

Each element of the keys origin information vector is a `KEY` expression.

`KEY` expressions consist of
- Optionally, key origin information, consisting of:
  - An open bracket `[`
  - Exactly 8 hex characters for the fingerprint of the master key from
which this key is derived from (see [BIP32](
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) for details)
  - Followed by zero or more `/NUM'` path elements to indicate hardened
derivation steps between the fingerprint and the xpub that follows
  - A closing bracket `]`
- Followed by the actual key, which is either
  - a hex-encoded pubkey, which is either
    - inside `wpkh` and `wsh`, only compressed public keys are permitted
(exactly 66 hex characters starting with `02` or `03`.
    - inside `tr`, x-only pubkeys are also permitted (exactly 64 hex
characters).
  - a serialized extended public key (`xpub`) (as defined in [BIP 32](
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki))

The placeholder `@i` for some number *i* represents the *i*-th key in the
vector of key origin information (which must be of size at least *i* + 1,
or the wallet policy is invalid).

A key with no origin information will be treated as external by the hardware wallet.

### Additional rules

The wallet policy is invalid if any placeholder expression with additional
derivation steps is used when the corresponding key information is not an
xpub.

The key information vector *should* be ordered so that placeholder `@i`
never appear for the first time before an occurrence of `@j` for some `j < i`; for example, the first placeholder is always `@0`, the next one is
`@1`, etc.

### Implementation-specific restrictions

- Placeholder _must_ be followed by `/**` or `/<0;1>`.
- Key expressions only support xpubs at this time (no hex-encoded pubkeys).
- Very large policies might not be supported because of the device's memory limitations.

## Descriptor derivation

From a wallet descriptor template (and the associated vector of keys
information), one can therefore obtain the 1-dimensional descriptor for
receive and change addresses by:

- replacing each key placeholder with the corresponding key origin
information;
- replacing every `/**` with `/0/*` for the receive descriptor, and `/1/*`
for the change descriptor;
- replacing every `/<M;N>` with `/M` for the receive descriptor, and `/N`
for the change descriptor.

For example, the wallet descriptor `pkh(@0/**)` with key information
`["[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"]`
produces the following two descriptors:

- Receive descriptor:
`pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*)`

- Change descriptor:
`pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)`


# Policy registration and usage
The app supports a number of features related to wallet policies. In order to securely sign transactions with a policy wallet (for example in a multisignature), it is necessary to be able to:

- register a wallet, validating all the information (policy and keys involved) with the user on the trusted screen;
- show the addresses for a registered wallet on the trusted screen;
- sign spends from the wallet. 

Since the application is stateless, wallet registration is not persisted on device. In order to make it possible to use a registered wallet in future requests, the device returns a hmac-sha256 (32 bytes long) for the wallet upon a successful registration. The client side is responsible for persisting the wallet policy *and* the returned hmac-sha256, and to provide this information in future requests.

As the symmetric key used for hmac-sha256 is deterministically derived from the hardware wallet seed (using [SLIP-0021](https://github.com/satoshilabs/slips/blob/master/slip-0021.md)), the completed wallet registration is non-revokable.

## Wallet policy serialization

A registered wallet policy comprises the following:
- The wallet name, up to 16 bytes long; the name is shown to the user on-screen in order to identify the wallet.
- The wallet descriptor template as a string.
- The list of keys.

The wallet policy is serialized as the concatenation of:

- `1 byte`: a byte equal to `0x02`, the version of the wallet policy language
- `1 byte`: the length of the wallet name (0 for standard wallet)
- `<variable length>`: the wallet name (empty for standard wallets)
- `<variable length>`: the length of the wallet descriptor template, encoded as a Bitcoin-style variable-length integer
- `32 bytes`: the sha256 hash of the wallet descriptor template
- `<variable length>`: the number of keys in the list of keys, encoded as a Bitcoin-style variable-length integer
- `<32 bytes>`: the root of the canonical Merkle tree of the list of keys

See [merkle](merkle.md) for information on Merkle trees.

The sha256 hash of a serialized wallet policy is used as a *wallet policy id*.

## Wallet name

The wallet name must be recognizable from the user when shown on-screen. Currently, the following limitations apply during wallet registration:
- The wallet name must be at least 1 and at most 64 characters long.
- Each character must be an ASCII character with code at least 32 = 0x20 (the 'space' character) and at most 125 = 0x7e (the '~' character).
- The first and the last character must _not_ be spaces.

The hardware wallet will reject registration for wallet names not respecting the above constraints.

## Supported policies

The following policy types are currently supported as top-level scripts:

- `sh(multi(...))` and `sh(sortedmulti(...))` (legacy multisignature wallets);
- `sh(wsh(multi(...)))` and `sh(wsh(sortedmulti(...)))` (wrapped-segwit multisignature wallets);
- `wsh(SCRIPT)`;
- `tr(KP)` and `tr(KP,TREE)`.

`SCRIPT` expression within `wsh` can be:
- `multi` or `sortedmulti`;
- a valid SegWit miniscript template.

`SCRIPT` expression within `TREE` can be:
- `multi_a` or `sortedmulti_a`;
- a valid taproot miniscript template.

# Default wallets
A few policies that correspond to standardized single-key wallets can be used without requiring any registration; in the serialization, the wallet name must be a zero-length string. Those are the following policies:

- ``pkh(@0/**)`` - legacy addresses as per [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- ``wpkh(@0/**)`` - native segwit addresses per [BIP-84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)
- ``sh(wpkh(@0/**))`` - nested segwit addresses as per [BIP-49](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki)
- ``tr(@0/**)`` - single Key P2TR as per [BIP-86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)

Note that the wallet policy is considered standard (and therefore usable for signing without prior registration) only if the signing paths (defined in the key origin information) adhere to the corresponding BIP. Moreover, the BIP-44 `account` level must be at most `100`, and the `address index` at most `50000`. Larger values can still be used by registering the policy.
