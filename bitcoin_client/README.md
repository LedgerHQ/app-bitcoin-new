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
from typing import Optional
from ledger_bitcoin import createClient, Chain, MultisigWallet, MultisigWallet, PolicyMapWallet, AddressType
from ledger_bitcoin.psbt import PSBT


def main():
    with createClient(chain=Chain.TEST) as client:

        # ==> Get the master key fingerprint

        fpr = client.get_master_fingerprint().hex()
        print(f"Master key fingerprint: {fpr}")

        # ==> Get and display on screen the first taproot address

        first_taproot_account_pubkey = client.get_extended_pubkey("m/86'/1'/0'")
        first_taproot_account_policy = PolicyMapWallet(
            "",
            "tr(@0)",
            [
                f"[{fpr}/86'/1'/0']{first_taproot_account_pubkey}/**"
            ],
        )
        first_taproot_account_address = client.get_wallet_address(
            first_taproot_account_policy,
            None,
            change=0,
            address_index=0,
            display=True # show address on the wallet's screen
        )

        print(f"First taproot account receive address: {first_taproot_account_address}")

        # ==> Register a multisig wallet named "Cold storage"

        our_pubkey = client.get_extended_pubkey("m/48'/1'/0'/2'")
        other_key_info = "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/**"

        multisig_policy = MultisigWallet(
            name="Cold storage",
            address_type=AddressType.WIT,
            threshold=2,
            keys_info=[
                other_key_info,                          # some other bitcoiner
                f"[{fpr}/48'/1'/0'/2']{our_pubkey}/**",  # that's us
            ],
        )

        policy_id, policy_hmac = client.register_wallet(multisig_policy)

        print(f"Policy hmac: {policy_hmac.hex()}. Store it safely (together with the policy).")

        assert policy_id == multisig_policy.id  # should never fail

        # ==> Derive and show an address for "Cold storage"

        multisig_address = client.get_wallet_address(multisig_policy, policy_hmac, change=0, address_index=0, display=True)
        print(f"Multisig wallet address: {multisig_address}")

        # ==> Sign a psbt

        # TODO: set a wallet policy and a valid psbt file in order to test psbt signing
        psbt_filename: Optional[str] = None
        signing_policy: Optional[PolicyMapWallet] = None
        signing_policy_hmac: Optional[bytes] = None
        if not psbt_filename or not signing_policy:
            print("Nothing to sign :(")
            return

        raw_psbt_base64 = open(psbt_filename, "r").read()
        psbt = PSBT()
        psbt.deserialize(raw_psbt_base64)

        result = client.sign_psbt(psbt, signing_policy, signing_policy_hmac)

        print("Returned signatures:")
        print(result)

if __name__ == "__main__":
    main()

```