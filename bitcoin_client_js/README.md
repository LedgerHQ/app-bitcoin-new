# Ledger Bitcoin application client

## Overview

TypeScript client for Ledger Bitcoin application. Supports versions 2.0.0 and above of the app.

Main repository and documentation: https://github.com/LedgerHQ/app-bitcoin-new

<!--
## Install

TODO: fill this once the module is published
-->

## Building

```bash
$ yarn

$ yarn build
```

## Getting started

The following example showcases all the main methods of the `Client`'s interface.

Testing the `signPsbt` method requires a valid PSBTv2, and provide the corresponding wallet policy; it is skipped by default in the following example.

```javascript
import { AppClient, DefaultWalletPolicy, WalletPolicy, PsbtV2 } from 'ledger-bitcoin';
import Transport from '@ledgerhq/hw-transport-node-hid';

// This examples assumes the Bitcoin Testnet app is running.
// Make sure to use addresses compatible with mainnet otherwise, by using paths where the BIP-44 coin_type
// is "0'" and not "1'".

async function main(transport) {
    const app = new AppClient(transport);

    // ==> Get the master key fingerprint
    const fpr = await app.getMasterFingerprint();
    console.log("Master key fingerprint:", fpr.toString("hex"));

    // ==> Get and display on screen the first taproot address
    const firstTaprootAccountPubkey = await app.getExtendedPubkey("m/86'/1'/0'");
    const firstTaprootAccountPolicy = new DefaultWalletPolicy(
        "tr(@0)",
        `[${fpr}/86'/1'/0']${firstTaprootAccountPubkey}/**`
    );

    const firstTaprootAccountAddress = await app.getWalletAddress(
        firstTaprootAccountPolicy,
        null,
        0,
        0,
        true // show address on the wallet's screen
    );

    console.log("First taproot account receive address:", firstTaprootAccountAddress);

    // ==> Register a multisig wallet named "Cold storage"

    const ourPubkey = await app.getExtendedPubkey("m/48'/1'/0'/2'");
    const ourKeyInfo = `[${fpr}/48'/1'/0'/2']${ourPubkey}/**`;
    const otherKeyInfo = "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/**";

    const multisigPolicy = new WalletPolicy(
        "Cold storage",
        "wsh(sortedmulti(2,@0,@1))", // a 2-of-2 multisig policy template
        [
            otherKeyInfo, // some other bitcoiner
            ourKeyInfo,   // that's us
        ]
    )

    const [policyId, policyHmac] = await app.registerWallet(multisigPolicy);

    console.log(`Policy hmac: ${policyHmac.toString("hex")}. Store it safely (together with the policy).`);

    console.assert(policyId.compare(multisigPolicy.getId()) == 0)  //  should never fail

    // ==> Derive and show an address for "Cold storage" that was just registered

    const multisigAddress = await app.getWalletAddress(multisigPolicy, policyHmac, 0, 0, true);
    console.log(`Multisig wallet address: ${multisigAddress}`);

    // ==> Sign a psbt

    // TODO: set a wallet policy and a valid psbt file in order to test psbt signing
    const rawPsbtBase64 = null; // a base64-encoded psbt file to sign
    const signingPolicy = null; // an instance of WalletPolicy
    const signingPolicyHmac = null; // if not a default wallet policy, this must also be set
    if (!rawPsbtBase64 || !signingPolicy) {
        console.log("Nothing to sign :(");
        await transport.close();
        return;
    }

    const psbt = new PsbtV2();
    psbt.deserialize(rawPsbtBase64);

    const result = await app.signPsbt(psbt, signingPolicy, signingPolicyHmac);

    console.log("Returned signatures:");
    console.log(result);

    await transport.close();
}

Transport.default.create()
    .then(main)
    .catch(console.log);
```