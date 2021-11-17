from pathlib import Path
import logging
from speculos.client import SpeculosClient
from bitcoin_client.command import BitcoinCommand
from bitcoin_client.wallet import MultisigWallet, PolicyMapWallet
from bitcoin_client.common import AddressType
from bitcoin_client.psbt import PSBT
import sys
import os
sys.path.append(os.path.join(sys.path[0], '..'))


logging.basicConfig(level=logging.INFO)

# default speculos seed: glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin

# master xpub:
# xpub661MyMwAqRbcGtJ6aNMHg7WyD3FoeAUoeoQ2SnqsqjgPa"eL8KML8nDLH2c6cFk1EhVDzaFSCDgtLSua2dW7k7Z8hYvbXDRgHmr32jBV1S12

# xpub for m/44'/1'/0' should be:
# xpub6CZvDaQ1mMRp7HfabkhHU5iQ8jm5CWm4wWuXA3vgYcLZg6vfjLeSjMpeCi7xEuBVX55qHdoK43pYCPxNNfjWa27yf5D7RE7GHhfEwJu1Dzb

tests_root: Path = Path(__file__).parent


def open_psbt_from_file(filename: str) -> PSBT:
    raw_psbt_base64 = open(filename, "r").read()

    psbt = PSBT()
    psbt.deserialize(raw_psbt_base64)
    return psbt


def print_psbt_v0(psbt: PSBT) -> None:
    print("tx version:", psbt.tx_version)

    print("tx:", psbt.tx)

    for i, inp in enumerate(psbt.inputs):
        print(f"Input {i}")
        print(f"Non-witness-utxo: {inp.non_witness_utxo}")
        print(f"Witness script: {inp.witness_script.hex()}")
        print(f"Key paths: {inp.hd_keypaths}")

    for i, outp in enumerate(psbt.outputs):
        print(f"Output {i}")
        if outp.script is not None:
            print(f"Script: {outp.script.hex()}")
        print(f"Non-witness-utxo: {inp.non_witness_utxo}")
        print(f"Key paths: {outp.hd_keypaths}")


def main():
    client = SpeculosClient("bin/app.elf")
    cmd = BitcoinCommand(client=client, debug=False)

    # wallet = PolicyMapWallet(
    #     "",
    #     "tr(@0)",
    #     [
    #         "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U/**"
    #     ],
    # )

    # print("Serialized wallet:", wallet.serialize().hex())

    # print(cmd.get_wallet_address(wallet, None, 1, 9, False))

    # psbt = PSBT()
    # psbt.deserialize("cHNidP8BAKYCAAAAAp4s/ifwrYe3iiN9XXQF1KMGZso2HVhaRnsN/kImK020AQAAAAD9////r7+uBlkPdB/xr1m2rEYRJjNqTEqC21U99v76tzesM/MAAAAAAP3///8CqDoGAAAAAAAWABTrOPqbgSj4HybpXtsMX/rqg2kP5OCTBAAAAAAAIgAgP6lmyd3Nwv2W5KXhvHZbn69s6LPrTxEEqta993Mk5b4AAAAAAAEAcQIAAAABk2qy4BBy95PP5Ml3VN4bYf4D59tlNsiy8h3QtXQsSEUBAAAAAP7///8C3uHHAAAAAAAWABTreNfEC/EGOw4/zinDVltonIVZqxAnAAAAAAAAFgAUIxjWb4T+9cSHX5M7A43GODH42hP5lx4AAQEfECcAAAAAAAAWABQjGNZvhP71xIdfkzsDjcY4MfjaEyIGA0Ve587cl7C6Q1uABm/JLJY6NMYAMXmB0TUzDE7kOsejGPWswv1UAACAAQAAgAAAAIAAAAAAAQAAAAABAHEBAAAAAQ5HHvTpLBrLUe/IZg+NP2mTbqnJsr/3L/m8gcUe/PRkAQAAAAAAAAAAAmCuCgAAAAAAFgAUNcbg3W08hLFrqIXcpzrIY9C1k+yvBjIAAAAAABYAFNwobgzS5r03zr6ew0n7XwiQVnL8AAAAAAEBH2CuCgAAAAAAFgAUNcbg3W08hLFrqIXcpzrIY9C1k+wiBgJxtbd5rYcIOFh3l7z28MeuxavnanCdck9I0uJs+HTwoBj1rML9VAAAgAEAAIAAAACAAQAAAAAAAAAAIgICKexHcnEx7SWIogxG7amrt9qm9J/VC6/nC5xappYcTswY9azC/VQAAIABAACAAAAAgAEAAAAKAAAAAAA=")
    # psbt.to_psbt_v2()
    # print(psbt.serialize())

    # result = cmd.sign_psbt(psbt, wallet, None)

    # # expected sigs
    # # #0:
    # #   "pubkey" : "TODO",
    # #   "signature" : "TODO"

    # assert(len(result) == 1)
    # assert(len(result[0]) == 65)

    # print(result)

    # for i, sig_i in result.items():
    #     psbt.inputs[i].final_script_witness.scriptWitness.stack = [sig_i]

    # print(psbt.serialize())

    # # assert result == {
    # #     0: bytes.fromhex(
    # #         "TODO"
    # #     )
    # # }

    xwallet = PolicyMapWallet(
        name="Blah",
        policy_map="pkh(@0)",
        keys_info=[
            f"[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT/**",
        ],
    )

    raw_psbt_base64 = "cHNidP8BAHQCAAAAAXoqmXlWwJ+Op/0oGcGph7sU4iv5rc2vIKiXY3Is7uJkAQAAAAD9////AqC7DQAAAAAAGXapFDRKD0jKFQ7CuQOBdmC5tosTpnAmiKx0OCMAAAAAABYAFOs4+puBKPgfJule2wxf+uqDaQ/kAAAAAAABAH0CAAAAAa+/rgZZD3Qf8a9ZtqxGESYzakxKgttVPfb++rc3rDPzAQAAAAD9////AnARAQAAAAAAIgAg/e5EHFblsG0N+CwSTHBwFKXKGWWL4LmFa8oW8e0yWfel9DAAAAAAABYAFDr4QprVlUql7oozyYP9ih6GeZJLAAAAAAEBH6X0MAAAAAAAFgAUOvhCmtWVSqXuijPJg/2KHoZ5kksiBgPuLD2Y6x+TwKGqjlpACbcOt7ROrRXxZm8TawEq1Y0waBj1rML9VAAAgAEAAIAAAACAAQAAAAgAAAAAACICAinsR3JxMe0liKIMRu2pq7fapvSf1Quv5wucWqaWHE7MGPWswv1UAACAAQAAgAAAAIABAAAACgAAAAA=="
    xpsbt = PSBT()
    xpsbt.deserialize(raw_psbt_base64)

    result = cmd.sign_psbt(xpsbt, xwallet, None)

    client.stop()


if __name__ == "__main__":
    main()
