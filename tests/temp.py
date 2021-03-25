import logging
import pytest

from ledgercomm import Transport

from bitcoin_client.bitcoin_cmd import BitcoinCommand
from bitcoin_client.wallet import MultisigWallet
from bitcoin_client.bitcoin_cmd_builder import AddrType, ScriptAddrType
from binascii import hexlify

logging.basicConfig(level=logging.INFO)

# default speculos seed: glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin

# master xpub:
# xpub661MyMwAqRbcGtJ6aNMHg7WyD3FoeAUoeoQ2SnqsqjgPaeL8KML8nDLH2c6cFk1EhVDzaFSCDgtLSua2dW7k7Z8hYvbXDRgHmr32jBV1S12

# xpub for m/44'/1'/0' should be:
# xpub6CZvDaQ1mMRp7HfabkhHU5iQ8jm5CWm4wWuXA3vgYcLZg6vfjLeSjMpeCi7xEuBVX55qHdoK43pYCPxNNfjWa27yf5D7RE7GHhfEwJu1Dzb

def main():
    transport = Transport(interface="tcp", debug=True)
    command = BitcoinCommand(transport=transport, debug=False)

            # "xpub6DqTtMuqBiBsHirAP1Tfm7w6ASuGqWTpn9A7efDwmYZd5bMfCuxtmBgMmVufK49sKpXgyxMhb7jYwMDa6nSzRjWry5xgDzjqrDxDqcPteqo",
            # "xpub6Dk2M8SzqzeRyuYuSJ1Vy5uRBvKfV7625LoME3KsDYRuEL8dww4MSQWMEkLLuJF9UK86hZUtRmqx1LSd1c6boq24dyq4E8UEPypQsSxupQ2",
            # "xpub6EZ2Bt4cGEhrYbtgzPgZjaC9c8v5edBRYPXHZhNux5muupbeygXB8WnJg9W9nCPRQQJSwPCTJznsmygJ94ojRYgnFPQFP4Zu4TJxz1adFXy"


    wallet = MultisigWallet(
        name = "Cold storage",
        threshold = 2,
        n_keys = 3,
        pubkeys=[
            "xpub6Dk2M8SzqzeRyuYuSJ1Vy5uRBvKfV7625LoME3KsDYRuEL8dww4MSQWMEkLLuJF9UK86hZUtRmqx1LSd1c6boq24dyq4E8UEPypQsSxupQ2",
            "xpub6EZ2Bt4cGEhrYbtgzPgZjaC9c8v5edBRYPXHZhNux5muupbeygXB8WnJg9W9nCPRQQJSwPCTJznsmygJ94ojRYgnFPQFP4Zu4TJxz1adFXy",
            "xpub6DqTtMuqBiBsHirAP1Tfm7w6ASuGqWTpn9A7efDwmYZd5bMfCuxtmBgMmVufK49sKpXgyxMhb7jYwMDa6nSzRjWry5xgDzjqrDxDqcPteqo"
        ]
    )


    # res = command.register_wallet(wallet)
    # print("Result:", res)

    # res = command.get_pubkey("m/44'/0'/0'", False)
    # print("Result:", res)
    # res = command.get_pubkey("m/44'/0'/1'", False)
    # print("Result:", res)
    # res = command.get_pubkey("m/44'/0'/2'", False)
    # print("Result:", res)

    # sig = bytes.fromhex("304402206cb79a3542249e38db4c1bbce4c797bb68867f487e26b5bc4701feb1abe73afb022007c0410b214b218d1ff04f3211b64ab97ee616e9a12dbe87881a846e9ccb8749")

    command.get_address(AddrType.PKH, "m/44'/0'/0'/0/0", True)

    sig = bytes.fromhex("3045022100dfbb33c2dff01a80aa3f2592c4c284aa00ef4e4f1b10e8fbf70581b7b79ef76802206d042b876bb3fb5caea0a928acb2b0543f95106375cc12e6119aa582dfac209a")

    for addr_type in [ScriptAddrType.PSH, ScriptAddrType.SH_WPSH, ScriptAddrType.WPSH]:
        res = command.get_wallet_address(addr_type, wallet, sig, 0, True)

        print("Result:", res)



    command.transport.close()



if __name__ == "__main__":
    main()
