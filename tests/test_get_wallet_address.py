from bitcoin_client.bitcoin_cmd_builder import AddrType
from bitcoin_client.exception import DenyError
from bitcoin_client.wallet import MultisigWallet

from utils import automation
from typing import List
from bitcoin_client.bitcoin_cmd_builder import ScriptAddrType

import pytest


# default speculos seed: glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin
# root extended private key: xprv9s21ZrQH143K4QDdULpHJyaEf1RKEhkxHaUReQSGHQ9Qhqzymp1tER1oBLqxePyRHepCzh3wnEoQR77ygSiEXzx9hVF7E8KEGqHLQqEmF9v
# root private key (hex): 34ac5d784ebb4df4727bcddf6a6743f5d5d46d83dd74aa825866390c694f2938
# root extended public key: xpub661MyMwAqRbcGtJ6aNMHg7WyD3FoeAUoeoQ2SnqsqjgPaeL8KML8nDLH2c6cFk1EhVDzaFSCDgtLSua2dW7k7Z8hYvbXDRgHmr32jBV1S12
# root compressed public key (hex): 0251ec84e33a3119486461a44240e906ff94bf40cf807b025b1ca43332b80dc9db

wallet = MultisigWallet(
    name = "Cold storage",
    threshold = 2,
    n_keys = 3,
    pubkeys = [
        "xpub6DqTtMuqBiBsHirAP1Tfm7w6ASuGqWTpn9A7efDwmYZd5bMfCuxtmBgMmVufK49sKpXgyxMhb7jYwMDa6nSzRjWry5xgDzjqrDxDqcPteqo",
        "xpub6Dk2M8SzqzeRyuYuSJ1Vy5uRBvKfV7625LoME3KsDYRuEL8dww4MSQWMEkLLuJF9UK86hZUtRmqx1LSd1c6boq24dyq4E8UEPypQsSxupQ2",
        "xpub6EZ2Bt4cGEhrYbtgzPgZjaC9c8v5edBRYPXHZhNux5muupbeygXB8WnJg9W9nCPRQQJSwPCTJznsmygJ94ojRYgnFPQFP4Zu4TJxz1adFXy"
    ]
)
wallet_sig = bytes.fromhex("304402206cb79a3542249e38db4c1bbce4c797bb68867f487e26b5bc4701feb1abe73afb022007c0410b214b218d1ff04f3211b64ab97ee616e9a12dbe87881a846e9ccb8749")

def test_get_wallet_address(cmd):

    res = cmd.get_wallet_address(ScriptAddrType.PSH, wallet, wallet_sig, 1)

    print(res)