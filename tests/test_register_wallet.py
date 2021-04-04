from bitcoin_client.bitcoin_cmd_builder import AddrType
from bitcoin_client.exception import DenyError
from bitcoin_client.wallet import MultisigWallet, AddressType
from utils import automation
from typing import List

from hashlib import sha256
from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey
from ecdsa.util import sigdecode_der


import pytest

# default speculos seed: glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin
# root extended private key: xprv9s21ZrQH143K4QDdULpHJyaEf1RKEhkxHaUReQSGHQ9Qhqzymp1tER1oBLqxePyRHepCzh3wnEoQR77ygSiEXzx9hVF7E8KEGqHLQqEmF9v
# root private key (hex): 34ac5d784ebb4df4727bcddf6a6743f5d5d46d83dd74aa825866390c694f2938
# root extended public key: xpub661MyMwAqRbcGtJ6aNMHg7WyD3FoeAUoeoQ2SnqsqjgPaeL8KML8nDLH2c6cFk1EhVDzaFSCDgtLSua2dW7k7Z8hYvbXDRgHmr32jBV1S12
# root compressed public key (hex): 0251ec84e33a3119486461a44240e906ff94bf40cf807b025b1ca43332b80dc9db

root_compressed_pk = "0251ec84e33a3119486461a44240e906ff94bf40cf807b025b1ca43332b80dc9db"

wallet = MultisigWallet(
    name="Cold storage",
    address_type=AddressType.SH_WIT,
    threshold=2,
    keys_info=[
        "[61e4f658]xpub6Dk2M8SzqzeRyuYuSJ1Vy5uRBvKfV7625LoME3KsDYRuEL8dww4MSQWMEkLLuJF9UK86hZUtRmqx1LSd1c6boq24dyq4E8UEPypQsSxupQ2",
        "[acc1fe38]xpub6EZ2Bt4cGEhrYbtgzPgZjaC9c8v5edBRYPXHZhNux5muupbeygXB8WnJg9W9nCPRQQJSwPCTJznsmygJ94ojRYgnFPQFP4Zu4TJxz1adFXy",
        "[ba16e65d]xpub6DqTtMuqBiBsHirAP1Tfm7w6ASuGqWTpn9A7efDwmYZd5bMfCuxtmBgMmVufK49sKpXgyxMhb7jYwMDa6nSzRjWry5xgDzjqrDxDqcPteqo"
    ]
)

@automation("automations/register_wallet_accept.json")
def test_register_wallet_accept(cmd):
    wallet_id, sig = cmd.register_wallet(wallet)

    assert wallet_id == wallet.id.hex()

    pk: VerifyingKey = VerifyingKey.from_string(
        bytes.fromhex(root_compressed_pk),
        curve=SECP256k1,
        hashfunc=sha256
    )

    assert pk.verify(signature=bytes.fromhex(sig),
                     data=wallet.serialize(),
                     hashfunc=sha256,
                     sigdecode=sigdecode_der) is True

@automation("automations/register_wallet_reject.json")
def test_register_wallet_reject_header(cmd):
    with pytest.raises(DenyError):
        cmd.register_wallet(wallet)

# TODO: add more tests for:
#  - rejections at different stages
#  - responses to different types of wrong data from the host
