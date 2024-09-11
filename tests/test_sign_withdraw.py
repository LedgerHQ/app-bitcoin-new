import pytest

from ledger_bitcoin.exception.errors import DenyError
from ledger_bitcoin.exception.device_exception import DeviceException
from ragger.navigator import Navigator
from ragger.firmware import Firmware
from ragger.error import ExceptionRAPDU
from ragger_bitcoin import RaggerClient
from ledger_bitcoin.withdraw import AcreWithdrawalData
from .instructions import withdrawal_instruction_approve, message_instruction_reject


def test_sign_withdraw(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    data = AcreWithdrawalData(
        to= "0xc14972DC5a4443E4f5e89E3655BE48Ee95A795aB",
        value= "0x0",
        data= "0xcae9ca510000000000000000000000000e781e9d538895ee99bd6e9bf28664942beff32f00000000000000000000000000000000000000000000000000470de4df820000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001000000000000000000000000006083Bde64CCBF08470a1a0dAa9a0281B4951be7C4b5e4623765ec95cfa6e261406d5c446012eff9300000000000000000000000008dcc842b8ed75efe1f222ebdc22d1b06ef35efff6469f708057266816f0595200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000587f579c500000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000001a1976a9143c6480044cfafde6dad7f718f76938cc87d0679a88ac000000000000",
        operation= "0",
        safeTxGas= "0x0",
        baseGas= "0x0",
        gasPrice= "0x0",
        gasToken= "0x0000000000000000000000000000000000000000",
        refundReceiver= "0x0000000000000000000000000000000000000000",
        nonce= "0xC",
    )
    path = "m/44'/1'/0'/0/0"
    result = client.sign_withdraw(data, path, navigator,
                                 instructions=withdrawal_instruction_approve(firmware),
                                 testname=test_name)

    # assert result == ...
    assert 1 == 1