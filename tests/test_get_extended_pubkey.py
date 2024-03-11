import pytest

from ragger_bitcoin import RaggerClient
from ragger.navigator import Navigator
from ragger.firmware import Firmware
from ragger.error import ExceptionRAPDU

from ledger_bitcoin.exception.errors import NotSupportedError, DenyError
from ledger_bitcoin.exception.device_exception import DeviceException
from .instructions import pubkey_instruction_approve, pubkey_instruction_reject_early, pubkey_reject


def test_get_extended_pubkey_standard_display(navigator: Navigator, firmware: Firmware, client:
                                              RaggerClient, test_name: str):
    testcases = {
        "m/44'/1'/0'": "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT",
        "m/44'/1'/10'": "tpubDCwYjpDhUdPGp21gSpVay2QPJVh6WNySWMXPhbcu1DsxH31dF7mY18oibbu5RxCLBc1Szerjscuc3D5HyvfYqfRvc9mesewnFqGmPjney4d",
        "m/44'/1'/2'/1/42": "tpubDGF9YgHKv6qh777rcqVhpmDrbNzgophJM9ec7nHiSfrbss7fVBXoqhmZfohmJSvhNakDHAspPHjVVNL657tLbmTXvSeGev2vj5kzjMaeupT",
        "m/48'/1'/4'/1'/0/7": "tpubDK8WPFx4WJo1R9mEL7Wq325wBiXvkAe8ipgb9Q1QBDTDUD2YeCfutWtzY88NPokZqJyRPKHLGwTNLT7jBG59aC6VH8q47LDGQitPB6tX2d7",
        "m/49'/1'/1'/1/3": "tpubDGnetmJDCL18TyaaoyRAYbkSE9wbHktSdTS4mfsR6inC8c2r6TjdBt3wkqEQhHYPtXpa46xpxDaCXU2PRNUGVvDzAHPG6hHRavYbwAGfnFr",
        "m/84'/1'/2'/0/10": "tpubDG9YpSUwScWJBBSrhnAT47NcT4NZGLcY18cpkaiWHnkUCi19EtCh8Heeox268NaFF6o56nVeSXuTyK6jpzTvV1h68Kr3edA8AZp27MiLUNt",
        "m/86'/1'/4'/1/12": "tpubDHTZ815MvTaRmo6Qg1rnU6TEU4ZkWyA56jA1UgpmMcBGomnSsyo34EZLoctzZY9MTJ6j7bhccceUeXZZLxZj5vgkVMYfcZ7DNPsyRdFpS3f",
    }

    for path, pubkey in testcases.items():
        assert pubkey == client.get_extended_pubkey(
            path=path,
            display=True,
            navigator=navigator,
            instructions=pubkey_instruction_approve(firmware),
            testname=f"{test_name}_{path}"
        )


def test_get_extended_pubkey_standard_nodisplay(client: RaggerClient):
    testcases = {
        "m/44'/1'/0'": "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT",
        "m/44'/1'/10'": "tpubDCwYjpDhUdPGp21gSpVay2QPJVh6WNySWMXPhbcu1DsxH31dF7mY18oibbu5RxCLBc1Szerjscuc3D5HyvfYqfRvc9mesewnFqGmPjney4d",
        "m/44'/1'/2'/1/42": "tpubDGF9YgHKv6qh777rcqVhpmDrbNzgophJM9ec7nHiSfrbss7fVBXoqhmZfohmJSvhNakDHAspPHjVVNL657tLbmTXvSeGev2vj5kzjMaeupT",
        "m/48'/1'/4'/1'/0/7": "tpubDK8WPFx4WJo1R9mEL7Wq325wBiXvkAe8ipgb9Q1QBDTDUD2YeCfutWtzY88NPokZqJyRPKHLGwTNLT7jBG59aC6VH8q47LDGQitPB6tX2d7",
        "m/49'/1'/1'/1/3": "tpubDGnetmJDCL18TyaaoyRAYbkSE9wbHktSdTS4mfsR6inC8c2r6TjdBt3wkqEQhHYPtXpa46xpxDaCXU2PRNUGVvDzAHPG6hHRavYbwAGfnFr",
        "m/84'/1'/2'/0/10": "tpubDG9YpSUwScWJBBSrhnAT47NcT4NZGLcY18cpkaiWHnkUCi19EtCh8Heeox268NaFF6o56nVeSXuTyK6jpzTvV1h68Kr3edA8AZp27MiLUNt",
        "m/86'/1'/4'/1/12": "tpubDHTZ815MvTaRmo6Qg1rnU6TEU4ZkWyA56jA1UgpmMcBGomnSsyo34EZLoctzZY9MTJ6j7bhccceUeXZZLxZj5vgkVMYfcZ7DNPsyRdFpS3f",
        # support up to 8 steps
        "m/86'/1'/4'/1/2/3/4/5": "tpubDNcjumrTe1BBYEc1FmMaJZQw47mbvb4LfX4YwqC6GQ18PfMfuH3BEYREfdHm2gWXkSJ3JiXHF11iKnbJxzxp5qkgo8BBy2L48FRvrLhpTuh",
        # the following two paths test compatibility with Unchained Capital's multisig setup
        "m/45'/1'/0'": "tpubDCy2BKyxJFzACNgThkunvdnkHNotREK9LQDw8L9J1gx26SyzfoeJynJgWekzkramggmahVAgeHPxfpnvFtJ7hcYADrsVUnsPSei2tY9fBLL",
        "m/45'/1'/0'/1": "tpubDFGDxRGdGFKekUtPuta4p9Kw2a2PSeyyhSTa7KNENJfBuJ78EEsL1LxwAA8ddSxZFWBT9gYRuLDoa2rwdix56WRsq77vAJ2iqeyPw6UBeyt",
    }

    for path, pubkey in testcases.items():
        assert pubkey == client.get_extended_pubkey(
            path=path,
            display=False
        )


def test_get_extended_pubkey_nonstandard_nodisplay(client: RaggerClient):
    # as these paths are not standard, the app should reject immediately if display=False
    testcases = [
        "m",  # unusual to export the root key
        "m/44'",
        "m/44'/1'",
        "m/44'/10'/0'",  # wrong coin_type
        "m/44'/1'/0",  # first step should be hardened
        "m/44'/1/0'",  # second step should be hardened
        "m/44/1'/0'",  # third step should be hardened
        "m/48'/1'/0'/0'",  # script_type is 1' or 2' for BIP-0048
        "m/48'/1'/0'/3'",  # script_type is 1' or 2' for BIP-0048
        "m/999'/1'/0'",  # no standard with this purpose
    ]

    for path in testcases:
        with pytest.raises(ExceptionRAPDU) as e:
            client.get_extended_pubkey(
                path=path,
                display=False
            )
        assert DeviceException.exc.get(e.value.status) == NotSupportedError
        assert len(e.value.data) == 0


def test_get_extended_pubkey_non_standard(navigator: Navigator, firmware: Firmware, client:
                                          RaggerClient,
                                          test_name: str):
    # Test the successful UX flow for a non-standard path (here, root path)
    # (Slow test, not feasible to repeat it for many paths)

    pub_key = client.get_extended_pubkey(
        path="m",  # root pubkey
        display=True,
        navigator=navigator,
        instructions=pubkey_instruction_approve(firmware),
        testname=test_name
    )

    assert pub_key == "tpubD6NzVbkrYhZ4YgUx2ZLNt2rLYAMTdYysCRzKoLu2BeSHKvzqPaBDvf17GeBPnExUVPkuBpx4kniP964e2MxyzzazcXLptxLXModSVCVEV1T"


def test_get_extended_pubkey_non_standard_reject_early(navigator: Navigator, firmware: Firmware,
                                                       client: RaggerClient, test_name: str):
    # Test rejecting after the "Reject if you're not sure" warning
    # (Slow test, not feasible to repeat it for many paths)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_extended_pubkey(
            path="m/111'/222'/333'",
            display=True,
            navigator=navigator,
            instructions=pubkey_instruction_reject_early(firmware),
            testname=test_name
        )
    assert DeviceException.exc.get(e.value.status) == DenyError
    assert len(e.value.data) == 0


def test_get_extended_pubkey_non_standard_reject(navigator: Navigator, firmware: Firmware, client:
                                                 RaggerClient, test_name: str):
    # Test rejecting at the end
    # (Slow test, not feasible to repeat it for many paths)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_extended_pubkey(
            path="m/111'/222'/333'",
            display=True,
            navigator=navigator,
            instructions=pubkey_reject(firmware),
            testname=test_name,
        )
    assert DeviceException.exc.get(e.value.status) == DenyError
    assert len(e.value.data) == 0
