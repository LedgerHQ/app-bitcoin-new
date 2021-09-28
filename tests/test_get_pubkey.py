import threading

import pytest

from bitcoin_client.command import BitcoinCommand
from bitcoin_client.exception import DenyError, NotSupportedError

from speculos.client import SpeculosClient


def test_get_pubkey_standard_nodisplay(cmd: BitcoinCommand):
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
        assert pubkey == cmd.get_pubkey(
            bip32_path=path,
            display=False
        )


def test_get_pubkey_nonstandard_nodisplay(cmd: BitcoinCommand):
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
        "m/44'/1'/10'/0",  # missing address_index
        "m/44'/1'/10'/2/3",  # change bigger than 1
        "m/44'/1'/10'/0/3/5",  # no derivation steps expected after address_index
    ]

    for path in testcases:
        with pytest.raises(NotSupportedError):
            cmd.get_pubkey(
                bip32_path=path,
                display=False
            )


def test_get_pubkey_non_standard(client: SpeculosClient, cmd: BitcoinCommand):
    # Test the successful UX flow for a non-standard path (here, root path)
    # (Slow test, not feasible to repeat it for many paths)

    if not isinstance(client, SpeculosClient):
        pytest.skip("Requires speculos")

    def ux_thread():
        event = client.wait_for_text_event("path is unusual")

        # press right until the last screen (will press the "right" button more times than needed)
        while "Reject" != event["text"]:
            client.press_and_release("right")

            event = client.get_next_event()

        # go back to the Accept screen, then accept
        client.press_and_release("left")
        client.press_and_release("both")

    x = threading.Thread(target=ux_thread)
    x.start()

    pub_key = cmd.get_pubkey(
        bip32_path="m",  # root pubkey
        display=True
    )

    x.join()

    assert pub_key == "tpubD6NzVbkrYhZ4YgUx2ZLNt2rLYAMTdYysCRzKoLu2BeSHKvzqPaBDvf17GeBPnExUVPkuBpx4kniP964e2MxyzzazcXLptxLXModSVCVEV1T"


def test_get_pubkey_non_standard_reject_early(client: SpeculosClient, cmd: BitcoinCommand):
    # Test rejecting after the "Reject if you're not sure" warning
    # (Slow test, not feasible to repeat it for many paths)

    if not isinstance(client, SpeculosClient):
        pytest.skip("Requires speculos")

    def ux_thread():
        client.wait_for_text_event("path is unusual")
        client.press_and_release("right")
        client.wait_for_text_event("Confirm public key")
        client.press_and_release("right")
        client.wait_for_text_event("111'/222'/333'")
        client.press_and_release("right")
        client.wait_for_text_event("not sure")  # second line of "Reject if you're not sure"
        client.press_and_release("both")

    x = threading.Thread(target=ux_thread)
    x.start()

    with pytest.raises(DenyError):
        cmd.get_pubkey(
            bip32_path="m/111'/222'/333'",
            display=True
        )

    x.join()


def test_get_pubkey_non_standard_reject(client: SpeculosClient, cmd: BitcoinCommand):
    # Test rejecting at the end
    # (Slow test, not feasible to repeat it for many paths)

    if not isinstance(client, SpeculosClient):
        pytest.skip("Requires speculos")

    def ux_thread():
        event = client.wait_for_text_event("path is unusual")

        # press right until the last screen (will press the "right" button more times than needed)
        while "Reject" != event["text"]:
            client.press_and_release("right")

            event = client.get_next_event()

        # finally, reject
        client.press_and_release("both")

    x = threading.Thread(target=ux_thread)
    x.start()

    with pytest.raises(DenyError):
        cmd.get_pubkey(
            bip32_path="m/111'/222'/333'",
            display=True
        )

    x.join()
