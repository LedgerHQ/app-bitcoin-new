import pytest

from bitcoin_client.ledger_bitcoin import Client
from bitcoin_client.ledger_bitcoin.client_base import ApduException
from bitcoin_client.ledger_bitcoin.command_builder import BitcoinCommandBuilder, BitcoinInsType, CURRENT_PROTOCOL_VERSION


def test_high_p1_allowed(client: Client):
    # We reserve p1 for feature flags, so non-zero bits shouldn't be rejected
    # for forward-compatibility; this allows graceful degradation for optional features.

    # We can't use the client to send this apdu, so we use raw transport.
    # We're only testing that no exception is raised.
    client.transport_client.apdu_exchange(
        cla=BitcoinCommandBuilder.CLA_BITCOIN,
        ins=BitcoinInsType.GET_MASTER_FINGERPRINT,
        p1=0xff,
        p2=CURRENT_PROTOCOL_VERSION,
        data=b''
    )


def test_p2_too_high(client: Client):
    # Tests that sending a p2 > CURRENT_PROTOCOL_VERSION fails with 0x6a86 (WRONG_P1P2)
    with pytest.raises(ApduException, match="Exception: invalid status 0x6a86"):
        # We can't use the client to send this apdu, so we use raw transport
        client.transport_client.apdu_exchange(
            cla=BitcoinCommandBuilder.CLA_BITCOIN,
            ins=BitcoinInsType.GET_MASTER_FINGERPRINT,
            p1=0,
            p2=CURRENT_PROTOCOL_VERSION + 1,
            data=b''
        )
