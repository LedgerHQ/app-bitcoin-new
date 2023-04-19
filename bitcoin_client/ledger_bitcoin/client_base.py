from dataclasses import dataclass
from typing import List, Tuple, Optional, Union, Literal
from io import BytesIO

from ledgercomm.interfaces.hid_device import HID

from .transport import Transport

from .common import Chain

from .command_builder import DefaultInsType
from .exception import DeviceException

from .wallet import WalletPolicy
from .psbt import PSBT
from ._serialize import deser_string

try:
    from speculos.client import ApduException
except ImportError:
    # Speculos package not available, we use our own class
    class ApduException(Exception):
        def __init__(self, sw: int, data: bytes) -> None:
            super().__init__(f"Exception: invalid status 0x{sw:x}")
            self.sw = sw
            self.data = data


class TransportClient:
    def __init__(self, interface: Literal['hid', 'tcp'] = "tcp", *, server: str = "127.0.0.1", port: int = 9999, path: Optional[str] = None, hid: Optional[HID] = None, debug: bool = False):
        self.transport = Transport('hid', path=path, hid=hid, debug=debug) if interface == 'hid' else Transport(interface, server=server, port=port, debug=debug)

    def apdu_exchange(
        self, cla: int, ins: int, data: bytes = b"", p1: int = 0, p2: int = 0
    ) -> bytes:
        sw, data = self.transport.exchange(cla, ins, p1, p2, None, data)

        if sw != 0x9000:
            raise ApduException(sw, data)

        return data

    def apdu_exchange_nowait(
        self, cla: int, ins: int, data: bytes = b"", p1: int = 0, p2: int = 0
    ):
        raise NotImplementedError()

    def stop(self) -> None:
        self.transport.close()


def print_apdu(apdu_dict: dict) -> None:
    serialized_apdu = b''.join([
        apdu_dict["cla"].to_bytes(1, byteorder='big'),
        apdu_dict["ins"].to_bytes(1, byteorder='big'),
        apdu_dict["p1"].to_bytes(1, byteorder='big'),
        apdu_dict["p2"].to_bytes(1, byteorder='big'),
        len(apdu_dict["data"]).to_bytes(1, byteorder='big'),
        apdu_dict["data"]
    ])
    print(f"=> {serialized_apdu.hex()}")


def print_response(sw: int, data: bytes) -> None:
    print(f"<= {data.hex()}{sw.to_bytes(2, byteorder='big').hex()}")


@dataclass(frozen=True)
class PartialSignature:
    """Represents a partial signature returned by sign_psbt.

    It always contains a pubkey and a signature.
    The pubkey

    The tapleaf_hash is also filled if signing a for a tapscript.
    """
    pubkey: bytes
    signature: bytes
    tapleaf_hash: Optional[bytes] = None


class Client:
    def __init__(self, transport_client: TransportClient, chain: Chain = Chain.MAIN, debug: bool = False) -> None:
        self.transport_client = transport_client
        self.chain = chain
        self.debug = debug

    def _apdu_exchange(self, apdu: dict) -> Tuple[int, bytes]:
        try:
            if self.debug:
                print_apdu(apdu)

            response = self.transport_client.apdu_exchange(**apdu)
            if self.debug:
                print_response(0x9000, response)

            return 0x9000, response
        except ApduException as e:
            if self.debug:
                print_response(e.sw, e.data)

            return e.sw, e.data

    def _make_request(self, apdu: dict) -> Tuple[int, bytes]:
        return self._apdu_exchange(apdu)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.transport_client.stop()

    def stop(self) -> None:
        """Stops the transport_client."""

        self.transport_client.stop()

    def get_version(self) -> Tuple[str, str, bytes]:
        """Queries the hardware wallet for the currently running app's name, version and state flags.

        Returns
        -------
        Tuple[str, str, bytes]
            The first element is the app's name, as a short string.
            The second element is the app's version.
            The third element is a binary string representing the platform's global state (pin lock etc).
        """

        sw, response = self._make_request(
            {"cla": 0xB0, "ins": DefaultInsType.GET_VERSION, "p1": 0, "p2": 0, "data": b''})

        if sw != 0x9000:
            raise DeviceException(
                error_code=sw, ins=DefaultInsType.GET_VERSION)

        r = BytesIO(response)

        format = r.read(1)

        app_name = deser_string(r)
        app_version = deser_string(r)
        app_flags = deser_string(r)

        if format != b'\1' or app_name == b'' or app_version == b'' or app_flags == b'':
            raise DeviceException(error_code=sw, ins=DefaultInsType.GET_VERSION,
                                  message="Invalid format returned by GET_VERSION")

        return app_name.decode(), app_version.decode(), app_flags

    def get_extended_pubkey(self, path: str, display: bool = False) -> str:
        """Gets the serialized extended public key for certain BIP32 path. Optionally, validate with the user.

        Parameters
        ----------
        path : str
            BIP32 path of the public key you want.
        display : bool
            Whether you want to display address and ask confirmation on the device.

        Returns
        -------
        str
            The requested serialized extended public key.
        """

        raise NotImplementedError

    def register_wallet(self, wallet: WalletPolicy) -> Tuple[bytes, bytes]:
        """Registers a wallet policy with the user. After approval returns the wallet id and hmac to be stored on the client.

        Parameters
        ----------
        wallet : WalletPolicy
            The Wallet policy to register on the device.

        Returns
        -------
        Tuple[bytes, bytes]
            The first element the tuple is the 32-bytes wallet id.
            The second element is the hmac.
        """

        raise NotImplementedError

    def get_wallet_address(
        self,
        wallet: WalletPolicy,
        wallet_hmac: Optional[bytes],
        change: int,
        address_index: int,
        display: bool,
    ) -> str:
        """For a given wallet that was already registered on the device (or a standard wallet that does not need registration),
        returns the address for a certain `change`/`address_index` combination.

        Parameters
        ----------
        wallet : WalletPolicy
            The registered wallet policy, or a standard wallet policy.

        wallet_hmac: Optional[bytes]
            For a registered wallet, the hmac obtained at wallet registration. `None` for a standard wallet policy.

        change: int
            0 for a standard receive address, 1 for a change address. Other values are invalid.

        address_index: int
            The address index in the last step of the BIP32 derivation.

        display: bool
            Whether you want to display address and ask confirmation on the device.

        Returns
        -------
        str
            The requested address.
        """

        raise NotImplementedError

    def sign_psbt(self, psbt: Union[PSBT, bytes, str], wallet: WalletPolicy, wallet_hmac: Optional[bytes]) -> List[Tuple[int, PartialSignature]]:
        """Signs a PSBT using a registered wallet (or a standard wallet that does not need registration).

        Signature requires explicit approval from the user.

        Parameters
        ----------
        psbt : PSBT | bytes | str
            A PSBT of version 0 or 2, with all the necessary information to sign the inputs already filled in; what the
            required fields changes depending on the type of input.
            The non-witness UTXO must be present for both legacy and SegWit inputs, or the hardware wallet will reject
            signing (this will change for Taproot inputs).
            The argument can be either a `PSBT` object, or `bytes`, or a base64-encoded `str`.

        wallet : WalletPolicy
            The registered wallet policy, or a standard wallet policy.

        wallet_hmac: Optional[bytes]
            For a registered wallet, the hmac obtained at wallet registration. `None` for a standard wallet policy.

        Returns
        -------
        List[Tuple[int, PartialSignature]]
            A list of tuples returned by the hardware wallets, where each element is a tuple of:
            - an integer, the index of the input being signed;
            - an instance of `PartialSignature`.
        """

        raise NotImplementedError

    def get_master_fingerprint(self) -> bytes:
        """Gets the fingerprint of the master public key, as per BIP-32.

        Returns
        -------
        bytes
            The fingerprint of the master public key, as an array of 4 bytes.
        """

        raise NotImplementedError

    def sign_message(self, message: Union[str, bytes], bip32_path: str) -> str:
        """
        Sign a message (bitcoin message signing).
        Signs a message using the legacy Bitcoin Core signed message format.
        The message is signed with the key at the given path.
        :param message: The message to be signed. First encoded as bytes if not already.
        :param bip32_path: The BIP 32 derivation for the key to sign the message with.
        :return: The signature
        """
        raise NotImplementedError
