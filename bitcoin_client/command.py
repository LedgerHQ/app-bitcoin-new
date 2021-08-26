from typing import Tuple, List, Mapping, Generator, Optional
import base64
from io import BytesIO, BufferedReader

from ledgercomm import Transport
from speculos.client import ApduException, ApduResponse

from bitcoin_client.command_builder import BitcoinCommandBuilder, BitcoinInsType
from bitcoin_client.common import AddressType
from bitcoin_client.exception import DeviceException

from bitcoin_client.client_command import ClientCommandInterpreter

from bitcoin_client.merkle import get_merkleized_map_commitment
from bitcoin_client.wallet import Wallet, WalletType, PolicyMapWallet
from bitcoin_client.psbt import PSBT, deser_string


def parse_stream_to_map(f: BufferedReader) -> Mapping[bytes, bytes]:
    result = {}
    while True:
        try:
            key = deser_string(f)
        except Exception:
            break

        # Check for separator
        if len(key) == 0:
            break

        value = deser_string(f)

        result[key] = value
    return result


class HIDClient:
    def __init__(self):
        self.transport = Transport("hid")  # TODO: other params

    def apdu_exchange(
        self, cla: int, ins: int, data: bytes = b"", p1: int = 0, p2: int = 0
    ) -> bytes:
        sw, data = self.transport.exchange(cla, ins, p1, p2, None, data)

        if sw != 0x9000:
            raise ApduException(sw, data)

        return data

    def apdu_exchange_nowait(
        self, cla: int, ins: int, data: bytes = b"", p1: int = 0, p2: int = 0
    ) -> Generator[ApduResponse, None, None]:
        raise NotImplementedError()

    def stop(self) -> None:
        self.transport.close()


class BitcoinCommand:
    def __init__(self, client: HIDClient, debug: bool = False) -> None:
        self.client = client
        self.builder = BitcoinCommandBuilder(debug=debug)
        self.debug = debug

    def _apdu_exchange(self, apdu: dict) -> Tuple[int, bytes]:
        try:
            return 0x9000, self.client.apdu_exchange(**apdu)
        except ApduException as e:
            return e.sw, e.data

    def make_request(
        self, apdu: dict, client_intepreter: ClientCommandInterpreter = None
    ) -> Tuple[int, bytes]:
        sw, response = self._apdu_exchange(apdu)

        while sw == 0xE000:
            if not client_intepreter:
                raise RuntimeError("Unexpected SW_INTERRUPTED_EXECUTION received.")

            command_response = client_intepreter.execute(response)
            sw, response = self._apdu_exchange(
                self.builder.continue_interrupted(command_response)
            )

        return sw, response

    def get_pubkey(self, bip32_path: str, display: bool = False) -> str:
        """Gets the serialized extended public key for certain BIP32 path. Optionally, validate with the user.

        Parameters
        ----------
        bip32_path : str
            BIP32 path of the public key you want.
        display : bool
            Whether you want to display address and ask confirmation on the device.

        Returns
        -------
        str
            The requested serialized extended public key.
        """

        sw, response = self.make_request(self.builder.get_pubkey(bip32_path, display))

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_PUBKEY)

        return response.decode()

    def get_address(
        self, address_type: AddressType, bip32_path: str, display: bool = False
    ) -> str:
        """Get an address given address type and BIP32 path. Optionally, validate with the user.

        Parameters
        ----------
        address_type : AddressType
            Type of address. Could be AddressType.LEGACY, AddressType.WIT, AddressType.SH_WIT.
        bip32_path : str
            BIP32 path of the public key you want.
        display : bool
            Whether you want to display address and ask confirmation on the device.

        Returns
        -------
        str
            The requested address.
        """
        sw, response = self.make_request(
            self.builder.get_address(address_type, bip32_path, display)
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_PUBKEY)

        return response.decode()

    def register_wallet(self, wallet: Wallet) -> Tuple[bytes, bytes]:
        """Registers a wallet policy with the user. After approval returns the wallet id and hmac to be stored on the client.

        Parameters
        ----------
        wallet : Wallet
            The Wallet policy to register on the device.

        Returns
        -------
        Tuple[bytes, bytes]
            The first element the tuple is the 32-bytes wallet id.
            The second element is the hmac.
        """

        if wallet.type != WalletType.POLICYMAP:
            raise ValueError("wallet type must be POLICYMAP")

        client_intepreter = ClientCommandInterpreter()
        client_intepreter.add_known_preimage(wallet.serialize())
        client_intepreter.add_known_list([k.encode() for k in wallet.keys_info])

        sw, response = self.make_request(
            self.builder.register_wallet(wallet), client_intepreter
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.REGISTER_WALLET)

        if len(response) != 64:
            raise RuntimeError(f"Invalid response length: {len(response)}")

        wallet_id = response[0:32]
        wallet_hmac = response[32:64]

        return wallet_id, wallet_hmac

    def get_wallet_address(
        self,
        wallet: Wallet,
        wallet_hmac: Optional[bytes],
        change: int,
        address_index: int,
        display: bool,
    ) -> str:
        """For a given wallet that was already registered on the device (or a standard wallet that does not need registration),
        returns the address for a certain `change`/`address_index` combination.

        Parameters
        ----------
        wallet : Wallet
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

        if wallet.type != WalletType.POLICYMAP or not isinstance(
            wallet, PolicyMapWallet
        ):
            raise ValueError("wallet type must be POLICYMAP")

        if change != 0 and change != 1:
            raise ValueError("Invalid change")

        client_intepreter = ClientCommandInterpreter()
        client_intepreter.add_known_list([k.encode() for k in wallet.keys_info])
        client_intepreter.add_known_preimage(wallet.serialize())

        sw, response = self.make_request(
            self.builder.get_wallet_address(
                wallet, wallet_hmac, address_index, change, display
            ),
            client_intepreter,
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_WALLET_ADDRESS)

        return response.decode()

    # TODO: should we return an updated PSBT with signatures, instead?
    def sign_psbt(self, psbt: PSBT, wallet: Wallet, wallet_hmac: Optional[bytes]) -> Mapping[int, bytes]:
        """Signs a PSBT using a registered wallet (or a standard wallet that does not need registration).

        Signature requires explicit approval from the user.

        Parameters
        ----------
        psbt : PSBT
            A PSBT of version 0 or 2, with all the necessary information to sign the inputs already filled in; what the
            required fields changes depending on the type of input.
            The non-witness UTXO must be present for both legacy and SegWit inputs, or the hardware wallet will reject
            signing (this will change for Taproot inputs).

        wallet : Wallet
            The registered wallet policy, or a standard wallet policy.

        wallet_hmac: Optional[bytes]
            For a registered wallet, the hmac obtained at wallet registration. `None` for a standard wallet policy.

        Returns
        -------
        Mapping[int, bytes]
            A mapping that has as keys the indexes of inputs that the Hardware Wallet signed, and the corresponding signatures as values.
        """
        if psbt.version != 2:
            psbt_v2 = PSBT()
            psbt_v2.deserialize(psbt.serialize())  # clone psbt
            psbt_v2.to_psbt_v2()
        else:
            psbt_v2 = psbt

        psbt_bytes = base64.b64decode(psbt_v2.serialize())
        f = BytesIO(psbt_bytes)

        # We parse the individual maps (global map, each input map, and each output map) from the psbt serialized as a
        # sequence of bytes, in order to produce the serialized Merkleized map commitments. Moreover, we prepare the
        # client interpreter to respond on queries on all the relevant Merkle trees and pre-images in the psbt.

        assert f.read(5) == b"psbt\xff"

        client_intepreter = ClientCommandInterpreter()
        client_intepreter.add_known_list([k.encode() for k in wallet.keys_info])
        client_intepreter.add_known_preimage(wallet.serialize())

        global_map: Mapping[bytes, bytes] = parse_stream_to_map(f)
        client_intepreter.add_known_mapping(global_map)

        input_maps: List[Mapping[bytes, bytes]] = []
        for _ in range(psbt_v2.input_count):
            input_maps.append(parse_stream_to_map(f))
        for m in input_maps:
            client_intepreter.add_known_mapping(m)

        output_maps: List[Mapping[bytes, bytes]] = []
        for _ in range(psbt_v2.output_count):
            output_maps.append(parse_stream_to_map(f))
        for m in output_maps:
            client_intepreter.add_known_mapping(m)

        # We also add the Merkle tree of the input (resp. output) map commitments as a known tree
        input_commitments = [get_merkleized_map_commitment(m_in) for m_in in input_maps]
        output_commitments = [get_merkleized_map_commitment(m_out) for m_out in output_maps]

        client_intepreter.add_known_list(input_commitments)
        client_intepreter.add_known_list(output_commitments)

        sw, _ = self.make_request(
            self.builder.sign_psbt(
                global_map, input_maps, output_maps, wallet, wallet_hmac
            ),
            client_intepreter,
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.SIGN_PSBT)

        # parse results and return a structured version instead
        results = client_intepreter.yielded

        if any(len(x) <= 1 for x in results):
            raise RuntimeError("Invalid response")

        return {int(res[0]): res[1:] for res in results}

    def get_master_fingerprint(self) -> bytes:
        """Gets the fingerprint of the master public key, as per BIP-32.

        Returns
        -------
        bytes
            The fingerprint of the master public key, as an array of 4 bytes.
        """

        sw, response = self.make_request(self.builder.get_master_fingerprint())

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_PUBKEY)

        return response
