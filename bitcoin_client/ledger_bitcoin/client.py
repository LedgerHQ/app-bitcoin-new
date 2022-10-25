from packaging.version import parse as parse_version
from typing import Tuple, List, Mapping, Optional, Union
import base64
from io import BytesIO, BufferedReader

from .command_builder import BitcoinCommandBuilder, BitcoinInsType
from .common import Chain, read_uint, read_varint
from .client_command import ClientCommandInterpreter
from .client_base import Client, TransportClient
from .client_legacy import LegacyClient
from .exception import DeviceException
from .merkle import get_merkleized_map_commitment
from .wallet import WalletPolicy, WalletType
from .psbt import PSBT, normalize_psbt
from ._serialize import deser_string


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


class NewClient(Client):
    # internal use for testing: if set to True, sign_psbt will not clone the psbt before converting to psbt version 2
    _no_clone_psbt: bool = False

    def __init__(self, comm_client: TransportClient, chain: Chain = Chain.MAIN, debug: bool = False) -> None:
        super().__init__(comm_client, chain, debug)
        self.builder = BitcoinCommandBuilder()

    # Modifies the behavior of the base method by taking care of SW_INTERRUPTED_EXECUTION responses
    def _make_request(
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

    def get_extended_pubkey(self, path: str, display: bool = False) -> str:
        sw, response = self._make_request(self.builder.get_extended_pubkey(path, display))

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_EXTENDED_PUBKEY)

        return response.decode()

    def register_wallet(self, wallet: WalletPolicy) -> Tuple[bytes, bytes]:
        if wallet.version not in [WalletType.WALLET_POLICY_V1, WalletType.WALLET_POLICY_V2]:
            raise ValueError("invalid wallet policy version")

        client_intepreter = ClientCommandInterpreter()
        client_intepreter.add_known_preimage(wallet.serialize())
        client_intepreter.add_known_list([k.encode() for k in wallet.keys_info])

        # necessary for version 1 of the protocol (introduced in version 2.1.0)
        client_intepreter.add_known_preimage(wallet.descriptor_template.encode())

        sw, response = self._make_request(
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
        wallet: WalletPolicy,
        wallet_hmac: Optional[bytes],
        change: int,
        address_index: int,
        display: bool,
    ) -> str:

        if not isinstance(wallet, WalletPolicy) or wallet.version not in [WalletType.WALLET_POLICY_V1, WalletType.WALLET_POLICY_V2]:
            raise ValueError("wallet type must be WalletPolicy, with version either WALLET_POLICY_V1 or WALLET_POLICY_V2")

        if change != 0 and change != 1:
            raise ValueError("Invalid change")

        client_intepreter = ClientCommandInterpreter()
        client_intepreter.add_known_list([k.encode() for k in wallet.keys_info])
        client_intepreter.add_known_preimage(wallet.serialize())

        # necessary for version 1 of the protocol (introduced in version 2.1.0)
        client_intepreter.add_known_preimage(wallet.descriptor_template.encode())

        sw, response = self._make_request(
            self.builder.get_wallet_address(
                wallet, wallet_hmac, address_index, change, display
            ),
            client_intepreter,
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_WALLET_ADDRESS)

        return response.decode()

    def sign_psbt(self, psbt: Union[PSBT, bytes, str], wallet: WalletPolicy, wallet_hmac: Optional[bytes]) -> List[Tuple[int, bytes, bytes]]:
        psbt = normalize_psbt(psbt)

        if psbt.version != 2:
            if self._no_clone_psbt:
                psbt.convert_to_v2()
                psbt_v2 = psbt
            else:
                psbt_v2 = PSBT()
                psbt_v2.deserialize(psbt.serialize())  # clone psbt
                psbt_v2.convert_to_v2()
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

        # necessary for version 1 of the protocol (introduced in version 2.1.0)
        client_intepreter.add_known_preimage(wallet.descriptor_template.encode())

        global_map: Mapping[bytes, bytes] = parse_stream_to_map(f)
        client_intepreter.add_known_mapping(global_map)

        input_maps: List[Mapping[bytes, bytes]] = []
        for _ in range(len(psbt_v2.inputs)):
            input_maps.append(parse_stream_to_map(f))
        for m in input_maps:
            client_intepreter.add_known_mapping(m)

        output_maps: List[Mapping[bytes, bytes]] = []
        for _ in range(len(psbt_v2.outputs)):
            output_maps.append(parse_stream_to_map(f))
        for m in output_maps:
            client_intepreter.add_known_mapping(m)

        # We also add the Merkle tree of the input (resp. output) map commitments as a known tree
        input_commitments = [get_merkleized_map_commitment(m_in) for m_in in input_maps]
        output_commitments = [get_merkleized_map_commitment(m_out) for m_out in output_maps]

        client_intepreter.add_known_list(input_commitments)
        client_intepreter.add_known_list(output_commitments)

        sw, _ = self._make_request(
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

        results_list: List[Tuple[int, bytes, bytes]] = []
        for res in results:
            res_buffer = BytesIO(res)
            input_index = read_varint(res_buffer)

            pubkey_len = read_uint(res_buffer, 8)
            pubkey = res_buffer.read(pubkey_len)

            signature = res_buffer.read()

            results_list.append((input_index, pubkey, signature))

        return results_list

    def get_master_fingerprint(self) -> bytes:
        sw, response = self._make_request(self.builder.get_master_fingerprint())

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_EXTENDED_PUBKEY)

        return response

    def sign_message(self, message: Union[str, bytes], bip32_path: str) -> str:
        if isinstance(message, str):
            message_bytes = message.encode("utf-8")
        else:
            message_bytes = message

        chunks = [message_bytes[64 * i: 64 * i + 64] for i in range((len(message_bytes) + 63) // 64)]

        client_intepreter = ClientCommandInterpreter()
        client_intepreter.add_known_list(chunks)

        sw, response = self._make_request(self.builder.sign_message(message_bytes, bip32_path), client_intepreter)

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_EXTENDED_PUBKEY)

        return base64.b64encode(response).decode('utf-8')


def createClient(comm_client: Optional[TransportClient] = None, chain: Chain = Chain.MAIN, debug: bool = False) -> Union[LegacyClient, NewClient]:
    if comm_client is None:
        comm_client = TransportClient("hid")

    base_client = Client(comm_client, chain, debug)
    app_name, app_version, _ = base_client.get_version()

    version = parse_version(app_version)

    # Use the legacy client if either:
    # - the name of the app is "Bitcoin Legacy" or "Bitcoin Test Legacy" (regardless of the version)
    # - the version is strictly less than 2.1
    use_legacy = app_name in ["Bitcoin Legacy", "Bitcoin Test Legacy"] or version.major < 2 or (version.major == 2 and version.minor == 0)

    if use_legacy:
        return LegacyClient(comm_client, chain, debug)
    else:
        return NewClient(comm_client, chain, debug)
