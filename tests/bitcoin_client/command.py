from typing import Tuple, List, Mapping
import base64
from io import BytesIO, BufferedReader

from ledgercomm import Transport

from bitcoin_client.command_builder import (
    BitcoinCommandBuilder,
    BitcoinInsType,
)
from bitcoin_client.common import AddressType
from bitcoin_client.exception import DeviceException

from .client_command import ClientCommandInterpreter

from .merkle import get_merkleized_map_commitment
from .wallet import Wallet, WalletType, PolicyMapWallet
from .psbt import PSBT, deser_string


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
        print(f"Key type: {key[0]}")
        print(f"{key.hex()}:{value.hex()}")

        result[key] = value
    return result


class BitcoinCommand:
    def __init__(self,
                 transport: Transport,
                 debug: bool = False) -> None:
        self.transport = transport
        self.builder = BitcoinCommandBuilder(debug=debug)
        self.debug = debug

    def make_request(self, apdu: bytes, client_intepreter: ClientCommandInterpreter = None) -> Tuple[int, bytes]:
        sw, response = self.transport.exchange_raw(apdu)

        while sw == 0xE000:
            if not client_intepreter:
                raise RuntimeError("Unexpected SW_INTERRUPTED_EXECUTION received.")

            command_response = client_intepreter.execute(response)
            sw, response = self.transport.exchange_raw(
                self.builder.continue_interrupted(command_response))

        return sw, response

    def get_pubkey(self, bip32_path: str, display: bool = False) -> str:
        # TODO: add docs
        sw, response = self.make_request(
            self.builder.get_pubkey(bip32_path, display)
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_PUBKEY)

        return response.decode()

    def get_address(self,
                    address_type: AddressType,
                    bip32_path: str,
                    display: bool = False) -> str:
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

        """
        sw, response = self.make_request(
            self.builder.get_address(address_type, bip32_path, display)
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_PUBKEY)

        return response.decode()

    def register_wallet(self, wallet: Wallet) -> Tuple[bytes, bytes]:
        if wallet.type != WalletType.POLICYMAP:
            raise ValueError("wallet type must be POLICYMAP")

        client_intepreter = ClientCommandInterpreter()
        client_intepreter.add_known_pubkey_list(wallet.keys_info)

        sw, response = self.make_request(
            self.builder.register_wallet(wallet),
            client_intepreter
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.REGISTER_WALLET)

        wallet_id = response[0:32]
        sig_len = response[32]
        sig = response[33:]

        if len(sig) != sig_len:
            raise RuntimeError("Invalid response")

        return wallet_id, sig

    def get_wallet_address(self, wallet: Wallet, signature: bytes, address_index: int, display: bool = False) -> str:
        if wallet.type != WalletType.POLICYMAP or not isinstance(wallet, PolicyMapWallet):
            raise ValueError("wallet type must be POLICYMAP")

        client_intepreter = ClientCommandInterpreter()
        client_intepreter.add_known_pubkey_list(wallet.keys_info)

        sw, response = self.make_request(
            self.builder.get_wallet_address(wallet, signature, address_index, display),
            client_intepreter
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_WALLET_ADDRESS)

        return response.decode()

    # TODO: should we return an updated PSBT with signatures, instead?
    def sign_psbt(self, psbt: PSBT, wallet: Wallet, wallet_sig: bytes = b'') -> str:
        print(psbt.serialize())

        if psbt.version != 2:
            psbt_v2 = PSBT()
            psbt_v2.deserialize(psbt.serialize()) # clone psbt
            psbt_v2.to_psbt_v2()
        else:
            psbt_v2 = psbt

        psbt_bytes = base64.b64decode(psbt_v2.serialize())
        f = BytesIO(psbt_bytes)

        assert f.read(5) == b"psbt\xff"

        client_intepreter = ClientCommandInterpreter()
        client_intepreter.add_known_pubkey_list(wallet.keys_info)

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

        # We also add the Merkle tree of the (resp. output) input map commitments as a known tree
        input_commitments = [get_merkleized_map_commitment(m_in) for m_in in input_maps]
        output_commitments = [get_merkleized_map_commitment(
            m_out) for m_out in output_maps]

        client_intepreter.add_known_list(input_commitments)
        client_intepreter.add_known_list(output_commitments)

        sw, _ = self.make_request(
            self.builder.sign_psbt(global_map, input_maps,
                                   output_maps, wallet, wallet_sig),
            client_intepreter
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.SIGN_PSBT)

        # parse results and return a structured version instead
        results = client_intepreter.yielded

        if any(len(x) <= 1 for x in results):
            raise RuntimeError("Invalid response")

        return {
            int(res[0]): res[1:] for res in results
        }
