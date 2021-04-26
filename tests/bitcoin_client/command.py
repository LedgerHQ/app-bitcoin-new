import struct
from typing import Tuple, List, Mapping
from collections import deque
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

from .common import ripemd160
from .merkle import element_hash, get_merkleized_map_commitment, MerkleTree
from .wallet import Wallet, WalletType, MultisigWallet
from .psbt import PSBT, deser_string
from .tx import CTransaction

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
            sw, response = self.transport.exchange_raw(self.builder.continue_interrupted(command_response))

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
        if wallet.type != WalletType.MULTISIG:
            raise ValueError("wallet type must be MULTISIG")

        cmd_interpreter = ClientCommandInterpreter()
        cmd_interpreter.add_known_keylist(wallet.keys_info)

        sw, response = self.make_request(
            self.builder.register_wallet(wallet),
            cmd_interpreter
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
        if wallet.type != WalletType.MULTISIG or not isinstance(wallet, MultisigWallet):
            raise ValueError("wallet type must be MULTISIG")

        cmd_interpreter = ClientCommandInterpreter()
        cmd_interpreter.add_known_keylist(wallet.keys_info)

        sw, response = self.make_request(
            self.builder.get_wallet_address(wallet, signature, address_index, display),
            cmd_interpreter
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_WALLET_ADDRESS)

        return response.decode()

    # TODO: placeholder of the future command that will instead take a psbt as input; just for testing
    def sign_psbt(self, psbt: PSBT) -> str:
        psbt_bytes = base64.b64decode(psbt.serialize())
        f = BytesIO(psbt_bytes)
        end = len(psbt_bytes)

        assert f.read(5) == b"psbt\xff"

        global_map = parse_stream_to_map(f)

        if b'\x00' not in global_map:
            raise ValueError("Invalid PSBT: PSBT_GLOBAL_UNSIGNED_TX")

        # as the psbt format v1 does not specifies the number of inputs and outputs, we need to parse the
        # PSBT_GLOBAL_UNSIGNED_TX = 0x00 field from the global map.

        tx = CTransaction()
        tx.deserialize(BytesIO(global_map[b'\x00']))

        input_maps = []
        for _ in tx.vin:
            print("INPUT START:", f.tell())
            input_maps.append(parse_stream_to_map(f))

        output_maps = []
        for _ in tx.vout:
            print("OUTPUT START:", f.tell())
            output_maps.append(parse_stream_to_map(f))

        print(end, f.tell())
        print(len(input_maps), len(output_maps))

        print(tx)
        print()

        print(global_map)
        print(input_maps)
        print(output_maps)


        return
        # sw, response = self.make_request(
        #     self.builder.sign_psbt(hash),
        #     [
        #         GetPreimageCommand({
        #             hash: preimage
        #         })
        #     ]
        # )

        # if sw != 0x9000:
        #     raise DeviceException(error_code=sw, ins=BitcoinInsType.SIGN_PSBT)

        # return response.decode()
