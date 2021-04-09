import struct
from typing import Tuple, List

from ledgercomm import Transport

from bitcoin_client.bitcoin_cmd_builder import (
    BitcoinCommandBuilder,
    BitcoinInsType,
    FrameworkInsType,
    ClientCommandCode
)
from bitcoin_client.button import Button
from bitcoin_client.exception import DeviceException
from bitcoin_client.transaction import Transaction
from bitcoin_client.bip32 import ExtendedPubkey

from .wallet import AddressType, Wallet, WalletType
from .utils import ripemd160, serialize_str
from .merkle import MerkleTree


class ClientCommand:
    def execute(self, request: bytes) -> bytes:
        raise NotImplementedError("Subclasses should implement this method.")

    @property
    def code(self) -> int:
        raise NotImplementedError("Subclasses should implement this method.")


class GetSquareCommand(ClientCommand):
    @property
    def code(self) -> int:
        return ClientCommandCode.GET_SQUARE

    def execute(self, request: bytes) -> bytes:
        if len(request) != 2:
            raise ValueError("Wrong request length.")
        n = request[1]

        return (n * n).to_bytes(4, 'big')


class GetPubkeyInfoCommand(ClientCommand):
    def __init__(self, keys_info: List[str]):
        self.keys_info = keys_info
        keys_info_hashes = map(lambda k: ripemd160(k.encode("latin-1")), keys_info)
        self.merkle_tree = MerkleTree(keys_info_hashes)

    @property
    def code(self) -> int:
        return ClientCommandCode.CCMD_GET_PUBKEY_INFO

    def execute(self, request: bytes) -> bytes:
        if len(request) != 2:
            raise ValueError("Wrong request length.")

        n = request[1]

        if not (0 <= n < len(self.keys_info)):
            raise RuntimeError(f"Unexpected request: n = {n}, but there are {len(self.keys)} keys.")

        return b''.join([
            serialize_str(self.keys_info[n]),
            self.merkle_tree.prove_leaf(n),
        ])


class GetSortedPubkeyInfoCommand(ClientCommand):
    def __init__(self, keys_info: List[str]):
        self.keys_info = keys_info
        keys_info_hashes = map(lambda k: ripemd160(k.encode("latin-1")), keys_info)
        self.merkle_tree = MerkleTree(keys_info_hashes)

    @property
    def code(self) -> int:
        return ClientCommandCode.CCMD_GET_SORTED_PUBKEY_INFO

    def execute(self, request: bytes) -> bytes:
        if len(request) < 2:
            raise ValueError("Wrong request length.")

        n = request[1]

        if not (0 <= n < len(self.keys_info)):
            raise RuntimeError(f"Unexpected request: n = {n}, but there are {len(self.keys_info)} keys.")

        bip32_path_len = int(request[2])
        if not (0 <= bip32_path_len <= 10):
            raise RuntimeError(f"Invalid derivation len: {bip32_path_len}")

        if len(request) != 1 + 1 + 1 + 4 * bip32_path_len:
            raise ValueError(f"Wrong request length: {len(request)}")

        bip32_path = []
        for i in range(bip32_path_len):
            bip32_path.append(int.from_bytes(request[1 + 1 + 1 + i*4: 1 + 1 + i*4 + 4], byteorder="big"))

        # function to sort keys by the corresponding derived pubkey
        def derived_pk(pubkey_info: str) -> int:
            # Remove the key origin info (if present) by looking for the ']' character
            pos = pubkey_info.find(']')
            pubkey_str = pubkey_info if pos == -1 else pubkey_info[pos+1:]

            ext_pubkey = ExtendedPubkey.from_base58(pubkey_str)
            for d in bip32_path:
                ext_pubkey = ext_pubkey.derive_child(d)

            print(ext_pubkey.compressed_pubkey.hex())
            return ext_pubkey.compressed_pubkey

        sorted_keys = sorted(enumerate(self.keys_info), key=lambda index_key: derived_pk(index_key[1]))

        i, key_info = sorted_keys[n]
        return b''.join([
            i.to_bytes(1, byteorder="big"),
            serialize_str(key_info),
            self.merkle_tree.prove_leaf(i),
        ])


class BitcoinCommand:
    def __init__(self,
                 transport: Transport,
                 debug: bool = False) -> None:
        self.transport = transport
        self.builder = BitcoinCommandBuilder(debug=debug)
        self.debug = debug

    def make_request(self, apdu: bytes, commands: List['ClientCommand'] = []) -> Tuple[int, bytes]:
        sw, response = self.transport.exchange_raw(apdu)

        commands = { cmd.code: cmd for cmd in commands }

        while sw == 0xE000:
            cmd_code = response[0]
            if cmd_code not in commands:
                raise RuntimeError("Unexpected command code: 0x{:02X}".format(cmd_code))  # TODO: more precise Error type

            command_response = commands[cmd_code].execute(response)
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

        sw, response = self.make_request(
            self.builder.register_wallet(wallet),
            [GetPubkeyInfoCommand(wallet.keys_info)]
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
        if wallet.type != WalletType.MULTISIG:
            raise ValueError("wallet type must be MULTISIG")

        sw, response = self.make_request(
            self.builder.get_wallet_address(wallet, signature, address_index, display),
            [
                GetPubkeyInfoCommand(wallet.keys_info),
                GetSortedPubkeyInfoCommand(wallet.keys_info)
            ]
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_WALLET_ADDRESS)

        return response.decode()

    def get_sum_of_squares(self, n: int) -> int:
        if n < 0 or n > 255:
            raise ValueError("n must be an integer between 0 and 255 (inclusive)")

        sw, response = self.make_request(
            self.builder.get_sum_of_squares(n),
            [GetSquareCommand()]
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_SUM_OF_SQUARES)

        assert len(response) == 4
        result, = struct.unpack("<L", response)
        return result