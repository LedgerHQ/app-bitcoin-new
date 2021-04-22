import struct
from typing import Tuple, List, Mapping
from collections import deque

from ledgercomm import Transport

from bitcoin_client.command_builder import (
    BitcoinCommandBuilder,
    BitcoinInsType,
)
from bitcoin_client.common import AddressType
from bitcoin_client.exception import DeviceException

from .client_command import (
    GetPreimageCommand,
    GetMerkleLeafHashCommand,
    GetMerkleLeafIndexCommand,
    GetMoreElementsCommand,
    GetPubkeysInDerivationOrder,
)

from .common import ripemd160
from .merkle import element_hash
from .wallet import Wallet, WalletType, MultisigWallet


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

        queue = deque()

        known_images: Mapping[bytes, bytes] = {}
        elements_lists: List[List[bytes]] = []

        if isinstance(wallet, MultisigWallet):
            known_images = {
                element_hash(el.encode()): el.encode() for el in wallet.keys_info
            }
            elements_lists.append(list(element_hash(el.encode()) for el in wallet.keys_info))
        else:
            raise RuntimeError(f"wallet has unexpected class '{type(wallet).__name__}'")


        sw, response = self.make_request(
            self.builder.register_wallet(wallet), 
            [
                GetPreimageCommand(known_images),
                GetMerkleLeafHashCommand(elements_lists, queue),
                GetMoreElementsCommand(queue)
            ]
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

        queue = deque()

        known_images: Mapping[bytes, bytes] = {}
        elements_lists: List[List[bytes]] = []

        if isinstance(wallet, MultisigWallet):
            known_images = {
                element_hash(el.encode()): el.encode() for el in wallet.keys_info
            }
            elements_lists.append(list(element_hash(el.encode()) for el in wallet.keys_info))
        else:
            raise RuntimeError(f"wallet has unexpected class '{type(wallet).__name__}'")

        sw, response = self.make_request(
            self.builder.get_wallet_address(wallet, signature, address_index, display),
            [
                GetPreimageCommand(known_images),
                GetMerkleLeafHashCommand(elements_lists, queue),
                GetMoreElementsCommand(queue),
                GetPubkeysInDerivationOrder(wallet.keys_info)
            ]
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_WALLET_ADDRESS)

        return response.decode()

    # TODO: placeholder of the future command that will instead take a psbt as input; just for testing
    def sign_psbt(self, preimage: bytes) -> str:
        hash = ripemd160(preimage)
        sw, response = self.make_request(
            self.builder.sign_psbt(hash),
            [
                GetPreimageCommand({
                    hash: preimage
                })
            ]
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.SIGN_PSBT)

        return response.decode()
