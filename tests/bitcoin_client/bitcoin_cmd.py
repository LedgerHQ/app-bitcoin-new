import struct
from typing import Tuple, List

from ledgercomm import Transport

from bitcoin_client.bitcoin_cmd_builder import (
    AddrType,
    BitcoinCommandBuilder,
    BitcoinInsType,
    FrameworkInsType,
    ClientCommandCode
)
from bitcoin_client.button import Button
from bitcoin_client.exception import DeviceException
from bitcoin_client.transaction import Transaction

class ClientCommand:
    def __init__(self, request: bytes):
        if len(request) == 0:
            raise ValueError("Commands should be at least 1 byte long.")
        self.request = request

    def execute(self) -> bytes:
        raise NotImplementedError("Subclasses should implement this method.")

    @property
    def code(self) -> int:
        return self.request[0]

    @staticmethod
    def create(request: bytes):
        if len(request) == 0:
            raise ValueError("Commands should be at least 1 byte long.")

        command_code = request[0]
        if command_code == ClientCommandCode.GET_SQUARE:
            return GetSquareCommand(request)
        else:
            raise ValueError("Unknown command code: {:02X}".format(command_code))

class GetSquareCommand(ClientCommand):
    def __init__(self, request: bytes):
        super().__init__(request)

        if len(request) != 2:
            raise ValueError("Wrong request length.")

        self.n = request[1]

    def execute(self):
        return (self.n * self.n).to_bytes(4, 'big')

class BitcoinCommand:
    def __init__(self,
                 transport: Transport,
                 debug: bool = False) -> None:
        self.transport = transport
        self.builder = BitcoinCommandBuilder(debug=debug)
        self.debug = debug

    def process_client_command(self, request: bytes) -> Tuple[int, bytes]:
        command = ClientCommand.create(request)
        command_response = command.execute()
        return self.transport.exchange_raw(self.builder.continue_interrupted(command_response))

    def get_pubkey(self, bip32_path: str, display: bool = False) -> str:
        # TODO: add docs
        sw, response = self.transport.exchange_raw(
            self.builder.get_pubkey(bip32_path, display)
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_PUBKEY)

        return response.decode()

    def get_address(self,
                    addr_type: AddrType,
                    bip32_path: str,
                    display: bool = False) -> str:
        """Get an address given address type and BIP32 path. Optionally, validate with the user.

        Parameters
        ----------
        addr_type : AddrType
            Type of address. Could be AddrType.PKH, AddrType.SH_WPKH,
            AddrType.WPKH.
        bip32_path : str
            BIP32 path of the public key you want.
        display : bool
            Whether you want to display address and ask confirmation on the device.

        Returns
        -------

        """
        sw, response = self.transport.exchange_raw(
            self.builder.get_address(addr_type, bip32_path, display)
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_PUBKEY)

        return response.decode()


    def register_wallet(self, wallet_type: int, name: str, threshold: int, n_keys:int, pubkeys: List[str]) -> bytes:
        if wallet_type != 0:
            raise ValueError("wallet_type must be 0")

        if len(name.encode("latin-1")) > 16:
            raise ValueError("The length of name must be at most 16 bytes")

        if (threshold < 0 or n_keys < 0 or threshold > 15 or n_keys > 15 or threshold > n_keys):
            raise ValueError("Invalid threshold or n_keys")

        sw, response = self.transport.exchange_raw(
            self.builder.register_wallet(wallet_type, name, threshold, n_keys, pubkeys)
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.REGISTER_WALLET)

        return response


    def get_sum_of_squares(self, n: int) -> int:
        if n < 0 or n > 255:
            raise ValueError("n must be an integer between 0 and 255 (inclusive)")

        sw, response = self.transport.exchange_raw(
            self.builder.get_sum_of_squares(n)
        )

        while sw == 0xE000:
            sw, response = self.process_client_command(response)

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_SUM_OF_SQUARES)

        assert len(response) == 4
        result, = struct.unpack("<L", response)
        return result