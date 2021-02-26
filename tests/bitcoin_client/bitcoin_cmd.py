import struct
from typing import Tuple

from ledgercomm import Transport

from bitcoin_client.bitcoin_cmd_builder import BitcoinCommandBuilder, BitcoinInsType, FrameworkInsType, ClientCommandCode
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

    def get_sum_of_squares(self, n: int):
        if n < 0 or n > 255:
            raise ValueError("n must be an integer between 0 and 255 (inclusive)")

        sw, response = self.transport.exchange_raw(
            self.builder.get_sum_of_squares(n)
        )  # type: int, bytes

        while sw == 0xE000:
            sw, response = self.process_client_command(response)

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_SUM_OF_SQUARES)

        assert len(response) == 4
        result, = struct.unpack("<L", response)
        return result