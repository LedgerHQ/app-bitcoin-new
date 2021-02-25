import struct
from typing import Tuple

from ledgercomm import Transport

from bitcoin_client.bitcoin_cmd_builder import BitcoinCommandBuilder, InsType, ClientCommandCode
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

    def get_app_and_version(self) -> Tuple[str, str]:
        sw, response = self.transport.exchange_raw(
            self.builder.get_app_and_version()
        )  # type: int, bytes

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=0x01)

        # response = format_id (1) ||
        #            app_name_len (1) ||
        #            app_name (var) ||
        #            version_len (1) ||
        #            version (var) ||
        offset: int = 0

        format_id: int = response[offset]
        offset += 1
        app_name_len: int = response[offset]
        offset += 1
        app_name: str = response[offset:offset + app_name_len].decode("ascii")
        offset += app_name_len
        version_len: int = response[offset]
        offset += 1
        version: str = response[offset:offset + version_len].decode("ascii")
        offset += version_len

        return app_name, version

    def get_version(self) -> Tuple[int, int, int]:
        sw, response = self.transport.exchange_raw(
            self.builder.get_version()
        )  # type: int, bytes

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=InsType.INS_GET_VERSION)

        # response = MAJOR (1) || MINOR (1) || PATCH (1)
        assert len(response) == 3

        major, minor, patch = struct.unpack(
            "BBB",
            response
        )  # type: int, int, int

        return major, minor, patch

    def get_app_name(self) -> str:
        sw, response = self.transport.exchange_raw(
            self.builder.get_app_name()
        )  # type: int, bytes

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=InsType.INS_GET_APP_NAME)

        return response.decode("ascii")

    def get_public_key(self, bip32_path: str, display: bool = False) -> Tuple[bytes, bytes]:
        sw, response = self.transport.exchange_raw(
            self.builder.get_public_key(bip32_path=bip32_path,
                                        display=display)
        )  # type: int, bytes

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=InsType.INS_GET_PUBLIC_KEY)

        # response = pub_key_len (1) ||
        #            pub_key (var) ||
        #            chain_code_len (1) ||
        #            chain_code (var)
        offset: int = 0

        pub_key_len: int = response[offset]
        offset += 1
        pub_key: bytes = response[offset:offset + pub_key_len]
        offset += pub_key_len
        chain_code_len: int = response[offset]
        offset += 1
        chain_code: bytes = response[offset:offset + chain_code_len]
        offset += chain_code_len

        assert len(response) == 1 + pub_key_len + 1 + chain_code_len

        return pub_key, chain_code

    def sign_tx(self, bip32_path: str, transaction: Transaction, button: Button) -> Tuple[int, bytes]:
        sw: int
        response: bytes = b""

        for is_last, chunk in self.builder.sign_tx(bip32_path=bip32_path, transaction=transaction):
            self.transport.send_raw(chunk)

            if is_last:
                # Review Transaction
                button.right_click()
                # Address 1/3, 2/3, 3/3
                button.right_click()
                button.right_click()
                button.right_click()
                # Amount
                button.right_click()
                # Approve
                button.both_click()

            sw, response = self.transport.recv()  # type: int, bytes

            if sw != 0x9000:
                raise DeviceException(error_code=sw, ins=InsType.INS_SIGN_TX)

        # response = der_sig_len (1) ||
        #            der_sig (var) ||
        #            v (1)
        offset: int = 0
        der_sig_len: int = response[offset]
        offset += 1
        der_sig: bytes = response[offset:offset + der_sig_len]
        offset += der_sig_len
        v: int = response[offset]
        offset += 1

        assert len(response) == 1 + der_sig_len + 1

        return v, der_sig

    def get_sum_of_squares(self, n: int):
        if n < 0 or n > 255:
            raise ValueError("n must be an integer between 0 and 255 (inclusive)")

        sw, response = self.transport.exchange_raw(
            self.builder.get_sum_of_squares(n)
        )  # type: int, bytes

        while sw == 0xA000:
            sw, response = self.process_client_command(response)

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=InsType.INS_GET_SUM_OF_SQUARES)

        assert len(response) == 4
        result, = struct.unpack("<L", response)
        return result