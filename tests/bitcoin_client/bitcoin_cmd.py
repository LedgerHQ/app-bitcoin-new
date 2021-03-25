import struct
from typing import Tuple, List

from ledgercomm import Transport

from bitcoin_client.bitcoin_cmd_builder import (
    AddrType,
    ScriptAddrType,
    BitcoinCommandBuilder,
    BitcoinInsType,
    FrameworkInsType,
    ClientCommandCode
)
from bitcoin_client.button import Button
from bitcoin_client.exception import DeviceException
from bitcoin_client.transaction import Transaction

from .wallet import Wallet, WalletType

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


class GetCosignerPubkeyCommand(ClientCommand):
    def __init__(self, pubkeys: List[str]):
        self.pubkeys = pubkeys

    @property
    def code(self) -> int:
        return ClientCommandCode.GET_COSIGNER_PUBKEY

    def execute(self, request: bytes) -> bytes:
        if len(request) != 2:
            raise ValueError("Wrong request length.")

        n = request[1]

        assert 0 <= n < len(self.pubkeys)
        if not (0 <= n < len(self.pubkeys)):
            raise RuntimeError(f"Unexpected request: n = {n}, but there are {len(self.pubkeys)} pubkeys.")

        result = self.pubkeys[n]
        return len(result).to_bytes(1, byteorder="big") + result.encode("latin-1")


class BitcoinCommand:
    def __init__(self,
                 transport: Transport,
                 debug: bool = False) -> None:
        self.transport = transport
        self.builder = BitcoinCommandBuilder(debug=debug)
        self.debug = debug

    def process_client_commands(self, request: bytes) -> Tuple[int, bytes]:
        command = ClientCommand.create(request)
        command_response = command.execute()
        return self.transport.exchange_raw(self.builder.continue_interrupted(command_response))

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
        sw, response = self.make_request(
            self.builder.get_address(addr_type, bip32_path, display)
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.GET_PUBKEY)

        return response.decode()


    def register_wallet(self, wallet: Wallet) -> Tuple[str, str]:
        if wallet.type != WalletType.MULTISIG:
            raise ValueError("wallet type must be MULTISIG")

        sw, response = self.make_request(
            self.builder.register_wallet(wallet),
            [GetCosignerPubkeyCommand(wallet.pubkeys)]
        )

        if sw != 0x9000:
            raise DeviceException(error_code=sw, ins=BitcoinInsType.REGISTER_WALLET)

        wallet_id = response[0:32]
        sig_len = response[32]
        sig = response[33:]

        if len(sig) != sig_len:
            raise RuntimeError("Invalid response")

        return wallet_id.hex(), sig.hex()


    def get_wallet_address(self, addr_type: ScriptAddrType, wallet: Wallet, signature: bytes, address_index: int, display: bool = False) -> str:
        if wallet.type != WalletType.MULTISIG:
            raise ValueError("wallet type must be MULTISIG")

        sw, response = self.make_request(
            self.builder.get_wallet_address(addr_type, wallet, signature, address_index, display),
            [GetCosignerPubkeyCommand(wallet.pubkeys)]
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