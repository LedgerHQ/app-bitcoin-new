
class AcreWithdrawalDataBytes:
    def __init__(self, to: bytes, value: bytes, data: bytes, operation: bytes, safeTxGas: bytes, baseGas: bytes, gasPrice: bytes, gasToken: bytes, refundReceiver: bytes, nonce: bytes):
        self.to = to
        self.value = value
        self.data = data
        self.operation = operation
        self.safeTxGas = safeTxGas
        self.baseGas = baseGas
        self.gasPrice = gasPrice
        self.gasToken = gasToken
        self.refundReceiver = refundReceiver
        self.nonce = nonce

class AcreWithdrawalData:
    def __init__(self, to: str, value: str, data: str, operation: str, safeTxGas: str, baseGas: str, gasPrice: str, gasToken: str, refundReceiver: str, nonce: str):
        self.to = to
        self.value = value
        self.data = data
        self.operation = operation
        self.safeTxGas = safeTxGas
        self.baseGas = baseGas
        self.gasPrice = gasPrice
        self.gasToken = gasToken
        self.refundReceiver = refundReceiver
        self.nonce = nonce

    def to_bytes(self) -> AcreWithdrawalDataBytes:
        def hex_to_bytes(hex_str: str, size: int) -> bytes:
            if hex_str.startswith("0x"):
                hex_str = hex_str[2:]
            hex_str = hex_str.zfill(size * 2)  # Pad with leading zeros to the desired byte length
            return bytes.fromhex(hex_str)
        
        def hex_to_bytes_data(hex_str: str) -> bytes:
            if hex_str.startswith("0x"):
                hex_str = hex_str[2:]
            size = len(hex_str) // 2  # Calculate size without the 0x prefix
            hex_str = hex_str.zfill(size * 2)  # Pad with leading zeros to the desired byte length
            return bytes.fromhex(hex_str)

        return AcreWithdrawalDataBytes(
            to=hex_to_bytes(self.to, 20),
            value=hex_to_bytes(self.value, 32),
            data=hex_to_bytes_data(self.data),
            operation=hex_to_bytes(self.operation, 1),
            safeTxGas=hex_to_bytes(self.safeTxGas, 32),
            baseGas=hex_to_bytes(self.baseGas, 32),
            gasPrice=hex_to_bytes(self.gasPrice, 32),
            gasToken=hex_to_bytes(self.gasToken, 20),
            refundReceiver=hex_to_bytes(self.refundReceiver, 20),
            nonce=hex_to_bytes(self.nonce, 32)
        )