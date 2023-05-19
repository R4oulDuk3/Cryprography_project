import struct

from src.pgp.consts.consts import Algorithm, UTF_8
from src.pgp.util.util import validate_if_algorithm_symmetric_encryption


def write_chunk(chunk):
    return struct.pack('!I', len(chunk)) + chunk


def read_chunk(data: bytes, offset: int):
    size = struct.unpack_from('!I', data, offset)[0]
    offset += 4
    value = data[offset: offset + size]
    offset += size
    return value, offset


class PGPMessage:
    def __init__(self,
                 encrypted_session_key: bytes,
                 sender_mail: str,
                 receiver_mail: str,
                 signature: bytes,
                 encrypted_message: bytes,
                 was_compressed: bool,
                 was_converted: bool,
                 symmetric_encryption_algorithm: Algorithm,
                 ):
        validate_if_algorithm_symmetric_encryption(symmetric_encryption_algorithm)
        """Session key component"""
        self.receiver_mail = receiver_mail
        self.encrypted_session_key = encrypted_session_key
        """Signature"""
        self.sender_mail = sender_mail
        self.signature = signature
        """Data"""
        self.encrypted_message = encrypted_message
        self.was_compressed = was_compressed
        self.was_converted = was_converted
        self.symmetric_encryption_algorithm = symmetric_encryption_algorithm

    def to_bytes(self):
        byte_array = bytearray()
        byte_array += write_chunk(self.receiver_mail.encode(UTF_8))
        byte_array += write_chunk(self.encrypted_session_key)
        byte_array += write_chunk(self.sender_mail.encode(UTF_8))
        byte_array += write_chunk(self.signature)
        byte_array += write_chunk(self.encrypted_message)
        byte_array += struct.pack('!?', self.was_compressed)
        byte_array += struct.pack('!?', self.was_converted)
        byte_array += write_chunk(self.symmetric_encryption_algorithm.value.encode(UTF_8))
        return bytes(byte_array)

    @classmethod
    def from_bytes(cls, data: bytes):
        offset = 0

        receiver_mail, offset = read_chunk(data, offset)
        receiver_mail = receiver_mail.decode(UTF_8)
        encrypted_session_key, offset = read_chunk(data, offset)
        sender_mail, offset = read_chunk(data, offset)
        sender_mail = sender_mail.decode(UTF_8)
        signature, offset = read_chunk(data, offset)
        encrypted_message, offset = read_chunk(data, offset)
        was_compressed = struct.unpack_from('!?', data, offset)[0]
        offset += 1
        was_converted = struct.unpack_from('!?', data, offset)[0]
        offset += 1
        symmetric_encryption_algorithm, offset = read_chunk(data, offset)
        symmetric_encryption_algorithm = Algorithm(symmetric_encryption_algorithm.decode(UTF_8))

        return cls(encrypted_session_key=encrypted_session_key,
                   sender_mail=sender_mail,
                   receiver_mail=receiver_mail,
                   signature=signature,
                   encrypted_message=encrypted_message,
                   was_compressed=was_compressed,
                   was_converted=was_converted,
                   symmetric_encryption_algorithm=symmetric_encryption_algorithm,
                   )

    def __str__(self):
        return f"PGPMessage(receiver_mail={self.receiver_mail}, encrypted_session_key={self.encrypted_session_key}, " \
               f"sender_mail={self.sender_mail}, signature={self.signature}," \
               f" encrypted_message={self.encrypted_message}, " \
               f"was_compressed={self.was_compressed}, was_converted={self.was_converted}, " \
               f"symmetric_encryption_algorithm={self.symmetric_encryption_algorithm})"


def test_pgp_message_serialization():
    message = PGPMessage(
        sender_mail="sender@gmail.com",
        encrypted_session_key=bytes.fromhex("1234"),
        encrypted_message=bytes.fromhex("123456"),
        signature=bytes.fromhex("12345678"),
        receiver_mail="received@gmail.com",
        was_compressed=True,
        was_converted=True,
        symmetric_encryption_algorithm=Algorithm.TRIPLE_DES,
    )
    print(message.to_bytes())
    print(PGPMessage.from_bytes(message.to_bytes()).to_bytes())
    assert message.to_bytes() == PGPMessage.from_bytes(message.to_bytes()).to_bytes()


if __name__ == '__main__':
    test_pgp_message_serialization()
