import struct

from src.pgp.consts.consts import Algorithm, UTF_8
from src.pgp.message.util import write_chunk, read_chunk
from src.pgp.util.util import validate_if_algorithm_symmetric_encryption


class PGPMessage:
    def __init__(self,
                 message_body_bytes: bytes,
                 is_encrypted: bool,
                 is_compressed: bool = False,
                 symmetric_encryption_algorithm: Algorithm = None,
                 asymmetric_encryption_key_id: str = None,
                 encrypted_session_key: bytes = None,
                 ):
        if is_encrypted:
            validate_if_algorithm_symmetric_encryption(symmetric_encryption_algorithm)
        self.message_body_bytes = message_body_bytes
        self.encrypted_session_key = encrypted_session_key
        self.is_encrypted = is_encrypted
        self.asymmetric_encryption_key_id = asymmetric_encryption_key_id
        self.symmetric_encryption_algorithm = symmetric_encryption_algorithm
        self.is_compressed = is_compressed

    def to_bytes(self):
        byte_array = bytearray()
        byte_array += write_chunk(self.message_body_bytes)
        byte_array += struct.pack('!?', self.is_encrypted)
        byte_array += struct.pack('!?', self.is_compressed)
        if self.is_encrypted:
            byte_array += write_chunk(self.encrypted_session_key)
            byte_array += write_chunk(self.asymmetric_encryption_key_id.encode(UTF_8))
            byte_array += write_chunk(self.symmetric_encryption_algorithm.value.encode(UTF_8))
        return bytes(byte_array)

    @classmethod
    def from_bytes(cls, data: bytes):
        offset = 0

        message_body_bytes, offset = read_chunk(data, offset)
        is_encrypted = struct.unpack_from('!?', data, offset)[0]
        offset += 1
        is_compressed = struct.unpack_from('!?', data, offset)[0]
        offset += 1
        if is_encrypted:
            encrypted_session_key, offset = read_chunk(data, offset)
            asymmetric_encryption_key_id, offset = read_chunk(data, offset)
            asymmetric_encryption_key_id = asymmetric_encryption_key_id.decode(UTF_8)
            symmetric_encryption_algorithm, offset = read_chunk(data, offset)
            symmetric_encryption_algorithm = symmetric_encryption_algorithm.decode(UTF_8)
            symmetric_encryption_algorithm = Algorithm(symmetric_encryption_algorithm)
        else:
            encrypted_session_key = None
            asymmetric_encryption_key_id = None
            symmetric_encryption_algorithm = None

        return cls(
            message_body_bytes=message_body_bytes,
            is_encrypted=is_encrypted,
            is_compressed=is_compressed,
            encrypted_session_key=encrypted_session_key,
            asymmetric_encryption_key_id=asymmetric_encryption_key_id,
            symmetric_encryption_algorithm=symmetric_encryption_algorithm,
        )

    def __str__(self):
        return f'PGPMessage(message_and_optional_signature_compressed_bytes={self.message_body_bytes},' \
               f' is_encrypted={self.is_encrypted}, is_compressed={self.is_compressed}' \
               f' encrypted_session_key={self.encrypted_session_key},' \
               f' asymmetric_encryption_key_id={self.asymmetric_encryption_key_id},' \
               f' symmetric_encryption_algorithm={self.symmetric_encryption_algorithm})'


def test_pgp_message_serialization():
    pgp_message = PGPMessage(
        message_body_bytes=b'1234567890',
        is_encrypted=True,
        encrypted_session_key=b'1234567890',
        asymmetric_encryption_key_id='1234567890',
        symmetric_encryption_algorithm=Algorithm.CAST_128,
        is_compressed=True,
    )
    pgp_message_bytes = pgp_message.to_bytes()
    pgp_message_deserialized = PGPMessage.from_bytes(pgp_message_bytes)
    print(pgp_message)
    print(pgp_message_deserialized)
    assert pgp_message.message_body_bytes == pgp_message_deserialized.message_body_bytes


if __name__ == '__main__':
    test_pgp_message_serialization()
