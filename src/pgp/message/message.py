import struct

from src.pgp.consts.consts import KEY_ID_LENGTH


class PGPMessage:
    def __init__(self,
                 encryption_key_id: bytes,
                 encrypted_session_key: bytes,
                 signing_key_id: bytes,
                 signature: bytes,
                 compressed_converted_encrypted_data: bytes
                 ):
        """Session key component"""
        self.encryption_key_id = encryption_key_id
        self.encrypted_session_key = encrypted_session_key
        """Signature"""
        self.signing_key_id = signing_key_id
        self.signature = signature
        """Data"""
        self.compressed_converted_encrypted_data = compressed_converted_encrypted_data

    def to_bytes(self):
        def write_chunk(chunk):
            return struct.pack('!I', len(chunk)) + chunk

        result = b''
        result += write_chunk(self.encryption_key_id)
        result += write_chunk(self.encrypted_session_key)
        result += write_chunk(self.signing_key_id)
        result += write_chunk(self.signature)
        result += write_chunk(self.compressed_converted_encrypted_data)

        return result

    @classmethod
    def from_bytes(cls, data: bytes):
        offset = 0

        def read_chunk():
            nonlocal offset
            size = struct.unpack_from('!I', data, offset)[0]
            offset += 4
            value = data[offset: offset + size]
            offset += size
            return value

        encryption_key_id = read_chunk()
        encrypted_session_key = read_chunk()
        signing_key_id = read_chunk()
        signature = read_chunk()
        compressed_converted_encrypted_data = read_chunk()

        return cls(encryption_key_id, encrypted_session_key, signing_key_id, signature,
                   compressed_converted_encrypted_data)


def test_pgp_message_serialization():
    message = PGPMessage(
        encryption_key_id=bytes.fromhex("12"),
        encrypted_session_key=bytes.fromhex("1234"),
        compressed_converted_encrypted_data=bytes.fromhex("123456"),
        signature=bytes.fromhex("12345678"),
        signing_key_id=bytes.fromhex("12345678"),
    )
    print(message.to_bytes())
    print(PGPMessage.from_bytes(message.to_bytes()).to_bytes())
    assert message.to_bytes() == PGPMessage.from_bytes(message.to_bytes()).to_bytes()


if __name__ == '__main__':
    test_pgp_message_serialization()
