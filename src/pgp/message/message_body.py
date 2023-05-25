import struct

from src.pgp.consts.consts import UTF_8
from src.pgp.message.util import write_chunk, read_chunk


class MessageBody:

    def __init__(self,
                 plaintext: str,
                 is_signed: bool,
                 signature_bytes: bytes = None,
                 signing_key_id: str = None,
                 ):
        self.plaintext = plaintext
        self.is_signed = is_signed
        self.signature_bytes = signature_bytes
        self.signing_key_id = signing_key_id

    def to_bytes(self):
        byte_array = bytearray()
        byte_array += write_chunk(self.plaintext.encode(UTF_8))
        byte_array += struct.pack('!?', self.is_signed)
        if self.is_signed:
            byte_array += write_chunk(self.signature_bytes)
            byte_array += write_chunk(self.signing_key_id.encode(UTF_8))
        return bytes(byte_array)

    @classmethod
    def from_bytes(cls, data: bytes):
        offset = 0

        plaintext, offset = read_chunk(data, offset)
        plaintext = plaintext.decode(UTF_8)
        is_signed = struct.unpack_from('!?', data, offset)[0]
        offset += 1
        if is_signed:
            signature_bytes, offset = read_chunk(data, offset)
            signing_key_id, offset = read_chunk(data, offset)
            signing_key_id = signing_key_id.decode(UTF_8)
        else:
            signature_bytes = None
            signing_key_id = None

        return cls(plaintext=plaintext,
                   is_signed=is_signed,
                   signature_bytes=signature_bytes,
                   signing_key_id=signing_key_id,
                   )

    def __str__(self):
        return f'MessageAndOptionalSignature(plaintext={self.plaintext},' \
               f' is_signed={self.is_signed},' \
               f' signature_bytes={self.signature_bytes},' \
               f' signing_key_id={self.signing_key_id})'


def test_message_and_signature():
    message_and_signature = MessageBody(plaintext='Hello World!',
                                        is_signed=True,
                                        signature_bytes=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c',
                                        signing_key_id='0x12345678')
    bytes_ = message_and_signature.to_bytes()
    print(bytes_)
    message_and_signature_ = MessageBody.from_bytes(bytes_)
    print(message_and_signature_)
    assert message_and_signature.plaintext == message_and_signature_.plaintext


if __name__ == '__main__':
    test_message_and_signature()
