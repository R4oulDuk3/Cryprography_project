import mimetypes

from src.pgp.compression.compressor import Compressor, ZIPCompressor
from src.pgp.consts.consts import Algorithm
from src.pgp.conversion.convertor import Convertor, Radix64Convertor
from src.pgp.encryption.asymmetric import AsymmetricEncryptor
from src.pgp.encryption.symmetric import SymmetricEncryptor
from src.pgp.key.generate.session import SessionKeyGenerator
from src.pgp.key.key import SessionKey
from src.pgp.key.key_serializer import KeySerializer

from src.pgp.key.manager import KeyManager
from src.pgp.message.message import PGPMessage
from src.pgp.message.message_body import MessageBody
from src.pgp.signature.sign import Signer


class Receiver:
    def __init__(self,
                 key_manager: KeyManager,
                 message_signer: Signer,
                 symmetric_encryptor: SymmetricEncryptor,
                 asymmetric_encryptor: AsymmetricEncryptor,
                 compressor: Compressor,
                 convertor: Convertor,
                 session_key_generator: SessionKeyGenerator,
                 key_serializer: KeySerializer):
        self.key_manager = key_manager
        self.message_signer = message_signer
        self.symmetric_encryptor = symmetric_encryptor
        self.asymmetric_encryptor = asymmetric_encryptor
        self.compressor = compressor
        self.convertor = convertor
        self.session_key_generator = session_key_generator
        self.key_serializer = key_serializer

    def _is_binary_file(self, file_path: str):
        with open(file_path, "rb") as file:
            return bool(file.read(1024).translate(None, bytearray(
                {7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})))

    def _is_text_file(self, file_path: str):
        return not self._is_binary_file(file_path)

    def unpack_message(self, path_to_message: str) -> PGPMessage:
        if self._is_binary_file(path_to_message):
            print("File is binary, reading...")
            with(open(path_to_message, "rb")) as file:
                message_bytes = file.read()
        else:
            print("File is text, decoding...")
            with(open(path_to_message, "r")) as file:
                message = file.read()
            message_bytes = self.convertor.decode(message)
        return PGPMessage.from_bytes(data=message_bytes)

    def decrypt_message(self,
                        message: PGPMessage,
                        password: str) -> str:
        print(message)
        # Decrypt session key
        message_body_bytes = self._decrypt(message=message,
                                           password=password)

        # Decompress message
        message_body_bytes = self._decompress(message=message,
                                              message_body_bytes=message_body_bytes)

        # Unpack message
        message_body: MessageBody = MessageBody.from_bytes(
            data=message_body_bytes)
        # Verify signature
        sender = self._verify(message_body=message_body)

        plaintext = message_body.plaintext
        return sender, plaintext

    def _verify(self, message_body: MessageBody) -> str:
        if message_body.is_signed:
            sender_public_key = self.key_manager.get_public_key_by_key_id(key_id=message_body.signing_key_id, )
            is_verified = self.message_signer.verify(message=message_body.plaintext,
                                                     signature=message_body.signature_bytes,
                                                     public_key=sender_public_key,
                                                     algorithm=sender_public_key.get_algorithm())
            if not is_verified:
                raise Exception("Signature could not be verified")
            sender_email = self.key_manager.get_user_mail_by_key_id(key_id=message_body.signing_key_id)
            return sender_email
        else:
            return "Unknown sender"


    def _decompress(self, message: PGPMessage, message_body_bytes: bytes):
        if message.is_compressed:
            message_body_bytes = self.compressor.decompress(
                data=message_body_bytes, )
        return message_body_bytes

    def _decrypt(self, message: PGPMessage, password: str):
        if message.is_encrypted:
            receiver_private_key = self.key_manager.get_key_pair_by_key_id(key_id=message.asymmetric_encryption_key_id,
                                                                           password=password).get_private_key()
            session_key_bytes = self.asymmetric_encryptor.decrypt(ciphertext=message.encrypted_session_key,
                                                                  private_key=receiver_private_key,
                                                                  algorithm=receiver_private_key.get_algorithm())
            session_key: SessionKey = self.key_serializer.bytes_to_session_key(key_bytes=session_key_bytes,
                                                                               algorithm=message.symmetric_encryption_algorithm)
            # Decrypt message with optional signature
            print(f"Decrypting message with {message.symmetric_encryption_algorithm}...")
            message_body_bytes = self.symmetric_encryptor.decrypt(
                ciphertext=message.message_body_bytes,
                session_key=session_key,
                algorithm=message.symmetric_encryption_algorithm)
        else:
            message_body_bytes = message.message_body_bytes
        return message_body_bytes


def test_message_receive():
    key_manager = KeyManager(user_name="user2")
    message_signer = Signer()
    symmetric_encryptor = SymmetricEncryptor()
    asymmetric_encryptor = AsymmetricEncryptor()
    compressor = ZIPCompressor()
    convertor = Radix64Convertor()
    session_key_generator = SessionKeyGenerator()
    key_serializer = KeySerializer()
    receiver = Receiver(key_manager=key_manager,
                        message_signer=message_signer,
                        symmetric_encryptor=symmetric_encryptor,
                        asymmetric_encryptor=asymmetric_encryptor,
                        compressor=compressor,
                        convertor=convertor,
                        session_key_generator=session_key_generator,
                        key_serializer=key_serializer)
    message = receiver.unpack_message(path_to_message="message.pgp")
    print(message)
    sender, plaintext = receiver.decrypt_message(message=message,
                                         password="password")
    print(plaintext)
    print(sender)