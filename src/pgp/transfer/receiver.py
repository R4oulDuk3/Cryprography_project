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
from src.pgp.message.plaintext_and_signature import PlaintextAndOptionalSignature
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

    def unpack_message(self, path_to_message: str) -> PGPMessage:
        with(open(path_to_message, "r")) as file:
            message = file.read()

        # Reconvert from radix64
        message_bytes = self.convertor.decode(message)
        return PGPMessage.from_bytes(data=message_bytes)

    def decrypt_message(self,
                        message: PGPMessage,
                        password: str) -> str:
        print(message)
        # Decrypt session key
        data_with_optional_signature_compressed_bytes = self._decrypt(message, password)

        # Decompress message
        message_with_optional_signature_bytes = self._decompress(data_with_optional_signature_compressed_bytes)

        # Unpack message
        message_with_optional_signature: PlaintextAndOptionalSignature = PlaintextAndOptionalSignature.from_bytes(
            data=message_with_optional_signature_bytes)
        # Verify signature
        self._verify(message_with_optional_signature, password)

        plaintext = message_with_optional_signature.plaintext
        return plaintext

    def _verify(self, message_with_optional_signature, password):
        if message_with_optional_signature.is_signed:
            sender_public_key = self.key_manager.get_key_pair_by_key_id(
                key_id=message_with_optional_signature.signing_key_id,
                password=password).get_public_key()
            is_verified = self.message_signer.verify(message=message_with_optional_signature.plaintext,
                                                     signature=message_with_optional_signature.signature_bytes,
                                                     public_key=sender_public_key,
                                                     algorithm=sender_public_key.get_algorithm())
            if not is_verified:
                raise Exception("Signature is not verified")

    def _decompress(self, data_with_optional_signature_compressed_bytes):
        message_with_optional_signature_bytes = self.compressor.decompress(
            data_with_optional_signature_compressed_bytes)
        return message_with_optional_signature_bytes

    def _decrypt(self, message, password):
        if message.is_encrypted:
            receiver_private_key = self.key_manager.get_key_pair_by_key_id(key_id=message.asymmetric_encryption_key_id,
                                                                           password=password).get_private_key()
            session_key_bytes = self.asymmetric_encryptor.decrypt(ciphertext=message.encrypted_session_key,
                                                                  private_key=receiver_private_key,
                                                                  algorithm=receiver_private_key.get_algorithm())
            session_key: SessionKey = self.key_serializer.bytes_to_session_key(key_bytes=session_key_bytes,
                                                                               algorithm=message.symmetric_encryption_algorithm)
            # Decrypt message with optional signature
            data_with_optional_signature_compressed_bytes = self.symmetric_encryptor.decrypt(
                ciphertext=message.message_and_optional_signature_compressed_bytes,
                session_key=session_key,
                algorithm=message.symmetric_encryption_algorithm)
        else:
            data_with_optional_signature_compressed_bytes = message.message_and_optional_signature_compressed_bytes
        return data_with_optional_signature_compressed_bytes


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
    plaintext = receiver.decrypt_message(message=message,
                                         password="password")
    print(plaintext)
