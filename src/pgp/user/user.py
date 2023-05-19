from src.pgp.key.key_serializer import KeySerializer
from src.pgp.transfer.receiver import Receiver
from src.pgp.compression.compressor import ZIPCompressor
from src.pgp.conversion.convertor import Radix64Convertor
from src.pgp.encryption.asymmetric import AsymmetricEncryptor
from src.pgp.encryption.symmetric import SymmetricEncryptor
from src.pgp.key.generate.session import SessionKeyGenerator

from src.pgp.key.manager import KeyManager
from src.pgp.signature.sign import Signer
from src.pgp.transfer.sender import Sender


class User:
    def __init__(self, user_name: str):
        self.user_name = user_name
        self.key_manager = KeyManager(user_name)
        self.receiver = Receiver(
            key_manager=self.key_manager,
            message_signer=Signer(),
            symmetric_encryptor=SymmetricEncryptor(),
            asymmetric_encryptor=AsymmetricEncryptor(),
            compressor=ZIPCompressor(),
            convertor=Radix64Convertor(),
            session_key_generator=SessionKeyGenerator(),
            key_serializer=KeySerializer(),
        )
        self.sender = Sender(
            key_manager=self.key_manager,
            message_signer=Signer(),
            symmetric_encryptor=SymmetricEncryptor(),
            asymmetric_encryptor=AsymmetricEncryptor(),
            compressor=ZIPCompressor(),
            convertor=Radix64Convertor(),
            session_key_generator=SessionKeyGenerator(),
            key_serializer=KeySerializer(),
        )
