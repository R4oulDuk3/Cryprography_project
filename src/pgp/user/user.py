from src.pgp.transfer.receiver import Receiver
from src.pgp.compression.compressor import ZIPCompressor
from src.pgp.conversion.converter import Radix64Convertor
from src.pgp.encryption.asymmetric import AsymmetricEncryptor
from src.pgp.encryption.symmetric import SymmetricEncryptor
from src.pgp.key.generate.session import SessionKeyGenerator

from src.pgp.key.manager import KeyManager
from src.pgp.signature.sign import Signer
from src.pgp.transfer.sender import Sender


class User:
    def __init__(self, user_id: str, name: str, email: str):
        self.name = name
        self.email = email
        self.id = user_id
        self.key_manager = KeyManager(user_id)
        self.receiver = Receiver(
            key_manager=self.key_manager,
            message_signer=Signer(),
            symmetric_encryptor=SymmetricEncryptor(),
            asymmetric_encryptor=AsymmetricEncryptor(),
            compressor=ZIPCompressor(),
            convertor=Radix64Convertor(),
            session_key_generator=SessionKeyGenerator(),
        )
        self.sender = Sender(
            key_manager=self.key_manager,
            message_signer=Signer(),
            symmetric_encryptor=SymmetricEncryptor(),
            asymmetric_encryptor=AsymmetricEncryptor(),
            compressor=ZIPCompressor(),
            convertor=Radix64Convertor(),
            session_key_generator=SessionKeyGenerator(),
        )

    @staticmethod
    def login(email):
        pass

    @staticmethod
    def register(name, email):
        pass
