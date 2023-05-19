from src.pgp.compression.compressor import Compressor
from src.pgp.conversion.converter import Convertor
from src.pgp.encryption.asymmetric import AsymmetricEncryptor
from src.pgp.encryption.symmetric import SymmetricEncryptor
from src.pgp.key.generate.session import SessionKeyGenerator

from src.pgp.key.manager import KeyManager
from src.pgp.message.message import PGPMessage
from src.pgp.signature.sign import Signer


class Receiver:
    def __init__(self,
                 key_manager: KeyManager,
                 message_signer: Signer,
                 symmetric_encryptor: SymmetricEncryptor,
                 asymmetric_encryptor: AsymmetricEncryptor,
                 compressor: Compressor,
                 convertor: Convertor,
                 session_key_generator: SessionKeyGenerator):
        self.key_manager = key_manager
        self.message_signer = message_signer
        self.symmetric_encryptor = symmetric_encryptor
        self.asymmetric_encryptor = asymmetric_encryptor
        self.compressor = compressor
        self.convertor = convertor
        self.session_key_generator = session_key_generator

    def get_received_messages(self, recipient_email: str) -> list[PGPMessage]:
        """
            Receiving implementation
        """
        pass

    def decrypt_message(self, message: PGPMessage) -> str:

        self.key_manager.get_private_key(message.recipient_public_key_id)
