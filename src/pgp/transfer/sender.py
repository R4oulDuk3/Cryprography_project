from src.pgp.compression.compressor import Compressor
from src.pgp.consts.consts import SymmetricEncryptionAlgorithm, AsymmetricEncryptionAlgorithm, \
    SessionKeyGeneratorAlgorithm
from src.pgp.conversion.converter import Convertor
from src.pgp.encryption.asymmetric import AsymmetricEncryptor
from src.pgp.encryption.symmetric import SymmetricEncryptor
from src.pgp.key.generate.session import SessionKeyGenerator

from src.pgp.key.manager import KeyManager
from src.pgp.message.message import PGPMessage
from src.pgp.signature.sign import Signer


class Sender:
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

    def prepare_message(self, data: str, recipient_email: str, signing_private_key_id: str,
                        session_key_generator_algorithm: SessionKeyGeneratorAlgorithm,
                        symmetric_encryption_algorithm: SymmetricEncryptionAlgorithm,
                        asymmetric_encryption_algorithm: AsymmetricEncryptionAlgorithm) -> PGPMessage:
        session_key = self.session_key_generator.generate_session_key(algorithm=session_key_generator_algorithm)

        ecnrypted_data = self.symmetric_encryptor.encrypt(data=data, session_key=session_key,
                                                          algorithm=symmetric_encryption_algorithm)

        encrypted_session_key = self.asymmetric_encryptor.encrypt(public_key=self.key_manager.get_public_key(recipient_email))

    def send(self, message: str, recipient_email: str, singing_private_key_id: str):
        message = self.prepare_message(message, recipient_email, singing_private_key_id)
        bytes = PGPMessage.to_bytes(message)
        """
            Sending implementation
        """