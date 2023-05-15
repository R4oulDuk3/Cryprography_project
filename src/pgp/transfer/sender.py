from src.pgp.compression.compressor import Compressor
from src.pgp.conversion.converter import Convertor
from src.pgp.encryption.asymmetric import AsymmetricEncryptor
from src.pgp.encryption.symmetric import SymmetricEncryptor
from src.pgp.key.generate.session import SessionKeyGenerator

from src.pgp.key.manager import KeyManager
from src.pgp.message.message import PGPMessage
from src.pgp.signature.hash import Hasher
from src.pgp.signature.sign import Signer


class Sender:
    def __init__(self,
                 key_manager: KeyManager,
                 message_signer: Signer,
                 message_hasher: Hasher,
                 symmetric_encryptor: SymmetricEncryptor,
                 asymmetric_encryptor: AsymmetricEncryptor,
                 compressor: Compressor,
                 convertor: Convertor,
                 session_key_generator: SessionKeyGenerator):
        self.key_manager = key_manager
        self.message_signer = message_signer
        self.message_hasher = message_hasher
        self.symmetric_encryptor = symmetric_encryptor
        self.asymmetric_encryptor = asymmetric_encryptor
        self.compressor = compressor
        self.convertor = convertor
        self.session_key_generator = session_key_generator

    def prepare_message(self, message: str, recipient_email: str, signing_private_key_id: str) -> PGPMessage:
        recipient_public_key = self.key_manager.get_public_key(recipient_email)
        message_bytes = message.encode()
        session_key = self.session_key_generator.generate_session_key()
        encrypted_message = self.symmetric_encryptor.encrypt(message_bytes, session_key)
        encrypted_session_key = self.asymmetric_encryptor.encrypt(session_key, recipient_public_key)
        message = PGPMessage(
            recipient_public_key_id=recipient_public_key.key_id,
            session_key=encrypted_session_key,
            sender_public_key_id=signing_private_key_id,
            data=encrypted_message
        )
        signed_message_packet = self.message_signer.sign(message, signing_private_key_id)
        return signed_message_packet

    def send(self, message: str, recipient_email: str, singing_private_key_id: str):
        message = self.prepare_message(message, recipient_email, singing_private_key_id)
        bytes = PGPMessage.to_bytes(message)
        """
            Sending implementation
        """