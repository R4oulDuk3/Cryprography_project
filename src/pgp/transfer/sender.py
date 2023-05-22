from src.pgp.compression.compressor import Compressor, ZIPCompressor
from src.pgp.consts.consts import Algorithm, AlgorithmType
from src.pgp.conversion.convertor import Convertor, Radix64Convertor
from src.pgp.encryption.asymmetric import AsymmetricEncryptor
from src.pgp.encryption.symmetric import SymmetricEncryptor
from src.pgp.key.generate.session import SessionKeyGenerator
from src.pgp.key.key import SessionKey, PublicKey
from src.pgp.key.key_serializer import KeySerializer

from src.pgp.key.manager import KeyManager
from src.pgp.message.message import PGPMessage
from src.pgp.signature.sign import Signer
from src.pgp.transfer.receiver import test_message_receive
from src.pgp.util.util import validate_if_algorithm_symmetric_encryption


class Sender:
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

    def prepare_message_with_mails(self,
                                   message: str,
                                   sender_mail: str,
                                   receiver_mail: str,
                                   password: str,
                                   symmetric_encryption_algorithm: Algorithm,
                                   convert: bool, compress: bool) -> PGPMessage:
        signing_key_id = self.key_manager.get_signing_key_id_by_user_email(sender_mail)
        asymmetric_encryption_key_id = self.key_manager.get_encryption_key_id_by_user_email(receiver_mail)
        return self.prepare_message(message=message,
                                    asymmetric_encryption_key_id=asymmetric_encryption_key_id,
                                    signing_key_id=signing_key_id,
                                    password=password,
                                    symmetric_encryption_algorithm=symmetric_encryption_algorithm,
                                    convert=convert,
                                    compress=compress)

    def prepare_message(self,
                        message: str,
                        asymmetric_encryption_key_id: str,
                        signing_key_id: str,
                        password: str,
                        symmetric_encryption_algorithm: Algorithm,
                        convert: bool, compress: bool) -> PGPMessage:
        validate_if_algorithm_symmetric_encryption(symmetric_encryption_algorithm)
        session_key: SessionKey = self.session_key_generator.generate_session_key(symmetric_encryption_algorithm)
        if convert:
            message = self.convertor.encode(message)

        encrypted_message: bytes = self.symmetric_encryptor.encrypt(session_key=session_key,
                                                                    plaintext=message,
                                                                    algorithm=symmetric_encryption_algorithm)
        if compress:
            encrypted_message = self.compressor.compress(encrypted_message)
        receiver_public_key: PublicKey = self.key_manager.get_public_key_by_key_id(key_id=asymmetric_encryption_key_id)

        session_key_bytes: bytes = self.key_serializer.session_key_to_bytes(session_key)

        encrypted_session_key: bytes = self.asymmetric_encryptor.encrypt(plaintext=session_key_bytes,
                                                                         public_key=receiver_public_key,
                                                                         algorithm=receiver_public_key.get_algorithm())

        signing_key = self.key_manager.get_key_pair_by_key_id(key_id=signing_key_id,
                                                              password=password).get_private_key()

        signature: bytes = self.message_signer.sign(message=message,
                                                    private_key=signing_key,
                                                    algorithm=signing_key.get_algorithm())

        return PGPMessage(encrypted_message=encrypted_message,
                          encrypted_session_key=encrypted_session_key,
                          signature=signature,
                          asymmetric_encryption_key_id=asymmetric_encryption_key_id,
                          signing_key_id=signing_key_id,
                          symmetric_encryption_algorithm=symmetric_encryption_algorithm,
                          was_converted=convert,
                          was_compressed=compress
                          )

    def send_message(self, message: PGPMessage, message_path: str):
        message_bytes = message.to_bytes()
        with open(message_path, "wb") as file:
            file.write(message_bytes)


def init_test():
    key_manager_user_1 = KeyManager(user_name="user1")

    key_manager_user_1.generate_key_pair(password="password",
                                         email="user1@gmail.com",
                                         key_size=1024,
                                         algorithm=Algorithm.RSA,
                                         algorithm_type=AlgorithmType.SIGNING)

    key_manager_user_1.generate_key_pair(password="password",
                                         email="user1@gmail.com",
                                         key_size=1024,
                                         algorithm=Algorithm.RSA,
                                         algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION)
    key_manager_user_2 = KeyManager(user_name="user2")

    key_manager_user_2.generate_key_pair(password="password",
                                         email="user2@gmail.com",
                                         key_size=1024,
                                         algorithm=Algorithm.RSA,
                                         algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION)
    key_manager_user_2.generate_key_pair(password="password",
                                         email="user2@gmail.com",
                                         key_size=1024,
                                         algorithm=Algorithm.RSA,
                                         algorithm_type=AlgorithmType.SIGNING)


def test_message_send():
    try:
        init_test()
    except Exception as e:
        print(f"Error while initializing test: {e}")

    sender = Sender(key_manager=KeyManager(user_name="user1"),
                    message_signer=Signer(),
                    symmetric_encryptor=SymmetricEncryptor(),
                    asymmetric_encryptor=AsymmetricEncryptor(),
                    compressor=ZIPCompressor(),
                    convertor=Radix64Convertor(),
                    session_key_generator=SessionKeyGenerator(),
                    key_serializer=KeySerializer())
    message = sender.prepare_message_with_mails(message="Hello World",
                                                sender_mail="user1@gmail.com",
                                                receiver_mail="user2@gmail.com",
                                                password="password",
                                                symmetric_encryption_algorithm=Algorithm.TRIPLE_DES,
                                                convert=True,
                                                compress=True)
    print(str(message))
    sender.send_message(message=message, message_path="message.pgp")


if __name__ == '__main__':
    test_message_send()
    test_message_receive()
