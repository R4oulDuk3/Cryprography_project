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
from src.pgp.message.message_body import MessageBody
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
                                   plaintext: str,
                                   sender_mail: str,
                                   receiver_mail: str,
                                   password: str,
                                   symmetric_encryption_algorithm: Algorithm,
                                   sign: bool = False,
                                   encrypt: bool = False,
                                   compress: bool = True,
                                   ) -> PGPMessage:
        signing_key_id = self.key_manager.get_signing_key_id_by_user_email(sender_mail)
        asymmetric_encryption_key_id = self.key_manager.get_encryption_key_id_by_user_email(receiver_mail)
        return self.prepare_message(plaintext=plaintext,
                                    asymmetric_encryption_key_id=asymmetric_encryption_key_id,
                                    signing_key_id=signing_key_id,
                                    password=password,
                                    symmetric_encryption_algorithm=symmetric_encryption_algorithm,
                                    sign=sign,
                                    encrypt=encrypt,
                                    compress=compress
                                    )

    def prepare_message(self,
                        plaintext: str,
                        asymmetric_encryption_key_id: str,
                        password: str = None,
                        signing_key_id: str = None,
                        symmetric_encryption_algorithm: Algorithm = None,
                        sign: bool = False,
                        encrypt: bool = False,
                        compress: bool = True,
                        ) -> PGPMessage:
        if symmetric_encryption_algorithm is not None:
            validate_if_algorithm_symmetric_encryption(symmetric_encryption_algorithm)

        # SIGN MESSAGE
        message_body = self._sign(password=password,
                                  plaintext=plaintext,
                                  sign=sign,
                                  signing_key_id=signing_key_id)

        # COMPRESS MESSAGE

        message_body_bytes: bytes = self._compress(
            message_body=message_body,
            compress=compress)

        # ENCRYPT MESSAGE

        pgp_message = self._encrypt(asymmetric_encryption_key_id=asymmetric_encryption_key_id,
                                    message_body_bytes=message_body_bytes,
                                    encrypt=encrypt,
                                    symmetric_encryption_algorithm=symmetric_encryption_algorithm,
                                    compressed=compress)

        # Convert to string

        return pgp_message

    def _convert(self, pgp_message):
        pgp_message_bytes: bytes = pgp_message.to_bytes()
        pgp_message_str = self.convertor.encode(pgp_message_bytes)
        return pgp_message_str

    def _encrypt(self, asymmetric_encryption_key_id: str,
                 message_body_bytes: bytes,
                 encrypt: bool,
                 compressed: bool,
                 symmetric_encryption_algorithm: Algorithm) -> PGPMessage:
        if encrypt:
            session_key: SessionKey = self.session_key_generator.generate_session_key(symmetric_encryption_algorithm)

            message_body_bytes: bytes = self.symmetric_encryptor.encrypt(
                session_key=session_key,
                plaintext=message_body_bytes,
                algorithm=symmetric_encryption_algorithm)

            receiver_public_key: PublicKey = self.key_manager.get_public_key_by_key_id(
                key_id=asymmetric_encryption_key_id)

            session_key_bytes: bytes = self.key_serializer.session_key_to_bytes(session_key)
            # ENCRYPT SESSION KEY
            encrypted_session_key: bytes = self.asymmetric_encryptor.encrypt(plaintext=session_key_bytes,
                                                                             public_key=receiver_public_key,
                                                                             algorithm=receiver_public_key.get_algorithm())
        else:
            encrypted_session_key = None
        pgp_message: PGPMessage = PGPMessage(
            message_body_bytes=message_body_bytes,
            is_encrypted=encrypt,
            is_compressed=compressed,
            symmetric_encryption_algorithm=symmetric_encryption_algorithm,
            asymmetric_encryption_key_id=asymmetric_encryption_key_id,
            encrypted_session_key=encrypted_session_key,
        )
        return pgp_message

    def _compress(self, compress: bool, message_body: MessageBody) -> bytes:
        if compress:
            compressed_plaintext_and_optional_signature: bytes = self.compressor.compress(
                message_body.to_bytes())
            return compressed_plaintext_and_optional_signature
        else:
            return message_body.to_bytes()

    def _sign(self, password: str, plaintext: str, sign: bool, signing_key_id: str):
        if sign:
            signing_key = self.key_manager.get_key_pair_by_key_id(key_id=signing_key_id,
                                                                  password=password).get_private_key()

            signature: bytes = self.message_signer.sign(message=plaintext,
                                                        private_key=signing_key,
                                                        algorithm=signing_key.get_algorithm())
        else:
            signing_key_id = None
            signature = None
        plaintext_and_optional_signature = MessageBody(plaintext=plaintext,
                                                       is_signed=sign,
                                                       signature_bytes=signature,
                                                       signing_key_id=signing_key_id)
        return plaintext_and_optional_signature

    def send_message(self, pgp_message: PGPMessage, convert: bool, message_path: str):
        print("Sending message to file: " + message_path)
        print("Message: " + str(pgp_message))
        if convert:
            pgp_message_str = self._convert(pgp_message)
            with open(message_path, "w") as file:
                file.write(pgp_message_str)
        else:
            with open(message_path, "wb") as file:
                file.write(pgp_message.to_bytes())


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
    pgp_message: PGPMessage = sender.prepare_message_with_mails(plaintext="Hello World",
                                                                sender_mail="user1@gmail.com",
                                                                receiver_mail="user2@gmail.com",
                                                                password="password",
                                                                symmetric_encryption_algorithm=Algorithm.TRIPLE_DES,
                                                                sign=True,
                                                                encrypt=True,
                                                                compress=True)
    print(str(pgp_message))
    sender.send_message(pgp_message=pgp_message, convert=True, message_path="message.pgp")


if __name__ == '__main__':
    test_message_send()
    test_message_receive()
