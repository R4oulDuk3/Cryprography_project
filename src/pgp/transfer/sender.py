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
from src.pgp.message.plaintext_and_signature import PlaintextAndOptionalSignature
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
                                   encrypt: bool = False, ) -> str:
        signing_key_id = self.key_manager.get_signing_key_id_by_user_email(sender_mail)
        asymmetric_encryption_key_id = self.key_manager.get_encryption_key_id_by_user_email(receiver_mail)
        return self.prepare_message(plaintext=plaintext,
                                    asymmetric_encryption_key_id=asymmetric_encryption_key_id,
                                    signing_key_id=signing_key_id,
                                    password=password,
                                    symmetric_encryption_algorithm=symmetric_encryption_algorithm,
                                    )

    def prepare_message(self,
                        plaintext: str,
                        asymmetric_encryption_key_id: str,
                        password: str = None,
                        signing_key_id: str = None,
                        symmetric_encryption_algorithm: Algorithm = None,
                        sign: bool = False,
                        encrypt: bool = False,
                        ) -> str:
        if symmetric_encryption_algorithm is not None:
            validate_if_algorithm_symmetric_encryption(symmetric_encryption_algorithm)

        # SIGN MESSAGE
        plaintext_and_optional_signature = self._sign(password, plaintext, sign, signing_key_id)

        # COMPRESS MESSAGE

        compressed_plaintext_and_optional_signature = self._compress(plaintext_and_optional_signature)

        # ENCRYPT MESSAGE

        pgp_message = self._encrypt(asymmetric_encryption_key_id, compressed_plaintext_and_optional_signature, encrypt,
                                    symmetric_encryption_algorithm)

        # Convert to string
        pgp_message_str = self._convert(pgp_message)

        return pgp_message_str

    def _convert(self, pgp_message):
        pgp_message_bytes: bytes = pgp_message.to_bytes()
        pgp_message_str = self.convertor.encode(pgp_message_bytes)
        return pgp_message_str

    def _encrypt(self, asymmetric_encryption_key_id, compressed_plaintext_and_optional_signature, encrypt,
                 symmetric_encryption_algorithm):
        if encrypt:
            session_key: SessionKey = self.session_key_generator.generate_session_key(symmetric_encryption_algorithm)

            compressed_plaintext_and_optional_signature: bytes = self.symmetric_encryptor.encrypt(
                session_key=session_key,
                plaintext=compressed_plaintext_and_optional_signature,
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
            message_and_optional_signature_compressed_bytes=compressed_plaintext_and_optional_signature,
            is_encrypted=encrypt,
            symmetric_encryption_algorithm=symmetric_encryption_algorithm,
            asymmetric_encryption_key_id=asymmetric_encryption_key_id,
            encrypted_session_key=encrypted_session_key,
        )
        return pgp_message

    def _compress(self, plaintext_and_optional_signature):
        compressed_plaintext_and_optional_signature: bytes = self.compressor.compress(
            plaintext_and_optional_signature.to_bytes())
        return compressed_plaintext_and_optional_signature

    def _sign(self, password, plaintext, sign, signing_key_id):
        if sign:
            signing_key = self.key_manager.get_key_pair_by_key_id(key_id=signing_key_id,
                                                                  password=password).get_private_key()

            signature: bytes = self.message_signer.sign(message=plaintext,
                                                        private_key=signing_key,
                                                        algorithm=signing_key.get_algorithm())
        else:
            signing_key_id = None
            signature = None
        plaintext_and_optional_signature = PlaintextAndOptionalSignature(plaintext=plaintext,
                                                                         is_signed=sign,
                                                                         signature_bytes=signature,
                                                                         signing_key_id=signing_key_id)
        return plaintext_and_optional_signature

    def send_message(self, pgp_message_str: str, message_path: str):
        print("Sending message to file: " + message_path)
        print("Message: " + pgp_message_str)
        with open(message_path, "w") as file:
            file.write(pgp_message_str)


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
    pgp_message_str = sender.prepare_message_with_mails(plaintext="Hello World",
                                                        sender_mail="user1@gmail.com",
                                                        receiver_mail="user2@gmail.com",
                                                        password="password",
                                                        symmetric_encryption_algorithm=Algorithm.TRIPLE_DES,
                                                        sign=True,
                                                        encrypt=True)
    print(str(pgp_message_str))
    sender.send_message(pgp_message_str=pgp_message_str, message_path="message.pgp")


if __name__ == '__main__':
    test_message_send()
    test_message_receive()
