from src.pgp.compression.compressor import Compressor, ZIPCompressor
from src.pgp.consts.consts import Algorithm
from src.pgp.conversion.convertor import Convertor, Radix64Convertor
from src.pgp.encryption.asymmetric import AsymmetricEncryptor
from src.pgp.encryption.symmetric import SymmetricEncryptor
from src.pgp.key.generate.session import SessionKeyGenerator
from src.pgp.key.key_serializer import KeySerializer

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
        with(open(path_to_message, "rb")) as file:
            message = file.read()
        return PGPMessage.from_bytes(data=message)

    def decrypt_message(self,
                        message: PGPMessage,
                        password: str) -> str:
        print(message)
        sender_public_key = self.key_manager.get_public_key_by_user_email(email=message.sender_mail)
        if not self.message_signer.verify(message=message.encrypted_message,
                                          public_key=sender_public_key,
                                          algorithm=sender_public_key.get_algorithm(),
                                          signature=message.signature
                                          ):
            raise Exception("Message was not signed by sender")
        print("Signature verified")
        receiver_private_key = self.key_manager.get_key_pair_by_user_mail(email=message.receiver_mail,
                                                                          password=password).get_private_key()
        encrypted_session_key = message.encrypted_session_key
        session_key_bytes = self.asymmetric_encryptor.decrypt(ciphertext=encrypted_session_key,
                                                              private_key=receiver_private_key,
                                                              algorithm=receiver_private_key.get_algorithm())

        session_key = self.key_serializer.bytes_to_session_key(key_bytes=session_key_bytes,
                                                               algorithm=message.symmetric_encryption_algorithm)
        encrypted_message = message.encrypted_message
        if message.was_compressed:
            encrypted_message = self.compressor.decompress(encrypted_message)
        plaintext = self.symmetric_encryptor.decrypt(session_key=session_key,
                                                     ciphertext=encrypted_message,
                                                     algorithm=session_key.get_algorithm())
        plaintext.decode("utf-8")
        if message.was_converted:
            plaintext = self.convertor.decode(plaintext)
        return plaintext


def init_test():
    key_manager_user_1 = KeyManager(user_name="user1")
    key_manager_user_2 = KeyManager(user_name="user2")
    key_manager_user_1.generate_key_pair(password="password",
                                         email="user1@gmail.com",
                                         key_size=2048,
                                         algorithm=Algorithm.RSA)
    key_manager_user_2.generate_key_pair(password="password",
                                         email="user2@gmail.com",
                                         key_size=2048,
                                         algorithm=Algorithm.RSA)


def test_message_receive():
    try:
        init_test()
    except:
        pass

    receiver = Receiver(key_manager=KeyManager(user_name="user2"),
                        message_signer=Signer(),
                        symmetric_encryptor=SymmetricEncryptor(),
                        asymmetric_encryptor=AsymmetricEncryptor(),
                        compressor=ZIPCompressor(),
                        convertor=Radix64Convertor(),
                        session_key_generator=SessionKeyGenerator(),
                        key_serializer=KeySerializer())
    message = receiver.unpack_message(path_to_message="./message.pgp")
    plaintext = receiver.decrypt_message(message=message, password="password")
    print(plaintext)


if __name__ == '__main__':
    test_message_receive()
