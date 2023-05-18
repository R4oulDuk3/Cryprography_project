from abc import ABC, abstractmethod
from src.pgp.consts.consts import SymmetricEncryptionAlgorithm
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from src.pgp.consts.consts import SymmetricEncryptionAlgorithm, UTF_8
from Crypto.Cipher import CAST

from src.pgp.key.generate.session import TripleDESSessionKeyGeneratorStrategy
from src.pgp.key.key import CAST128SessionKey, SessionKey, TripleDESSessionKey


class SymmetricEncryptor:
    def __init__(self):
        self._algorithms = {
            SymmetricEncryptionAlgorithm.TRIPLE_DES: TripleDESSymmetricEncryptionStrategy(),
            SymmetricEncryptionAlgorithm.AES_128: AES128SymmetricEncryptionStrategy(),
            SymmetricEncryptionAlgorithm.CAST_128: CAST128SymmetricEncryptionStrategy()
        }

    def encrypt(self, session_key: SessionKey, plaintext: str, algorithm: SymmetricEncryptionAlgorithm):
        return self._algorithms[algorithm].encrypt(session_key, plaintext)

    def decrypt(self, session_key: SessionKey, ciphertext: bytes, algorithm: SymmetricEncryptionAlgorithm):
        return self._algorithms[algorithm].decrypt(session_key, ciphertext)


class AbstractSymmetricEncryptionStrategy(ABC):
    @abstractmethod
    def encrypt(self, session_key: SessionKey, plaintext: str):
        pass

    @abstractmethod
    def decrypt(self, session_key: SessionKey, ciphertext: bytes):
        pass


class AES128SymmetricEncryptionStrategy(AbstractSymmetricEncryptionStrategy):
    def encrypt(self, session_key: SessionKey, plaintext: str):
        raise NotImplementedError()

    def decrypt(self, session_key: SessionKey, ciphertext: bytes):
        raise NotImplementedError()


class TripleDESSymmetricEncryptionStrategy(AbstractSymmetricEncryptionStrategy):
    def encrypt(self, session_key: TripleDESSessionKey, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        tdes = DES3.new(session_key.get_key(), DES3.MODE_CFB)
        iv = tdes.iv
        encrypted_data = iv + tdes.encrypt(data)
        return encrypted_data

    def decrypt(self, session_key: TripleDESSessionKey, data):
        iv = data[:DES3.block_size]
        encrypted_data = data[DES3.block_size:]
        tdes = DES3.new(session_key.get_key(), DES3.MODE_CFB, iv)
        decrypted_data = tdes.decrypt(data[DES3.block_size:])
        return decrypted_data.decode('utf-8')


class CAST128SymmetricEncryptionStrategy(AbstractSymmetricEncryptionStrategy):
    def encrypt(self, session_key: CAST128SessionKey, plaintext: str):
        ciphertext = CAST.new(session_key.get_key(), CAST.MODE_OPENPGP).encrypt(plaintext.encode(UTF_8))
        return ciphertext

    def decrypt(self, session_key: CAST128SessionKey, ciphertext: bytes) -> str:
        eiv = ciphertext[:CAST.block_size + 2]
        ciphertext = ciphertext[CAST.block_size + 2:]
        plaintext = CAST.new(session_key.get_key(), CAST.MODE_OPENPGP, eiv).decrypt(ciphertext).decode(UTF_8)
        return plaintext


def test_cast128():
    try:
        print("============================================")
        print("\t" * 2 + "CAST128 encryption/decryption")
        print("--------------------------------------------")
        plaintext = "hello world"
        key = CAST128SessionKey(b"12345678")
        ciphertext = CAST128SymmetricEncryptionStrategy().encrypt(key, plaintext)
        print(ciphertext)
        print(CAST128SymmetricEncryptionStrategy().decrypt(key, ciphertext))
    except (TypeError, ValueError) as e:
        print("CAST128 test failed.")

    print("============================================")


def test_tripledes():
    try:
        print("============================================")
        print("\t" * 2 + "TripleDES encryption/decryption")
        print("--------------------------------------------")
        data = 'TripleDES check sentence.'
        session_key = TripleDESSessionKeyGeneratorStrategy().generate_session_key()
        encrypted_data = TripleDESSymmetricEncryptionStrategy().encrypt(session_key, data)
        print(encrypted_data)
        decrypted_data = TripleDESSymmetricEncryptionStrategy().decrypt(session_key, encrypted_data)
        print(decrypted_data)
    except (TypeError, ValueError) as e:
        print("TripleDES test failed.")
    print("============================================")


if __name__ == "__main__":
    test_tripledes()
    test_cast128()

