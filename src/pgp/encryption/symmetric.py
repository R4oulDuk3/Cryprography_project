from abc import ABC, abstractmethod
from src.pgp.consts.consts import Algorithm, UTF_8
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import CAST

from src.pgp.key.generate.session import TripleDESSessionKeyGeneratorStrategy, SessionKeyGenerator
from src.pgp.key.key import CAST128SessionKey, SessionKey, TripleDESSessionKey
from src.pgp.util.util import validate_if_algorithm_symmetric_encryption


class SymmetricEncryptor:
    def __init__(self):
        self._algorithms = {
            Algorithm.TRIPLE_DES: TripleDESSymmetricEncryptionStrategy(),
            Algorithm.CAST_128: CAST128SymmetricEncryptionStrategy()
        }

    def encrypt(self, session_key: SessionKey, plaintext: str | bytes,
                algorithm: Algorithm) -> bytes:
        validate_if_algorithm_symmetric_encryption(algorithm)
        return self._algorithms[algorithm].encrypt(session_key, plaintext)

    def decrypt(self, session_key: SessionKey, ciphertext: str | bytes,
                algorithm: Algorithm) -> bytes:
        validate_if_algorithm_symmetric_encryption(algorithm)
        return self._algorithms[algorithm].decrypt(session_key, ciphertext)


class AbstractSymmetricEncryptionStrategy(ABC):
    @abstractmethod
    def encrypt(self, session_key: SessionKey, plaintext: str) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, session_key: SessionKey, ciphertext: bytes) -> bytes:
        pass


class TripleDESSymmetricEncryptionStrategy(AbstractSymmetricEncryptionStrategy):
    def encrypt(self, session_key: TripleDESSessionKey, data) -> bytes:
        if isinstance(data, str):
            data = data.encode('utf-8')
        tdes = DES3.new(session_key.get_key(), DES3.MODE_CFB)
        iv = tdes.iv
        encrypted_data = iv + tdes.encrypt(data)
        return encrypted_data

    def decrypt(self, session_key: TripleDESSessionKey, data) -> bytes:
        iv = data[:DES3.block_size]
        encrypted_data = data[DES3.block_size:]
        tdes = DES3.new(session_key.get_key(), DES3.MODE_CFB, iv)
        decrypted_data = tdes.decrypt(data[DES3.block_size:])
        return decrypted_data


class CAST128SymmetricEncryptionStrategy(AbstractSymmetricEncryptionStrategy):
    def encrypt(self, session_key: CAST128SessionKey, plaintext: str | bytes) -> bytes:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode(UTF_8)
        ciphertext = CAST.new(session_key.get_key(), CAST.MODE_OPENPGP).encrypt(plaintext=plaintext)
        return ciphertext

    def decrypt(self, session_key: CAST128SessionKey, ciphertext: bytes | str) -> bytes:
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode(UTF_8)
        eiv = ciphertext[:CAST.block_size + 2]
        ciphertext = ciphertext[CAST.block_size + 2:]
        plaintext = CAST.new(session_key.get_key(), CAST.MODE_OPENPGP, eiv).decrypt(ciphertext)
        return plaintext


def test_cast128():
    try:
        print("============================================")
        print("\t" * 2 + "CAST128 encryption/decryption")
        print("--------------------------------------------")
        plaintext = "hello world"
        key = CAST128SessionKey(b"12345678")
        ciphertext = SymmetricEncryptor().encrypt(key, plaintext, Algorithm.CAST_128)
        print(ciphertext)
        print(SymmetricEncryptor().decrypt(key, ciphertext, Algorithm.CAST_128))
    except (TypeError, ValueError) as e:
        print("CAST128 test failed.")

    print("============================================")


def test_tripledes():
    try:
        print("============================================")
        print("\t" * 2 + "TripleDES encryption/decryption")
        print("--------------------------------------------")
        data = 'TripleDES check sentence.'
        session_key = SessionKeyGenerator().generate_session_key(Algorithm.TRIPLE_DES)
        encrypted_data = SymmetricEncryptor().encrypt(session_key, data, Algorithm.TRIPLE_DES)
        decry_data = SymmetricEncryptor().decrypt(session_key, encrypted_data, Algorithm.TRIPLE_DES)
        print(encrypted_data)
        print(decry_data)
    except (TypeError, ValueError) as e:
        print("TripleDES test failed.")
    print("============================================")


if __name__ == "__main__":
    test_tripledes()
    test_cast128()
