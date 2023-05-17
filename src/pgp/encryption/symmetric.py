from abc import ABC, abstractmethod

from src.pgp.consts.consts import SymmetricEncryptionAlgorithm
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from src.pgp.consts.consts import SymmetricEncryptionAlgorithm, UTF_8
from Crypto.Cipher import CAST

from src.pgp.key.key import CAST128SessionKey, SessionKey

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


class TripleDESSymmetricEncryptionStrategy(AbstractSymmetricEncryptionStrategy):
    def encrypt(self, session_key, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        tdes = DES3.new(session_key, DES3.MODE_CFB)
        iv = tdes.iv
        encrypted_data = iv + tdes.encrypt(data)
        return encrypted_data

    def decrypt(self, session_key, data):
        iv = data[:DES3.block_size]
        encrypted_data = data[DES3.block_size:]
        tdes = DES3.new(session_key, DES3.MODE_CFB, iv)
        decrypted_data = tdes.decrypt(encrypted_data)
        return decrypted_data.decode('utf-8')

class AES128SymmetricEncryptionStrategy(AbstractSymmetricEncryptionStrategy):
    def encrypt(self, session_key: SessionKey, plaintext: str):
        raise NotImplementedError()

    def decrypt(self, session_key: SessionKey, ciphertext: bytes):
        raise NotImplementedError()



def testTripleDes():
    symmetric_encryptor = SymmetricEncryptor()
    try:
        session_key = get_random_bytes(24)
        adjusted_key = DES3.adjust_key_parity(session_key)
        data = 'TripleDES check sentence.'
        encrypted_data = symmetric_encryptor.encrypt(adjusted_key, data, SymmetricEncryptionAlgorithm.TRIPLE_DES)
        print(encrypted_data)
        decrypted_data = symmetric_encryptor.decrypt(adjusted_key, encrypted_data,
                                                     SymmetricEncryptionAlgorithm.TRIPLE_DES)
        print(decrypted_data)
    except ValueError:
        print("TripleDES check failed")
        
class CAST128SymmetricEncryptionStrategy(AbstractSymmetricEncryptionStrategy):
    def encrypt(self, session_key: CAST128SessionKey, plaintext: str):
        ciphertext = CAST.new(session_key.get_key(), CAST.MODE_OPENPGP).encrypt(plaintext.encode(UTF_8))
        return ciphertext

    def decrypt(self, session_key: CAST128SessionKey, ciphertext: bytes) -> str:
        eiv = ciphertext[:CAST.block_size + 2]
        ciphertext = ciphertext[CAST.block_size + 2:]
        plaintext = CAST.new(session_key.get_key(), CAST.MODE_OPENPGP, eiv).decrypt(ciphertext).decode(UTF_8)
        return plaintext


def testCast128():
    plaintext = "hello world"
    key = CAST128SessionKey(b"12345678")
    ciphertext = CAST128SymmetricEncryptionStrategy().encrypt(key, plaintext)
    print(ciphertext)
    print(CAST128SymmetricEncryptionStrategy().decrypt(key, ciphertext))


if __name__ == "__main__":
    testTripleDes()
    testCast128()

