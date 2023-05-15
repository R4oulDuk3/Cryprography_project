from abc import ABC, abstractmethod

from src.pgp.consts.consts import SymmetricEncryptionAlgorithm


class SymmetricEncryptor:
    def __init__(self):
        self._algorithms = {
            SymmetricEncryptionAlgorithm.TRIPLE_DES: TripleDESSymmetricEncryptionStrategy(),
            SymmetricEncryptionAlgorithm.AES_128: AES128SymmetricEncryptionStrategy()
        }

    def encrypt(self, session_key, data, algorithm: SymmetricEncryptionAlgorithm):
        return self._algorithms[algorithm].encrypt(session_key, data)

    def decrypt(self, session_key, data, algorithm: SymmetricEncryptionAlgorithm):
        return self._algorithms[algorithm].decrypt(session_key, data)


class AbstractSymmetricEncryptionStrategy(ABC):
    @abstractmethod
    def encrypt(self, session_key, data):
        pass

    @abstractmethod
    def decrypt(self, session_key, data):
        pass


class TripleDESSymmetricEncryptionStrategy(AbstractSymmetricEncryptionStrategy):
    def encrypt(self, session_key, data):
        raise NotImplementedError()

    def decrypt(self, session_key, data):
        raise NotImplementedError()


class AES128SymmetricEncryptionStrategy(AbstractSymmetricEncryptionStrategy):
    def encrypt(self, session_key, data):
        raise NotImplementedError()

    def decrypt(self, session_key, data):
        raise NotImplementedError()
