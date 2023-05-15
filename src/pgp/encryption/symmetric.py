from abc import ABC, abstractmethod

from src.pgp.consts.consts import SymmetricEncryptionAlgorithm


class SymmetricEncryptor:
    def __init__(self):
        self._algorithms = {
            SymmetricEncryptionAlgorithm.TRIPLE_DES: TripleDESSymmetricEncryptionStrategy(),
            SymmetricEncryptionAlgorithm.AES_128: AES128SymmetricEncryptionStrategy()
        }


class AbstractSymmetricEncryptionStrategy(ABC):
    @abstractmethod
    def encrypt(self, session_key, message):
        pass

    @abstractmethod
    def decrypt(self, session_key, message):
        pass


class TripleDESSymmetricEncryptionStrategy(AbstractSymmetricEncryptionStrategy):
    def encrypt(self, session_key, message):
        raise NotImplementedError()

    def decrypt(self, session_key, message):
        raise NotImplementedError()


class AES128SymmetricEncryptionStrategy(AbstractSymmetricEncryptionStrategy):
    def encrypt(self, session_key, message):
        raise NotImplementedError()

    def decrypt(self, session_key, message):
        raise NotImplementedError()
