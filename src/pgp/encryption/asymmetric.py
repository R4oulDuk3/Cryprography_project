from abc import ABC, abstractmethod
from enum import Enum

from src.pgp.consts.consts import AsymmetricEncryptionAlgorithm


class AsymmetricEncryptor:
    def __init__(self):
        self._algorithms = {
            AsymmetricEncryptionAlgorithm.RSA: RSASymmetricEncryptionStrategy(),
            AsymmetricEncryptionAlgorithm.ELGAMAL: ElGamalAsymmetricEncryptionStrategy()
        }

    def encrypt(self, public_key, message, algorithm: AsymmetricEncryptionAlgorithm):
        pass

    def decrypt(self, private_key, message, algorithm: AsymmetricEncryptionAlgorithm):
        pass


class AbstractAsymmetricEncryptionStrategy(ABC):
    @abstractmethod
    def encrypt(self, public_key, message):
        pass

    @abstractmethod
    def decrypt(self, private_key, message):
        pass


class RSASymmetricEncryptionStrategy(AbstractAsymmetricEncryptionStrategy):
    def encrypt(self, public_key, message):
        raise NotImplementedError()

    def decrypt(self, private_key, message):
        raise NotImplementedError()


class ElGamalAsymmetricEncryptionStrategy(AbstractAsymmetricEncryptionStrategy):
    def encrypt(self, public_key, message):
        raise NotImplementedError()

    def decrypt(self, private_key, message):
        raise NotImplementedError()
