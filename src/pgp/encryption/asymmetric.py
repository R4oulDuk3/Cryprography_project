from abc import ABC, abstractmethod
from enum import Enum

from src.pgp.consts.consts import AsymmetricEncryptionAlgorithm


class AsymmetricEncryptor:
    def __init__(self):
        self._algorithms = {
            AsymmetricEncryptionAlgorithm.RSA: RSASymmetricEncryptionStrategy(),
            AsymmetricEncryptionAlgorithm.ELGAMAL: ElGamalAsymmetricEncryptionStrategy()
        }

    def encrypt(self, public_key, data, algorithm: AsymmetricEncryptionAlgorithm):
        pass

    def decrypt(self, private_key, data, algorithm: AsymmetricEncryptionAlgorithm):
        pass


class AbstractAsymmetricEncryptionStrategy(ABC):
    @abstractmethod
    def encrypt(self, public_key, data):
        pass

    @abstractmethod
    def decrypt(self, private_key, data):
        pass


class RSASymmetricEncryptionStrategy(AbstractAsymmetricEncryptionStrategy):
    def encrypt(self, public_key, data):
        raise NotImplementedError()

    def decrypt(self, private_key, data):
        raise NotImplementedError()


class ElGamalAsymmetricEncryptionStrategy(AbstractAsymmetricEncryptionStrategy):
    def encrypt(self, public_key, data):
        raise NotImplementedError()

    def decrypt(self, private_key, data):
        raise NotImplementedError()
