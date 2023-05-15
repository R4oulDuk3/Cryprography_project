from abc import ABC, abstractmethod
from src.pgp.consts.consts import SigningAlgorithm


class Signer:
    def __init__(self):
        self._strategies = {
            SigningAlgorithm.RSA: RSASigningAlgorithmStrategy(),
            SigningAlgorithm.DSA: DSASigningAlgorithmStrategy()
        }

    @abstractmethod
    def sign(self, private_key, message, algorithm: SigningAlgorithm):
        return self._strategies[algorithm].sign(private_key, message)


class SigningAlgorithmStrategy(ABC):
    def __init__(self):
        raise NotImplementedError()

    @abstractmethod
    def sign(self, private_key, message):
        raise NotImplementedError()


class RSASigningAlgorithmStrategy(SigningAlgorithmStrategy):

    def sign(self, private_key, message):
        pass


class DSASigningAlgorithmStrategy(SigningAlgorithmStrategy):

    def sign(self, private_key, message):
        pass
