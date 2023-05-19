"""
1. Генерисање новог и брисање постојећег пара кључева
...Потребно је подржати RSA алгоритам за енкрипцију и
потписивање и комбинацију DSA алгоритма за потписивање и ElGamal алгоритма за енкрипцију
са величинама кључева од 1024 и 2048 бита...
"""

from abc import abstractmethod, ABC

import rsa
from Crypto.PublicKey import DSA

from src.pgp.consts.consts import Algorithm, KEY_SIZES
from src.pgp.key.key import KeyPair, RSAPublicKey, RSAPrivateKey, DSAPrivateKey, DSAPublicKey


class KeyPairGenerator:

    def __init__(self):
        self._strategies = {
            Algorithm.RSA: KeyPairGeneratorStrategyRSA(),
            Algorithm.ELGAMAL: KeyPairGeneratorStrategyElGamal(),
            Algorithm.DSA: KeyPairGeneratorStrategyDSA(),
        }
        self._key_sizes = KEY_SIZES

    def generate_key_pair(self, algorithm: Algorithm, key_size: int) -> KeyPair:
        return self._strategies[algorithm].generate_key_pair(key_size)

    def get_available_algorithms(self):
        return self._strategies.keys()

    def get_available_key_sizes(self):
        return self._key_sizes


# Abstraktna klasa za strategiju generisanja para kljuceva
class KeyPairGeneratorStrategy(ABC):
    @abstractmethod
    def generate_key_pair(self, key_size) -> KeyPair:
        pass


# Note: Ovaj moze da se koristi i za potpisivanje i za enkripciju
class KeyPairGeneratorStrategyRSA(KeyPairGeneratorStrategy):
    def generate_key_pair(self, key_size) -> KeyPair:
        (public_key, private_key) = rsa.newkeys(key_size)
        return KeyPair(
            private_key=RSAPrivateKey(key=private_key),
            public_key=RSAPublicKey(key=public_key),
            algorithm=Algorithm.RSA
        )


# Note: Ovaj moze da se koristi za potpisivanje
class KeyPairGeneratorStrategyDSA(KeyPairGeneratorStrategy):
    def generate_key_pair(self, key_size) -> KeyPair:
        private_key = DSA.generate(key_size)
        return KeyPair(
            private_key=DSAPrivateKey(key=private_key),
            public_key=DSAPublicKey(key=private_key.publickey()),
            algorithm=Algorithm.DSA
        )


# Note: Ovaj moze da se koristi za enkripciju
class KeyPairGeneratorStrategyElGamal(KeyPairGeneratorStrategy):
    def generate_key_pair(self, key_size) -> KeyPair:
        pass


def test_key_gen():
    key_pair_generator = KeyPairGenerator()
    key_pair = key_pair_generator.generate_key_pair(Algorithm.RSA, 1024)
    print(key_pair.get_private_key().get_key())
    print(key_pair.get_public_key().get_key())

    key_pair = key_pair_generator.generate_key_pair(Algorithm.RSA, 2048)
    print(key_pair.get_private_key().get_key())
    print(key_pair.get_public_key().get_key())


if __name__ == '__main__':
    test_key_gen()
