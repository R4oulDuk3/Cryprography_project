from abc import ABC, abstractmethod
from src.pgp.consts.consts import Algorithm, UTF_8
from enum import Enum
from typing import Union
import rsa

from src.pgp.key.generate.keypair import KeyPairGenerator
from src.pgp.key.key import RSAPublicKey, RSAPrivateKey, PublicKey, PrivateKey
from src.pgp.util.util import validate_if_algorithm_asymmetric_encryption


class AsymmetricEncryptor:
    def __init__(self):
        self._algorithms = {
            Algorithm.RSA: RSASymmetricEncryptionStrategy(),
            Algorithm.ELGAMAL: ElGamalAsymmetricEncryptionStrategy(),
        }

    def encrypt(self, public_key: PublicKey, plaintext: str | bytes, algorithm: Algorithm) -> bytes:
        validate_if_algorithm_asymmetric_encryption(algorithm)
        return self._algorithms[algorithm].encrypt(public_key, plaintext)

    def decrypt(self, private_key: PrivateKey, ciphertext: str | bytes, algorithm: Algorithm) -> bytes:
        validate_if_algorithm_asymmetric_encryption(algorithm)
        return self._algorithms[algorithm].decrypt(private_key, ciphertext)


class AbstractAsymmetricEncryptionStrategy(ABC):
    @abstractmethod
    def encrypt(self, public_key: PublicKey, plaintext: str | bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, private_key: PrivateKey, ciphertext: str | bytes) -> bytes:
        pass

# TODO: Implement ElGamal encryption/decryption
class ElGamalAsymmetricEncryptionStrategy(AbstractAsymmetricEncryptionStrategy):
    def encrypt(self, public_key: PublicKey, plaintext: str | bytes) -> bytes:
        pass

    def decrypt(self, private_key: PrivateKey, ciphertext: str | bytes) -> bytes:
        pass


class RSASymmetricEncryptionStrategy(AbstractAsymmetricEncryptionStrategy):
    def encrypt(self, public_key: RSAPublicKey, plaintext: str | bytes) -> bytes:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode(UTF_8)

        encrypted_data = rsa.encrypt(plaintext, public_key.get_key())
        return encrypted_data

    def decrypt(self, private_key: RSAPrivateKey, ciphertext: str | bytes) -> bytes:
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode(UTF_8)

        decrypted_data = rsa.decrypt(ciphertext, private_key.get_key())
        return decrypted_data


if __name__ == "__main__":

    # RSA encryption/decryption
    try:
        RSA_key_pair = KeyPairGenerator().generate_key_pair(Algorithm.RSA, KeyPairGenerator().get_available_key_sizes()[0])
        message = 'My RSA message'
        enciphered_message = AsymmetricEncryptor().encrypt(RSA_key_pair.get_public_key(), message, Algorithm.RSA)
        deciphered_message = AsymmetricEncryptor().decrypt(RSA_key_pair.get_private_key(), enciphered_message, Algorithm.RSA)
        print("============================================")
        print("\t" * 2 + "RSA encryption/decryption")
        print("--------------------------------------------")
        print(f"Original message: {message}")
        print(f"Enciphered message: {enciphered_message.hex()}")
        print(f"Deciphered message: {deciphered_message}")
        print("============================================")
    except (TypeError, ValueError) as e:
        print("RSA test failed.")

    # ElGamal encryption/decryption