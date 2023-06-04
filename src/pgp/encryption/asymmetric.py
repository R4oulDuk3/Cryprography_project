from abc import ABC, abstractmethod
from src.pgp.consts.consts import Algorithm, UTF_8
from enum import Enum
from typing import Union
import rsa
import pickle
from src.pgp.key.generate.keypair import KeyPairGenerator
from src.pgp.key.key import RSAPublicKey, RSAPrivateKey, PublicKey, PrivateKey, ElGamalPublicKey, ElGamalPrivateKey
from src.pgp.util.util import validate_if_algorithm_asymmetric_encryption
from Crypto.Util.number import getPrime, GCD
from Crypto.Random import get_random_bytes
from Crypto.Util.number import inverse, getRandomRange


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


class ElGamalAsymmetricEncryptionStrategy(AbstractAsymmetricEncryptionStrategy):
    def encrypt(self, public_key: ElGamalPublicKey, plaintext: str | bytes) -> bytes:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode(UTF_8)

        M = int.from_bytes(plaintext, byteorder='big')
        p, g, y = public_key.get_key()
        K = getRandomRange(2, p - 1)
        a = pow(g, K, p)
        b = (M * pow(y, K, p)) % p
        ciphertext = (a, b)
        return pickle.dumps(ciphertext)

    def decrypt(self, private_key: ElGamalPrivateKey, ciphertext: str | bytes) -> bytes:
        ciphertext = pickle.loads(ciphertext)
        p, g, x = private_key.get_key()
        a, b = ciphertext
        s = pow(a, x, p)
        inv_s = inverse(s, p)
        plaintext = (b * inv_s) % p
        return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, byteorder='big')


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
    try:
        # RSA encryption/decryption
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

        # El Gamal
        El_Gamal_key_pair = KeyPairGenerator().generate_key_pair(
            Algorithm.ELGAMAL,
            KeyPairGenerator().get_available_key_sizes()[0]
        )
        message = 'My ElGamal message'
        enciphered_message = AsymmetricEncryptor().encrypt(
            El_Gamal_key_pair.get_public_key(),
            message,
            Algorithm.ELGAMAL
        )
        deciphered_message = AsymmetricEncryptor().decrypt(
            El_Gamal_key_pair.get_private_key(),
            enciphered_message,
            Algorithm.ELGAMAL
        )
        print("============================================")
        print("\t" * 2 + "ElGamal encryption/decryption")
        print("--------------------------------------------")
        print(f"Original message: {message}")
        print(f"Enciphered message: {enciphered_message.hex()}")
        print(f"Deciphered message: {deciphered_message.decode(UTF_8)}")
        print("============================================")

    except (TypeError, ValueError) as e:
        print(f"Test failed.{e}")
