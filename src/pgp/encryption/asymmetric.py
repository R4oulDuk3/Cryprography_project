from abc import ABC, abstractmethod
from src.pgp.consts.consts import AsymmetricEncryptionAlgorithm
from enum import Enum
from typing import Union
import rsa
from src.pgp.key.key import RSAPublicKey, RSAPrivateKey


class AsymmetricEncryptor:
    def __init__(self):
        self._algorithms = {
            AsymmetricEncryptionAlgorithm.RSA: RSASymmetricEncryptionStrategy(),
            AsymmetricEncryptionAlgorithm.ELGAMAL: ElGamalAsymmetricEncryptionStrategy(),
        }

    def encrypt(self, public_key, data, algorithm: AsymmetricEncryptionAlgorithm):
        return self._algorithms[algorithm].encrypt(public_key, data)

    def decrypt(self, private_key, data, algorithm: AsymmetricEncryptionAlgorithm):
        return self._algorithms[algorithm].decrypt(private_key, data)


class AbstractAsymmetricEncryptionStrategy(ABC):
    @abstractmethod
    def encrypt(self, public_key, data):
        pass

    @abstractmethod
    def decrypt(self, private_key, data):
        pass


class ElGamalAsymmetricEncryptionStrategy(AbstractAsymmetricEncryptionStrategy):
    def encrypt(self, public_key, data):
        pass

    def decrypt(self, private_key, data):
        pass


class RSASymmetricEncryptionStrategy(AbstractAsymmetricEncryptionStrategy):
    def encrypt(self, public_key: RSAPublicKey, data: Union[str, bytes]) -> bytes:
        if isinstance(data, str):
            data = data.encode('utf-8')

        encrypted_data = rsa.encrypt(data, public_key.get_key())
        return encrypted_data

    def decrypt(self, private_key: RSAPrivateKey, data: Union[str, bytes]) -> str:
        if isinstance(data, str):
            data = data.encode('utf-8')

        decrypted_data = rsa.decrypt(data, private_key.get_key())
        return decrypted_data.decode('utf-8')


if __name__ == "__main__":

    # RSA encryption/decryption
    try:
        (public_key, private_key) = rsa.newkeys(1024)
        public_key_obj = RSAPublicKey(public_key)
        private_key_obj = RSAPrivateKey(private_key)
        message = 'My RSA message'
        enciphered_message = AsymmetricEncryptor().encrypt(public_key_obj, message, AsymmetricEncryptionAlgorithm.RSA)
        deciphered_message = AsymmetricEncryptor().decrypt(private_key_obj, enciphered_message, AsymmetricEncryptionAlgorithm.RSA)
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