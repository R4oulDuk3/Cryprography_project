from abc import ABC, abstractmethod
from src.pgp.consts.consts import AsymmetricEncryptionAlgorithm
from enum import Enum
import rsa

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
    def encrypt(self, public_key, data):
        if isinstance(public_key, str):
            public_key = rsa.PublicKey.load_pkcs1(public_key.encode('utf-8'))

        encrypted_data = rsa.encrypt(data.encode('utf-8'), public_key)
        return encrypted_data

    def decrypt(self, private_key, data):
        if isinstance(private_key, str):
            private_key = rsa.PrivateKey.load_pkcs1(private_key.encode('utf-8'))

        decrypted_data = rsa.decrypt(data, private_key)
        return decrypted_data.decode('utf-8')


if __name__ == "__main__":

    # RSA encryption/decryption
    (public_key, private_key) = rsa.newkeys(1024)
    message = 'My RSA message'
    encryptor = AsymmetricEncryptor()
    enciphered_message = encryptor.encrypt(public_key, message, AsymmetricEncryptionAlgorithm.RSA)
    deciphered_message = encryptor.decrypt(private_key, enciphered_message, AsymmetricEncryptionAlgorithm.RSA)
    print("-------------------------------------")
    print("\t\t\tRSA")
    print(f"Original message: {message}")
    print(f"Enciphered message: {enciphered_message.hex()}")
    print(f"Deciphered message: {deciphered_message}")
    print("-------------------------------------")

    # ElGamal encryption/decryption
