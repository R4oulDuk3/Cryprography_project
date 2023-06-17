from abc import ABC, abstractmethod

import rsa

import src.pgp.elgamal.elgamal as elgamal
from src.pgp.consts.consts import Algorithm, UTF_8, UTF_16
from src.pgp.key.generate.keypair import KeyPairGenerator
from src.pgp.key.generate.session import SessionKeyGenerator
from src.pgp.key.key import RSAPublicKey, RSAPrivateKey, PublicKey, PrivateKey, ElGamalPublicKey, ElGamalPrivateKey
from src.pgp.key.key_serializer import KeySerializer
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


class ElGamalAsymmetricEncryptionStrategy(AbstractAsymmetricEncryptionStrategy):
    def encrypt(self, public_key: ElGamalPublicKey, plaintext: str | bytes) -> bytes:
        if isinstance(plaintext, bytes):
            plaintext = plaintext.decode(UTF_16)
        res = elgamal.encrypt(public_key.get_key(), plaintext)
        print(f"Encrypted message: {res}")
        return res.encode(UTF_16)

    def decrypt(self, private_key: ElGamalPrivateKey, ciphertext: str | bytes) -> bytes:
        if isinstance(ciphertext, bytes):
            ciphertext = ciphertext.decode(UTF_16)
        res = elgamal.decrypt(private_key.get_key(), ciphertext)
        # For some reason our ElGmal implementation appends an uneeded 2 bytes when decrypting or something
        # So here we just remove them
        return res.encode(UTF_16)[2:]


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
        RSA_key_pair = KeyPairGenerator().generate_key_pair(Algorithm.RSA,
                                                            KeyPairGenerator().get_available_key_sizes()[0])
        message = 'My RSA message'
        enciphered_message = AsymmetricEncryptor().encrypt(RSA_key_pair.get_public_key(), message, Algorithm.RSA)
        deciphered_message = AsymmetricEncryptor().decrypt(RSA_key_pair.get_private_key(), enciphered_message,
                                                           Algorithm.RSA)
        print("============================================")
        print("\t" * 2 + "RSA encryption/decryption")
        print("--------------------------------------------")
        print(f"Original message: {message}")
        print(f"Enciphered message: {enciphered_message.hex()}")
        print(f"Deciphered message: {deciphered_message.decode(UTF_8)}")
        print("============================================")
        assert message == deciphered_message.decode(UTF_8)
        # El Gamal
        El_Gamal_key_pair = KeyPairGenerator().generate_key_pair(
            Algorithm.ELGAMAL,
            KeyPairGenerator().get_available_key_sizes()[0]
        )
        key_serializer = KeySerializer()
        message = key_serializer.session_key_to_bytes(
            key=SessionKeyGenerator().generate_session_key(Algorithm.CAST_128)
        )
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
        print(f"Deciphered message: {deciphered_message}")
        print("============================================")
        assert message == deciphered_message

    except (TypeError, ValueError) as e:
        print(f"Test failed.{e}")
