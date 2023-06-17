from abc import ABC, abstractmethod

import rsa
from Crypto.Hash import SHA1
from Crypto.Signature import DSS

from src.pgp.consts.consts import Algorithm, UTF_8
from src.pgp.key.generate.keypair import KeyPairGenerator
from src.pgp.key.key import RSAPrivateKey, RSAPublicKey, DSAPrivateKey, DSAPublicKey, PrivateKey, PublicKey


class Signer:
    def __init__(self):
        self._strategies = {
            Algorithm.RSA: RSASigningAlgorithmStrategy(),
            Algorithm.DSA: DSASigningAlgorithmStrategy()
        }

    def sign(self, private_key: PrivateKey, message: str | bytes, algorithm: Algorithm) -> bytes:
        return self._strategies[algorithm].sign(private_key, message)

    def verify(self, public_key: PublicKey, message: str | bytes, signature: str | bytes, algorithm: Algorithm) -> bool:
        return self._strategies[algorithm].verify(public_key, message, signature)


class SigningAlgorithmStrategy(ABC):
    @abstractmethod
    def sign(self, private_key, message):
        pass


class RSASigningAlgorithmStrategy(SigningAlgorithmStrategy):
    def sign(self, private_key: RSAPrivateKey, message: str | bytes):
        if isinstance(message, str):
            message = message.encode(UTF_8)

        signature = rsa.sign(message, private_key.get_key(), 'SHA-1')
        return signature

    def verify(self, public_key: RSAPublicKey, message: str | bytes, signature: str | bytes):
        if isinstance(message, str):
            message = message.encode(UTF_8)

        if isinstance(signature, str):
            signature = signature.encode(UTF_8)

        try:
            rsa.verify(message, signature, public_key.get_key())
            return True
        except (rsa.VerificationError, TypeError, ValueError):
            return False


class DSASigningAlgorithmStrategy(SigningAlgorithmStrategy):
    def sign(self, private_key: DSAPrivateKey, message: str | bytes):
        if isinstance(message, str):
            message = message.encode(UTF_8)
        hash_obj = SHA1.new(message)
        return DSS.new(private_key.get_key(), 'fips-186-3').sign(hash_obj)

    def verify(self, public_key: DSAPublicKey, message: str | bytes, signature: str | bytes):
        if isinstance(message, str):
            message = message.encode(UTF_8)

        if isinstance(signature, str):
            signature = signature.encode(UTF_8)

        hashed_msg = SHA1.new(message)
        verifier = DSS.new(public_key.get_key(), 'fips-186-3')
        try:
            verifier.verify(hashed_msg, signature)
            return True
        except ValueError:
            return False


if __name__ == "__main__":
    # RSA sign test byte
    try:
        RSA_key_pair = KeyPairGenerator().generate_key_pair(Algorithm.RSA,
                                                            KeyPairGenerator().get_available_key_sizes()[0])
        message_rsa_b = b'My byte example.'
        signature_rsa_s = Signer().sign(RSA_key_pair.get_private_key(), message_rsa_b, Algorithm.RSA)
        result = Signer().verify(RSA_key_pair.get_public_key(), message_rsa_b, signature_rsa_s, Algorithm.RSA)
        if result:
            print("RSA signature verified.")
        else:
            print("RSA signature failed.")
    except (rsa.VerificationError, TypeError, ValueError) as e:
        print(f"RSA signature failed. {e}")

    # DSA sign test byte
    try:
        DSA_key_pair = KeyPairGenerator().generate_key_pair(Algorithm.DSA,
                                                            KeyPairGenerator().get_available_key_sizes()[0])
        message_dsa_s = 'My string example.'
        signature_dsa_s = Signer().sign(DSA_key_pair.get_private_key(), message_dsa_s, Algorithm.DSA)
        result = Signer().verify(DSA_key_pair.get_public_key(), message_dsa_s, signature_dsa_s, Algorithm.DSA)
        if result:
            print("DSA signature verified.")
        else:
            print("DSA signature failed.")
    except (TypeError, ValueError) as e:
        print("DSA signature failed.")


