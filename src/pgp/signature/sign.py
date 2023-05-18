from abc import ABC, abstractmethod
from typing import Union
from src.pgp.consts.consts import SigningAlgorithm, KeyPairGeneratorType
import rsa
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA1

from src.pgp.key.generate.keypair import KeyPairGenerator
from src.pgp.key.key import RSAPrivateKey, RSAPublicKey, DSAPrivateKey, DSAPublicKey


class Signer:
    def __init__(self):
        self._strategies = {
            SigningAlgorithm.RSA: RSASigningAlgorithmStrategy(),
            SigningAlgorithm.DSA: DSASigningAlgorithmStrategy()
        }

    def sign(self, private_key, message, algorithm: SigningAlgorithm):
        return self._strategies[algorithm].sign(private_key, message)


class SigningAlgorithmStrategy(ABC):
    @abstractmethod
    def sign(self, private_key, message):
        pass


class RSASigningAlgorithmStrategy(SigningAlgorithmStrategy):
    def sign(self, private_key: RSAPrivateKey, message: str | bytes):
        if isinstance(message, str):
            message = message.encode('utf-8')

        signature = rsa.sign(message, private_key.get_key(), 'SHA-1')
        return signature


class DSASigningAlgorithmStrategy(SigningAlgorithmStrategy):
    def sign(self, private_key: DSAPrivateKey, message: str | bytes):
        if isinstance(message, str):
            message = message.encode('utf-8')

        hashed_msg = SHA1.new(message)
        return DSS.new(private_key.get_key(), 'fips-186-3').sign(hashed_msg)


if __name__ == "__main__":
    # RSA sign test byte
    try:
        (public_key_rsa_b, private_key_rsa_b) = rsa.newkeys(1024)
        public_key_rsa_b_obj = RSAPublicKey(public_key_rsa_b)
        private_key_rsa_b_obj = RSAPrivateKey(private_key_rsa_b)
        message_rsa_b = b'My byte example.'
        signature_rsa_s = RSASigningAlgorithmStrategy().sign(private_key_rsa_b_obj, message_rsa_b)
        rsa.verify(message_rsa_b, signature_rsa_s, public_key_rsa_b)
        print("RSA signature verified.")
    except (rsa.VerificationError, TypeError, ValueError) as e:
        print("RSA signature failed.")

    # DSA sign test byte
    try:
        DSA_key_pair = KeyPairGenerator().generate_key_pair(KeyPairGeneratorType.DSA, KeyPairGenerator().get_available_key_sizes()[0])
        message_dsa_s = 'My string example.'
        signature_dsa_s = Signer().sign(DSA_key_pair.get_private_key(), message_dsa_s, SigningAlgorithm.DSA)
        verifier = DSS.new(DSA_key_pair.get_public_key().get_key(), 'fips-186-3')
        verifier.verify(SHA1.new(message_dsa_s.encode('utf-8')), signature_dsa_s)
        print("DSA signature verified.")
    except (TypeError, ValueError) as e:
        print(f"DSA signature failed. {e}")


