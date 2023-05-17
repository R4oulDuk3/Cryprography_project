from abc import ABC, abstractmethod
from src.pgp.consts.consts import SigningAlgorithm
import rsa
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA1


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
    def sign(self, private_key, message):
        if isinstance(message, str):
            message = message.encode('utf-8')

        if isinstance(private_key, str):
            private_key = rsa.PrivateKey.load_pkcs1(private_key.encode('utf-8'))

        signature = rsa.sign(message, private_key, 'SHA-1')
        return signature


class DSASigningAlgorithmStrategy(SigningAlgorithmStrategy):
    def sign(self, private_key, message):
        if isinstance(message, str):
            message = message.encode('utf-8')

        if isinstance(private_key, str):
            private_key = DSA.import_key(private_key)

        hashed_msg = SHA1.new(message)
        signer = DSS.new(private_key, 'fips-186-3')
        signature = signer.sign(hashed_msg)
        return signature


if __name__ == "__main__":
    # RSA sign test byte
    (public_key_rsa_b, private_key_rsa_b) = rsa.newkeys(1024)
    message_rsa_b = b'My byte example.'
    signer = Signer()
    signature_rsa_s = signer.sign(private_key_rsa_b, message_rsa_b, SigningAlgorithm.RSA)
    try:
        rsa.verify(message_rsa_b, signature_rsa_s, public_key_rsa_b)
        print("RSA signature verified.")
    except rsa.VerificationError:
        print("RSA signature failed.")

    # DSA sign test byte
    private_key_dsa_b = DSA.generate(1024)
    message_dsa_b = b'My byte example.'
    public_key_dsa_b = private_key_dsa_b.publickey()
    signature_dsa_b = signer.sign(private_key_dsa_b, message_dsa_b, SigningAlgorithm.DSA)
    try:
        verifier = DSS.new(public_key_dsa_b, 'fips-186-3')
        verifier.verify(SHA1.new(message_dsa_b), signature_dsa_b)
        print("DSA signature verified.")
    except ValueError:
        print("DSA signature failed.")


    # RSA sign test string
    (public_key_rsa_s, private_key_rsa_s) = rsa.newkeys(1024)
    message_rsa_s = 'My string example.'
    signature_rsa_s = signer.sign(private_key_rsa_s, message_rsa_s, SigningAlgorithm.RSA)
    try:
        rsa.verify(message_rsa_s.encode('utf-8'), signature_rsa_s, public_key_rsa_s)
        print("RSA signature verified.")
    except rsa.VerificationError:
        print("RSA signature failed.")

    # DSA sign test string
    private_key_dsa_s = DSA.generate(1024)
    message_dsa_s = 'My string example.'
    public_key_dsa_s = private_key_dsa_s.publickey()
    signature_dsa_s = signer.sign(private_key_dsa_s, message_dsa_s, SigningAlgorithm.DSA)
    try:
        verifier = DSS.new(public_key_dsa_s, 'fips-186-3')
        verifier.verify(SHA1.new(message_dsa_s.encode('utf-8')), signature_dsa_s)
        print("DSA signature verified.")
    except ValueError:
        print("DSA signature failed.")


