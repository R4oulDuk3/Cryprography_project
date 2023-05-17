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
    # RSA sign test
    (public_key, private_key) = rsa.newkeys(1024)
    message = 'Exemplary message'
    signer = Signer()
    signature = signer.sign(private_key, message, SigningAlgorithm.RSA)
    try:
        rsa.verify(message.encode('utf-8'), signature, public_key)
        print("RSA signature verified.")
    except rsa.VerificationError:
        print("RSA signature failed.")

    # DSA sign test
    private_key = DSA.generate(1024)
    public_key = private_key.publickey()
    message = 'Exemplary message'
    signer = Signer()
    signature = signer.sign(private_key, message, SigningAlgorithm.DSA)
    try:
        verifier = DSS.new(public_key, 'fips-186-3')
        verifier.verify(SHA1.new(message.encode('utf-8')), signature)
        print("DSA signature verified.")
    except ValueError:
        print("DSA signature failed.")
