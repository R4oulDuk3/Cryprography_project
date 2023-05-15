from enum import Enum


class AsymmetricEncryptionAlgorithm(Enum):
    RSA = 'RSA'
    ELGAMAL = 'ElGamal'


class SymmetricEncryptionAlgorithm(Enum):
    TRIPLE_DES = '3DES'
    AES_128 = 'AES128'


class SigningAlgorithm(Enum):
    RSA = 'RSA'
    DSA = 'DSA'


class KeyType(Enum):
    PUBLIC = 'public'
    PRIVATE = 'private'
    SYMMETRICAL = 'symmetrical'


KEY_SIZES = [1024, 2048]


class KeyPairGeneratorType:
    RSA = 'RSA'
    DSA = 'DSA'
    ElGamal = 'ElGamal'


class SessionKeyGeneratorAlgorithm:
    TRIPLE_DES = 'TripleDES'
    AES_128 = 'AES128'


class KeyUsage(Enum):
    SIGN = 'sign'
    ENCRYPT = 'encrypt'


AlrgorithmToKeyUsage = {
    AsymmetricEncryptionAlgorithm.RSA: [KeyUsage.SIGN, KeyUsage.ENCRYPT],
    AsymmetricEncryptionAlgorithm.ELGAMAL: [KeyUsage.ENCRYPT],
    SymmetricEncryptionAlgorithm.TRIPLE_DES: [KeyUsage.ENCRYPT],
    SymmetricEncryptionAlgorithm.AES_128: [KeyUsage.ENCRYPT]

}
