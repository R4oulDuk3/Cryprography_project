from enum import Enum

PRIVATE_KEY_RING_SALT = 'private_key_ring_salt'

KEY_ID_LENGTH = 8
UTF_8 = 'utf-8'
UTF_16 = 'utf-16'
SECRET_KEY_RING_FILE = 'secret_key_ring.json'
DATA_DIR = 'data'
PUBLIC_KEY_RING_FILE = 'public_key_ring.json'


class PrivateRingElementAttributes(Enum):
    SIGNING_KEY_PAIR = 'signing_key_pair'
    ENCRYPTION_KEY_PAIR = 'encryption_key_pair'


class KeyPairPrivateRingAttributes(Enum):
    USER_NAME = 'user_name'
    USER_EMAIL = 'user_email'
    PUBLIC_KEY = 'public_key'
    ENCRYPTED_PRIVATE_KEY = 'encrypted_private_key'
    HASHED_PASSWORD_WITH_SALT = 'hashed_password_with_salt'
    ALGORITHM = 'algorithm'
    KEY_ID = 'key_id'


class PublicKeyRingElementAttributes(Enum):
    SIGNING_KEY = 'signing_public_key'
    ENCRYPTION_KEY = 'encryption_public_key'
    USER_NAME = 'user_name'


class PublicKeyPublicRingAttributes(Enum):
    ALGORITHM = 'algorithm'
    PUBLIC_KEY = 'public_key'
    USER_EMAIL = 'email'
    USER_NAME = 'name'
    KEY_ID = 'key_id'


class Algorithm(Enum):
    RSA = 'RSA'
    DSA = 'DSA'
    ELGAMAL = 'ElGamal'
    TRIPLE_DES = '3DES'
    CAST_128 = 'CAST128'


SIGNING_ALGORITHMS = [Algorithm.RSA, Algorithm.DSA]
ASYMMETRIC_ENCRYPTION_ALGORITHMS = [Algorithm.RSA, Algorithm.ELGAMAL]
SYMMETRIC_ENCRYPTION_ALGORITHMS = [Algorithm.TRIPLE_DES, Algorithm.CAST_128]


class AlgorithmType(Enum):
    SIGNING = 'signing'
    ASYMMETRIC_ENCRYPTION = 'asymmetric_encryption'
    SYMMETRIC_ENCRYPTION = 'symmetric_encryption'


class KeyType(Enum):
    PUBLIC = 'public'
    PRIVATE = 'private'
    SESSION = 'session'


KEY_SIZES = [1024, 2048]


class KeyUsage(Enum):
    SIGN = 'sign'
    ENCRYPT = 'encrypt'
