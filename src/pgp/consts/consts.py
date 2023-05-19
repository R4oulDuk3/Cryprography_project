from enum import Enum

PRIVATE_KEY_RING_SALT = 'private_key_ring_salt'

KEY_ID_LENGTH = 64
UTF_8 = 'utf-8'
SECRET_KEY_RING_FILE = 'secret_key_ring.json'
DATA_DIR = 'data'
PUBLIC_KEY_RING_FILE = 'public_key_ring.json'


class KeyPairPrivateRingAttributes(Enum):
    USER_NAME = 'user_name'
    USER_EMAIL = 'user_email'
    PUBLIC_KEY = 'public_key'
    ENCRYPTED_PRIVATE_KEY = 'encrypted_private_key'
    HASHED_PASSWORD_WITH_SALT = 'hashed_password_with_salt'
    ALGORITHM = 'algorithm'


class PublicKeyPublicRingAttributes(Enum):
    ALGORITHM = 'algorithm'
    PUBLIC_KEY = 'public_key'


class Algorithm(Enum):
    RSA = 'RSA'
    DSA = 'DSA'
    ELGAMAL = 'ElGamal'
    TRIPLE_DES = '3DES'
    CAST_128 = 'CAST128'


class KeyType(Enum):
    PUBLIC = 'public'
    PRIVATE = 'private'
    SESSION = 'session'


KEY_SIZES = [1024, 2048]


class KeyUsage(Enum):
    SIGN = 'sign'
    ENCRYPT = 'encrypt'
