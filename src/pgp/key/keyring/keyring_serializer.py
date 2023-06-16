import rsa

from src.pgp.consts.consts import Algorithm, \
    KeyPairPrivateRingAttributes, UTF_8, PRIVATE_KEY_RING_SALT, PublicKeyPublicRingAttributes
from src.pgp.encryption.symmetric import SymmetricEncryptor
from src.pgp.hash.hash import SHA1Hasher
from src.pgp.key.key import PublicKey, RSAPrivateKey, RSAPublicKey, KeyPair, CAST128SessionKey, made_key_id
from src.pgp.key.key_serializer import KeySerializer


def _private_ring_json_verify_all_attributes_exist(key_json: dict):
    for attribute in KeyPairPrivateRingAttributes:
        if attribute.value not in key_json:
            raise ValueError(f"{attribute} is missing from key_json")


class SecretKeyRingSerializer:
    def __init__(self):
        self._symmetric_encryptor = SymmetricEncryptor()
        self._hasher = SHA1Hasher()
        self._key_serializer = KeySerializer()

    def _validate_password(self, password: str, key_json: dict):
        hashed_password_with_salt = self._hasher.hash(message=f"{password}:{PRIVATE_KEY_RING_SALT}")
        if hashed_password_with_salt != bytes.fromhex(
                key_json[KeyPairPrivateRingAttributes.HASHED_PASSWORD_WITH_SALT.value]):
            raise ValueError("Invalid password")

    def _decrypt_private_key(self, key_json: dict, password: str) -> bytes:
        self._validate_password(password=password, key_json=key_json)
        hashed_password = self._hasher.hash(message=password)
        cast128_session_key = CAST128SessionKey(key=hashed_password[:16])
        return self._symmetric_encryptor.decrypt(
            ciphertext=bytes.fromhex(key_json[KeyPairPrivateRingAttributes.ENCRYPTED_PRIVATE_KEY.value]),
            session_key=cast128_session_key,
            algorithm=Algorithm.CAST_128
        )

    def key_pair_json_deserialize(self, key_json: dict, password: str) -> KeyPair:
        _private_ring_json_verify_all_attributes_exist(key_json=key_json)
        private_key: bytes = self._decrypt_private_key(key_json=key_json, password=password)

        # if key_json[KeyPairPrivateRingAttributes.ALGORITHM.value] == AsymmetricEncryptionAlgorithm.RSA.value:
        return KeyPair(
            public_key=self._key_serializer.bytes_to_public_key(
                key_bytes=bytes.fromhex(key_json[KeyPairPrivateRingAttributes.PUBLIC_KEY.value]),
                algorithm=Algorithm[key_json[KeyPairPrivateRingAttributes.ALGORITHM.value]]
            ),
            private_key=self._key_serializer.bytes_to_private_key(
                key_bytes=private_key,
                algorithm=Algorithm[key_json[KeyPairPrivateRingAttributes.ALGORITHM.value]]
            ),
            algorithm=Algorithm[key_json[KeyPairPrivateRingAttributes.ALGORITHM.value]]
        )

    def key_pair_json_serialize(self, key_pair: KeyPair, password: str, user_name: str, user_email: str):
        hashed_password_with_salt: bytes = self._hasher.hash(message=f"{password}:{PRIVATE_KEY_RING_SALT}")
        hashed_password: bytes = self._hasher.hash(message=password)
        # print("Len hashed password: " + str(len(hashed_password)))

        private_key_bytes: bytes = self._key_serializer.private_key_to_bytes(key=key_pair.get_private_key())
        public_key_bytes: bytes = self._key_serializer.public_key_to_bytes(key=key_pair.get_public_key())
        encrypted_private_key = self._symmetric_encryptor.encrypt(
            plaintext=private_key_bytes.decode(UTF_8),
            session_key=CAST128SessionKey(key=hashed_password[:16]),
            algorithm=Algorithm.CAST_128
        )
        key_json = {
            KeyPairPrivateRingAttributes.HASHED_PASSWORD_WITH_SALT.value: hashed_password_with_salt.hex(),
            KeyPairPrivateRingAttributes.ENCRYPTED_PRIVATE_KEY.value: encrypted_private_key.hex(),
            KeyPairPrivateRingAttributes.PUBLIC_KEY.value: public_key_bytes.hex(),
            KeyPairPrivateRingAttributes.ALGORITHM.value: key_pair.get_algorithm().value,
            KeyPairPrivateRingAttributes.USER_NAME.value: user_name,
            KeyPairPrivateRingAttributes.USER_EMAIL.value: user_email,
            KeyPairPrivateRingAttributes.KEY_ID.value: made_key_id(key_bytes=public_key_bytes)
        }
        return key_json


class PublicKeyRingSerializer:
    def __init__(self):
        self._symmetric_encryptor = SymmetricEncryptor()
        self._hasher = SHA1Hasher()
        self._key_serializer = KeySerializer()

    def public_key_json_deserialize(self, public_key_json: dict) -> PublicKey:
        if PublicKeyPublicRingAttributes.ALGORITHM.value not in public_key_json:
            raise ValueError("Algorithm is missing from key_json")
        return self._key_serializer.bytes_to_public_key(
            key_bytes=bytes.fromhex(public_key_json[PublicKeyPublicRingAttributes.PUBLIC_KEY.value]),
            algorithm=Algorithm[public_key_json[KeyPairPrivateRingAttributes.ALGORITHM.value]]
        )

    def public_key_json_serialize(self, public_key: PublicKey, user_email, user_name) -> dict:
        public_key_bytes: bytes = self._key_serializer.public_key_to_bytes(key=public_key)
        return {
            PublicKeyPublicRingAttributes.PUBLIC_KEY.value: public_key_bytes.hex(),
            PublicKeyPublicRingAttributes.ALGORITHM.value: Algorithm.RSA.value,
            PublicKeyPublicRingAttributes.USER_NAME.value: user_name,
            PublicKeyPublicRingAttributes.USER_EMAIL.value: user_email,
            PublicKeyPublicRingAttributes.KEY_ID.value: made_key_id(key_bytes=public_key_bytes)
        }


def test_key_serializer():
    (public_key, private_key) = rsa.newkeys(1024)
    secret_key_ring_serializer = SecretKeyRingSerializer()
    print("Public key: " + str(public_key))
    print("Private key: " + str(private_key))
    key_pair = KeyPair(
        public_key=RSAPublicKey(public_key),
        private_key=RSAPrivateKey(private_key),
        algorithm=Algorithm.RSA
    )
    key_pair_json = secret_key_ring_serializer.key_pair_json_serialize(
        key_pair=key_pair,
        password="password",
        user_name="test",
        user_email="test"
    )
    print(key_pair_json)

    key_pair = secret_key_ring_serializer.key_pair_json_deserialize(key_json=key_pair_json, password="password")
    print("Public key: " + str(key_pair.get_public_key().get_key()))
    print("Private key: " + str(key_pair.get_private_key().get_key()))

    public_key_ring_serializer = PublicKeyRingSerializer()
    public_key_json = public_key_ring_serializer.public_key_json_serialize(public_key=key_pair.get_public_key(), user_email="test", user_name="test")
    print(public_key_json)
    public_key = public_key_ring_serializer.public_key_json_deserialize(public_key_json=public_key_json)
    print("Public key: " + str(public_key.get_key()))
    print("Public key: " + str(key_pair.get_public_key().get_key()))
    print("Public key: " + str(public_key.get_key() == key_pair.get_public_key().get_key()))


if __name__ == "__main__":
    test_key_serializer()
