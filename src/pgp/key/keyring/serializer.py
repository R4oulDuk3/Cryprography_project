from enum import Enum

import rsa

from src.pgp.consts.consts import AsymmetricEncryptionAlgorithm, SymmetricEncryptionAlgorithm, SigningAlgorithm, \
    KeyPairPrivateRingAttributes, UTF_8, PRIVATE_KEY_RING_SALT
from src.pgp.encryption.symmetric import SymmetricEncryptor
from src.pgp.key.key import SessionKey, PrivateKey, PublicKey, RSAPrivateKey, RSAPublicKey, KeyPair, CAST128SessionKey
from src.pgp.signature.hash import SHA1Hasher


def _private_ring_json_verify_all_atributes_exist(key_json: dict):
    for attribute in KeyPairPrivateRingAttributes:
        if attribute.value not in key_json:
            raise ValueError(f"{attribute} is missing from key_json")


class KeySerializer:
    def __init__(self):
        self._symmetric_encryptor = SymmetricEncryptor()
        self._hasher = SHA1Hasher()

    def _validate_password(self, password: str, key_json: dict):
        hashed_password_with_salt = self._hasher.hash(message=f"{password}:{PRIVATE_KEY_RING_SALT}")
        if hashed_password_with_salt != key_json[KeyPairPrivateRingAttributes.HASHED_PASSWORD_WITH_SALT.value]:
            raise ValueError("Invalid password")

    def _decrypt_private_key(self, key_json: dict, password: str) -> str:
        self._validate_password(password=password, key_json=key_json)
        hashed_password = self._hasher.hash(message=password)
        cast128_session_key = CAST128SessionKey(key=hashed_password[:16])
        return self._symmetric_encryptor.decrypt(
            ciphertext=key_json[KeyPairPrivateRingAttributes.ENCRYPTED_PRIVATE_KEY.value],
            session_key=cast128_session_key,
            algorithm=SymmetricEncryptionAlgorithm.CAST_128
        )

    def private_ring_json_to_key_pair(self, key_json: dict, password: str) -> KeyPair:

        _private_ring_json_verify_all_atributes_exist(key_json=key_json)
        private_key: str = self._decrypt_private_key(key_json=key_json, password=password)

        if key_json[KeyPairPrivateRingAttributes.ALGORITHM.value] == AsymmetricEncryptionAlgorithm.RSA:
            return KeyPair(
                public_key=RSAPublicKey(
                    rsa.PublicKey.load_pkcs1(key_json[KeyPairPrivateRingAttributes.PUBLIC_KEY.value])),
                private_key=RSAPrivateKey(
                    rsa.PrivateKey.load_pkcs1(private_key.encode(UTF_8))),
                algorithm=AsymmetricEncryptionAlgorithm.RSA
            )
        else:
            raise NotImplementedError()

    def public_ring_json_to_public_key(self, key: str, algorithm: SymmetricEncryptionAlgorithm) -> SessionKey:
        raise NotImplementedError()

    def private_ring_key_pair_to_json(self, key_pair: KeyPair, password: str, user_name: str, user_email: str):
        hashed_password_with_salt: bytes = self._hasher.hash(message=f"{password}:{PRIVATE_KEY_RING_SALT}")
        hashed_password: bytes = self._hasher.hash(message=password)
        print("Len hashed password: " + str(len(hashed_password)))

        if key_pair.get_algorithm() == AsymmetricEncryptionAlgorithm.RSA:
            private_key_bytes: bytes = key_pair.get_private_key().get_key().save_pkcs1()
            public_key_bytes: bytes = key_pair.get_public_key().get_key().save_pkcs1()
            encrypted_private_key = self._symmetric_encryptor.encrypt(
                plaintext=private_key_bytes.decode(UTF_8),
                session_key=CAST128SessionKey(key=hashed_password[:16]),
                algorithm=SymmetricEncryptionAlgorithm.CAST_128
            )
            key_json = {
                KeyPairPrivateRingAttributes.HASHED_PASSWORD_WITH_SALT.value: hashed_password_with_salt,
                KeyPairPrivateRingAttributes.ENCRYPTED_PRIVATE_KEY.value: encrypted_private_key,
                KeyPairPrivateRingAttributes.PUBLIC_KEY.value: public_key_bytes,
                KeyPairPrivateRingAttributes.ALGORITHM.value: AsymmetricEncryptionAlgorithm.RSA,
                KeyPairPrivateRingAttributes.USER_NAME.value: user_name,
                KeyPairPrivateRingAttributes.USER_EMAIL.value: user_email
            }
            return key_json
        else:
            raise NotImplementedError()

    def public_ring_public_key_to_json(self, key: PublicKey):
        raise NotImplementedError()

    def import_private_key_from_pem(self, private_key_pem_path: str, algorithm: Enum) -> PrivateKey:
        with open(private_key_pem_path, 'r') as f:
            key_pem = f.read()
        if algorithm == AsymmetricEncryptionAlgorithm.RSA:
            return RSAPrivateKey(rsa.PrivateKey.load_pkcs1(key_pem.encode(UTF_8)))
        else:
            raise NotImplementedError()

    def import_public_key_from_pem(self, private_key_pem_path: str, algorithm: Enum) -> PublicKey:
        with open(private_key_pem_path, 'r') as f:
            key_pem = f.read()
        if algorithm == AsymmetricEncryptionAlgorithm.RSA:
            return RSAPublicKey(rsa.PublicKey.load_pkcs1(key_pem.encode(UTF_8)))
        else:
            raise NotImplementedError()


def test_key_pair_to_json():
    (public_key, private_key) = rsa.newkeys(1024)
    key_serializer = KeySerializer()
    print("Public key: " + str(public_key))
    print("Private key: " + str(private_key))
    key_pair = KeyPair(
        public_key=RSAPublicKey(public_key),
        private_key=RSAPrivateKey(private_key),
        algorithm=AsymmetricEncryptionAlgorithm.RSA
    )
    key_pair_json = key_serializer.private_ring_key_pair_to_json(
        key_pair=key_pair,
        password="password",
        user_name="test",
        user_email="test"
    )
    print(key_pair_json)

    key_pair = key_serializer.private_ring_json_to_key_pair(key_json=key_pair_json, password="password")
    print("Public key: " + str(key_pair.get_public_key().get_key()))
    print("Private key: " + str(key_pair.get_private_key().get_key()))


if __name__ == "__main__":
    test_key_pair_to_json()
