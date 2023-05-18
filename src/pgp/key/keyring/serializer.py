from enum import Enum

import rsa

from src.pgp.consts.consts import AsymmetricEncryptionAlgorithm, SymmetricEncryptionAlgorithm, SigningAlgorithm, \
    KeyPairPrivateRingAttributes, UTF_8, PRIVATE_KEY_RING_SALT, PublicKeyPublicRingAttributes
from src.pgp.encryption.symmetric import SymmetricEncryptor
from src.pgp.key.key import SessionKey, PrivateKey, PublicKey, RSAPrivateKey, RSAPublicKey, KeyPair, CAST128SessionKey
from src.pgp.signature.hash import SHA1Hasher


def _private_ring_json_verify_all_atributes_exist(key_json: dict):
    for attribute in KeyPairPrivateRingAttributes:
        if attribute.value not in key_json:
            raise ValueError(f"{attribute} is missing from key_json")


def conclude_pem_algorithm(key_pem: str) -> AsymmetricEncryptionAlgorithm:
    if "RSA" in key_pem:
        return AsymmetricEncryptionAlgorithm.RSA
    else:
        raise ValueError("Invalid algorithm")


class KeySerializer:
    def __init__(self):
        self._symmetric_encryptor = SymmetricEncryptor()
        self._hasher = SHA1Hasher()

    def _validate_password(self, password: str, key_json: dict):
        hashed_password_with_salt = self._hasher.hash(message=f"{password}:{PRIVATE_KEY_RING_SALT}")
        if hashed_password_with_salt != bytes.fromhex(key_json[KeyPairPrivateRingAttributes.HASHED_PASSWORD_WITH_SALT.value]):
            raise ValueError("Invalid password")

    def _decrypt_private_key(self, key_json: dict, password: str) -> str:
        self._validate_password(password=password, key_json=key_json)
        hashed_password = self._hasher.hash(message=password)
        cast128_session_key = CAST128SessionKey(key=hashed_password[:16])
        return self._symmetric_encryptor.decrypt(
            ciphertext=bytes.fromhex(key_json[KeyPairPrivateRingAttributes.ENCRYPTED_PRIVATE_KEY.value]),
            session_key=cast128_session_key,
            algorithm=SymmetricEncryptionAlgorithm.CAST_128
        )

    def key_pair_json_deserialize(self, key_json: dict, password: str) -> KeyPair:

        _private_ring_json_verify_all_atributes_exist(key_json=key_json)
        private_key: str = self._decrypt_private_key(key_json=key_json, password=password)

        if key_json[KeyPairPrivateRingAttributes.ALGORITHM.value] == AsymmetricEncryptionAlgorithm.RSA.value:
            return KeyPair(
                public_key=RSAPublicKey(
                    rsa.PublicKey.load_pkcs1(bytes.fromhex(key_json[KeyPairPrivateRingAttributes.PUBLIC_KEY.value]))),
                private_key=RSAPrivateKey(
                    rsa.PrivateKey.load_pkcs1(private_key.encode(UTF_8))),
                algorithm=AsymmetricEncryptionAlgorithm.RSA
            )
        else:
            raise NotImplementedError()

    def public_key_json_deserialize(self, public_key_json: dict) -> PublicKey:
        if PublicKeyPublicRingAttributes.ALGORITHM.value not in public_key_json:
            raise ValueError("Algorithm is missing from key_json")
        if public_key_json[PublicKeyPublicRingAttributes.ALGORITHM.value] == AsymmetricEncryptionAlgorithm.RSA.value:
            return RSAPublicKey(
                rsa.PublicKey.load_pkcs1(bytes.fromhex(public_key_json[PublicKeyPublicRingAttributes.PUBLIC_KEY.value]))
            )
        else:
            raise NotImplementedError()

    def key_pair_json_serialize(self, key_pair: KeyPair, password: str, user_name: str, user_email: str):
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
                KeyPairPrivateRingAttributes.HASHED_PASSWORD_WITH_SALT.value: hashed_password_with_salt.hex(),
                KeyPairPrivateRingAttributes.ENCRYPTED_PRIVATE_KEY.value: encrypted_private_key.hex(),
                KeyPairPrivateRingAttributes.PUBLIC_KEY.value: public_key_bytes.hex(),
                KeyPairPrivateRingAttributes.ALGORITHM.value: AsymmetricEncryptionAlgorithm.RSA.value,
                KeyPairPrivateRingAttributes.USER_NAME.value: user_name,
                KeyPairPrivateRingAttributes.USER_EMAIL.value: user_email
            }
            return key_json
        else:
            raise NotImplementedError()

    def public_key_json_serialize(self, public_key: PublicKey) -> dict:
        if public_key.get_algorithm() == AsymmetricEncryptionAlgorithm.RSA:
            return {
                PublicKeyPublicRingAttributes.PUBLIC_KEY.value: public_key.get_key().save_pkcs1().hex(),
                PublicKeyPublicRingAttributes.ALGORITHM.value: AsymmetricEncryptionAlgorithm.RSA.value
            }
        else:
            raise NotImplementedError()

    def import_private_key_from_pem(self, private_key_pem_path: str) -> PrivateKey:
        with open(private_key_pem_path, 'r') as f:
            private_key_pem = f.read()
        algorithm = conclude_pem_algorithm(key_pem=private_key_pem)

        if algorithm == AsymmetricEncryptionAlgorithm.RSA:
            return RSAPrivateKey(rsa.PrivateKey.load_pkcs1(private_key_pem.encode(UTF_8)))
        else:
            raise NotImplementedError()

    def import_public_key_from_pem(self, public_key_pem_path: str) -> PublicKey:
        with open(public_key_pem_path, 'r') as f:
            public_key_pem = f.read()
        algorithm = conclude_pem_algorithm(key_pem=public_key_pem)

        if algorithm == AsymmetricEncryptionAlgorithm.RSA:
            return RSAPublicKey(rsa.PublicKey.load_pkcs1(public_key_pem.encode(UTF_8)))
        else:
            raise NotImplementedError()

    def export_private_key_to_pem(self, key_pair: KeyPair, private_key_pem_path: str):
        if key_pair.get_algorithm() == AsymmetricEncryptionAlgorithm.RSA:
            with open(private_key_pem_path, 'w') as f:
                f.write(key_pair.get_private_key().get_key().save_pkcs1().decode(UTF_8))
        else:
            raise NotImplementedError()

    def export_public_key_to_pem(self, key_pair: KeyPair, public_key_pem_path: str):
        if key_pair.get_algorithm() == AsymmetricEncryptionAlgorithm.RSA:
            with open(public_key_pem_path, 'w') as f:
                f.write(key_pair.get_public_key().get_key().save_pkcs1().decode(UTF_8))
        else:
            raise NotImplementedError()


def test_key_serializer():
    (public_key, private_key) = rsa.newkeys(1024)
    key_serializer = KeySerializer()
    print("Public key: " + str(public_key))
    print("Private key: " + str(private_key))
    key_pair = KeyPair(
        public_key=RSAPublicKey(public_key),
        private_key=RSAPrivateKey(private_key),
        algorithm=AsymmetricEncryptionAlgorithm.RSA
    )
    key_pair_json = key_serializer.key_pair_json_serialize(
        key_pair=key_pair,
        password="password",
        user_name="test",
        user_email="test"
    )
    print(key_pair_json)

    key_pair = key_serializer.key_pair_json_deserialize(key_json=key_pair_json, password="password")
    print("Public key: " + str(key_pair.get_public_key().get_key()))
    print("Private key: " + str(key_pair.get_private_key().get_key()))

    key_serializer.export_private_key_to_pem(key_pair=key_pair, private_key_pem_path="private_key.pem")
    key_serializer.export_public_key_to_pem(key_pair=key_pair, public_key_pem_path="public_key.pem")

    private_key = key_serializer.import_private_key_from_pem(private_key_pem_path="private_key.pem")
    public_key = key_serializer.import_public_key_from_pem(public_key_pem_path="public_key.pem")

    print("Public key: " + str(public_key.get_key()))
    print("Private key: " + str(private_key.get_key()))

    public_key_serialized = key_serializer.public_key_json_serialize(public_key=public_key)
    print(public_key_serialized)
    public_key_deserialized = key_serializer.public_key_json_deserialize(public_key_json=public_key_serialized)
    print("Public key: " + str(public_key_deserialized.get_key()))


if __name__ == "__main__":
    test_key_serializer()
