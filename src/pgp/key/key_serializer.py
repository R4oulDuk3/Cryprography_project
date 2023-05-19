import rsa

from src.pgp.consts.consts import UTF_8, Algorithm
from src.pgp.key.generate.keypair import KeyPairGenerator
from src.pgp.key.key import KeyPair, RSAPublicKey, PrivateKey, RSAPrivateKey, PublicKey, SessionKey


def conclude_pem_algorithm(key_pem: str) -> Algorithm:
    if "RSA" in key_pem:
        return Algorithm.RSA
    else:
        raise ValueError("Invalid algorithm")


class KeySerializer:

    def import_private_key_from_pem(self, private_key_pem_path: str) -> PrivateKey:
        with open(private_key_pem_path, 'r') as f:
            private_key_pem = f.read()
        algorithm = conclude_pem_algorithm(key_pem=private_key_pem)

        if algorithm == Algorithm.RSA:
            return RSAPrivateKey(rsa.PrivateKey.load_pkcs1(private_key_pem.encode(UTF_8)))
        else:
            raise NotImplementedError()

    def import_public_key_from_pem(self, public_key_pem_path: str) -> PublicKey:
        with open(public_key_pem_path, 'r') as f:
            public_key_pem = f.read()
        algorithm = conclude_pem_algorithm(key_pem=public_key_pem)

        if algorithm == Algorithm.RSA:
            return RSAPublicKey(rsa.PublicKey.load_pkcs1(public_key_pem.encode(UTF_8)))
        else:
            raise NotImplementedError()

    def export_private_key_to_pem(self, key_pair: KeyPair, private_key_pem_path: str):
        if key_pair.get_algorithm() == Algorithm.RSA:
            with open(private_key_pem_path, 'w') as f:
                f.write(key_pair.get_private_key().get_key().save_pkcs1().decode(UTF_8))
        else:
            raise NotImplementedError()

    def export_public_key_to_pem(self, key_pair: KeyPair, public_key_pem_path: str):
        if key_pair.get_algorithm() == Algorithm.RSA:
            with open(public_key_pem_path, 'w') as f:
                f.write(key_pair.get_public_key().get_key().save_pkcs1().decode(UTF_8))
        else:
            raise NotImplementedError()

    def public_key_to_bytes(self, key: PublicKey) -> bytes:
        if isinstance(key, RSAPublicKey):
            return key.get_key().save_pkcs1()
        else:
            raise NotImplementedError()

    def private_key_to_bytes(self, key: PrivateKey) -> bytes:
        if isinstance(key, RSAPrivateKey):
            return key.get_key().save_pkcs1()
        else:
            raise NotImplementedError()

    def session_key_to_bytes(self, key: SessionKey) -> bytes:
        if key.get_algorithm() == Algorithm.CAST_128:
            return key.get_key()
        elif key.get_algorithm() == Algorithm.TRIPLE_DES:
            return key.get_key()
        else:
            raise NotImplementedError()

    def bytes_to_public_key(self, key_bytes: bytes, algorithm: Algorithm) -> PublicKey:
        if algorithm == Algorithm.RSA:
            return RSAPublicKey(rsa.PublicKey.load_pkcs1(key_bytes))
        else:
            raise NotImplementedError()

    def bytes_to_private_key(self, key_bytes: bytes, algorithm: Algorithm) -> PrivateKey:
        if algorithm == Algorithm.RSA:
            return RSAPrivateKey(rsa.PrivateKey.load_pkcs1(key_bytes))
        else:
            raise NotImplementedError()

    def bytes_to_session_key(self, key_bytes: bytes, algorithm: Algorithm) -> SessionKey:
        if algorithm == Algorithm.CAST_128.value:
            return SessionKey(algorithm=Algorithm.CAST_128, key=key_bytes)
        elif algorithm == Algorithm.TRIPLE_DES.value:
            return SessionKey(algorithm=Algorithm.TRIPLE_DES, key=key_bytes)
        else:
            raise NotImplementedError()


def test_key_serializer():
    key_serializer = KeySerializer()
    key_pair = KeyPairGenerator().generate_key_pair(algorithm=Algorithm.RSA, key_size=2048)
    key_serializer.export_private_key_to_pem(key_pair=key_pair, private_key_pem_path="private_key.pem")
    key_serializer.export_public_key_to_pem(key_pair=key_pair, public_key_pem_path="public_key.pem")
    private_key = key_serializer.import_private_key_from_pem(private_key_pem_path="private_key.pem")
    public_key = key_serializer.import_public_key_from_pem(public_key_pem_path="public_key.pem")
    assert private_key.get_key().save_pkcs1() == key_pair.get_private_key().get_key().save_pkcs1()
    assert public_key.get_key().save_pkcs1() == key_pair.get_public_key().get_key().save_pkcs1()
    print("KeySerializer test passed")


if __name__ == "__main__":
    test_key_serializer()
