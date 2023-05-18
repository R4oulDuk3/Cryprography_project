import rsa

from src.pgp.consts.consts import AsymmetricEncryptionAlgorithm, KEY_ID_LENGTH, UTF_8
from src.pgp.key.key import RSAPublicKey, PublicKey


def make_key_id(public_key: PublicKey) -> str:
    if public_key.get_algorithm() == AsymmetricEncryptionAlgorithm.RSA:
        rsa_public_key: rsa.PublicKey = public_key.get_key()
        key_id = rsa_public_key.save_pkcs1()[-KEY_ID_LENGTH:]
        return key_id.hex()
    else:
        raise NotImplementedError()


def test_make_key_id():
    (public_key, private_key) = rsa.newkeys(1024)
    public_key = RSAPublicKey(public_key)
    key_id = make_key_id(public_key)
    print("Key id: " + str(key_id))


if __name__ == '__main__':
    test_make_key_id()
