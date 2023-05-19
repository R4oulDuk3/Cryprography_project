"""
    1. Генерисање новог и брисање постојећег пара кључева

    ...Студенти треба да предложе и имплементирају
    структуре у којима се чувају кључеви (прстен јавних и приватних кључева)...
"""
import json

from src.pgp.consts.consts import DATA_DIR, PUBLIC_KEY_RING_FILE, Algorithm, PublicKeyPublicRingAttributes
from src.pgp.key.generate.keypair import KeyPairGenerator
from src.pgp.key.key import Key, PublicKey, KeyPair
from src.pgp.key.keyring.keyring_serializer import PublicKeyRingSerializer
import os


def form_key_dictionary_path():
    os.makedirs(f"./{DATA_DIR}/", exist_ok=True)
    return f"./{DATA_DIR}/{PUBLIC_KEY_RING_FILE}"


def _load_key_dictionary_json() -> dict:
    path = form_key_dictionary_path()
    try:
        with open(path, 'r') as file:
            return json.load(file)
    except Exception as e:
        print("Error loading key dictionary json: ", str(e))
        return {}


class PublicKeyRing:

    def __init__(self):
        self._serializer = PublicKeyRingSerializer()
        self._serialized_key_dictionary = _load_key_dictionary_json()

    """
        The user_name is the name of the user who owns the private key for this public key.
    """

    def add_public_key(self, public_key: PublicKey, user_email: str, user_name: str):
        if user_email in self._serialized_key_dictionary:
            raise Exception("Public key with email: " + user_email + " already exists in the key ring")
        public_key_json = self._serializer.public_key_json_serialize(public_key=public_key, user_name=user_name,
                                                                     user_email=user_email)
        self._serialized_key_dictionary[user_email] = public_key_json

    def delete_public_key_by_user_email(self, user_email: str):
        del self._serialized_key_dictionary[user_email]

    def get_public_key_by_user_email(self, user_email: str):
        if user_email not in self._serialized_key_dictionary:
            raise Exception("No public key found for user email: " + user_email)
        return self._serializer.public_key_json_deserialize(self._serialized_key_dictionary[user_email])

    """
        Увоз и извоз јавног или приватног кључа у .pem формату
    """

    def save(self):
        file_path = form_key_dictionary_path()
        with open(file_path, 'w') as file:
            json.dump(self._serialized_key_dictionary, file, indent=4)

    """
        ...Сви генерисани и увезени кључеви
        треба да буду јасно видљиви на корисничком интерфејсу...
    """

    def get_key_pair_dictionary(self):
        return self._serialized_key_dictionary


def test_public_key_ring():
    public_key_ring = PublicKeyRing()
    public_key_ring.save()
    key_pair_generator = KeyPairGenerator()
    key_pair: KeyPair = key_pair_generator.generate_key_pair(Algorithm.RSA, 1024)
    print(key_pair.get_public_key().get_key())
    public_key_ring.add_public_key(public_key=key_pair.get_public_key(), user_email="user_email", user_name="user_name")
    print(public_key_ring.get_key_pair_dictionary())
    public_key_ring.save()

    public_key = public_key_ring.get_public_key_by_user_email(user_email="user_email")
    print(public_key.get_key())
    public_key_ring.delete_public_key_by_user_email(user_email="user_email")
    print(public_key_ring.get_key_pair_dictionary())


if __name__ == '__main__':
    test_public_key_ring()
