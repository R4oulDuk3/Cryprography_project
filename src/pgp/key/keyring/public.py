"""
    1. Генерисање новог и брисање постојећег пара кључева

    ...Студенти треба да предложе и имплементирају
    структуре у којима се чувају кључеви (прстен јавних и приватних кључева)...
"""
import json

from src.pgp.consts.consts import DATA_DIR, PUBLIC_KEY_RING_FILE, KeyPairGeneratorType
from src.pgp.key.generate.keypair import KeyPairGenerator
from src.pgp.key.key import Key, PublicKey, KeyPair
from src.pgp.key.keyring.key_id import make_key_id
from src.pgp.key.keyring.serializer import KeySerializer
import os


class PublicKeyRing:
    """
        The user_name is the name of the user who owns the keyring.
    """

    def __init__(self, user_name: str):
        self._user_name = user_name
        self._serializer = KeySerializer()
        self._serialized_key_dictionary = self._load_key_dictionary_json()

    def form_key_dictionary_path(self):
        os.makedirs(f"./{DATA_DIR}/{self._user_name}/", exist_ok=True)
        return f"./{DATA_DIR}/{self._user_name}/{PUBLIC_KEY_RING_FILE}"

    def _load_key_dictionary_json(self) -> dict:
        path = self.form_key_dictionary_path()
        try:
            with open(path, 'r') as file:
                return json.load(file)
        except Exception as e:
            print("Error loading key dictionary json: ", str(e))
            return {}

    """
        The user_name is the name of the user who owns the private key for this public key.
    """

    def add_public_key(self, public_key: PublicKey):
        public_key_json = self._serializer.public_key_json_serialize(public_key=public_key)
        self._serialized_key_dictionary[make_key_id(public_key=public_key)] = public_key_json

    def delete_public_key(self, key_id: str):
        del self._serialized_key_dictionary[key_id]

    def get_public_key_by_key_id(self, key_id: str):
        public_key_json = self._serialized_key_dictionary[key_id]
        return self._serializer.public_key_json_deserialize(public_key_json=public_key_json)

    """
        Увоз и извоз јавног или приватног кључа у .pem формату
    """

    def save(self):
        file_path = self.form_key_dictionary_path()
        with open(file_path, 'w') as file:
            json.dump(self._serialized_key_dictionary, file, indent=4)

    """
        ...Сви генерисани и увезени кључеви
        треба да буду јасно видљиви на корисничком интерфејсу...
    """

    def get_key_pair_dictionary(self):
        return self._serialized_key_dictionary


def test_public_key_ring():
    public_key_ring = PublicKeyRing(user_name="user")
    public_key_ring.save()
    key_pair_generator = KeyPairGenerator()
    key_pair: KeyPair = key_pair_generator.generate_key_pair(KeyPairGeneratorType.RSA, 1024)
    print(key_pair.get_public_key().get_key())
    public_key_ring.add_public_key(public_key=key_pair.get_public_key())
    print(public_key_ring.get_key_pair_dictionary())
    public_key_ring.save()

    public_key = public_key_ring.get_public_key_by_key_id(key_id=make_key_id(public_key=key_pair.get_public_key()))
    print(public_key.get_key())
    public_key_ring.delete_public_key(key_id=make_key_id(public_key=key_pair.get_public_key()))
    print(public_key_ring.get_key_pair_dictionary())


if __name__ == '__main__':
    test_public_key_ring()
