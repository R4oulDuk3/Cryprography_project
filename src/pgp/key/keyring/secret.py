"""
    1. Генерисање новог и брисање постојећег пара кључева

    ...Студенти треба да предложе и имплементирају
    структуре у којима се чувају кључеви (прстен јавних и приватних кључева)...
"""
import json
import os

from src.pgp.consts.consts import DATA_DIR, SECRET_KEY_RING_FILE, UTF_8, Algorithm, KeyPairPrivateRingAttributes
from src.pgp.key.generate.keypair import KeyPairGenerator
from src.pgp.key.key import KeyPair
from src.pgp.key.keyring.keyring_serializer import SecretKeyRingSerializer


class SecretKeyRing:

    def __init__(self, user_name: str):
        self._user_name = user_name
        self._serializer = SecretKeyRingSerializer()
        self._serialized_key_pair_dictionary = self._load_key_pair_dictionary_json()

    def form_key_pair_dictionary_path(self):
        os.makedirs(f"./{DATA_DIR}/{self._user_name}/", exist_ok=True)
        return f"./{DATA_DIR}/{self._user_name}/{SECRET_KEY_RING_FILE}"

    def _load_key_pair_dictionary_json(self) -> dict:
        path = self.form_key_pair_dictionary_path()
        try:
            with open(path, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            return {}

    def add_key_pair(self, key_pair: KeyPair, password: str, user_email: str):

        key_pair_json = self._serializer.key_pair_json_serialize(key_pair=key_pair, password=password,
                                                                 user_name=self._user_name,
                                                                 user_email=user_email)
        self._serialized_key_pair_dictionary[user_email] = key_pair_json

    def delete_key_pair_by_user_email(self, user_email: str, password: str):
        self.get_key_pair_by_user_email(user_mail=user_email, password=password)  # checks if password is correct
        self._serialized_key_pair_dictionary.pop(user_email)

    def get_key_pair_by_user_email(self, user_mail: str, password: str) -> KeyPair:

        key_pair_json = self._serialized_key_pair_dictionary[user_mail]
        key_pair: KeyPair = self._serializer.key_pair_json_deserialize(key_json=key_pair_json, password=password)
        return key_pair

    """
        Увоз и извоз јавног или приватног кључа у .pem формату
    """

    def save(self):
        path = self.form_key_pair_dictionary_path()
        with open(path, 'w') as file:
            json.dump(self._serialized_key_pair_dictionary, file, indent=4)

    """
        ...Сви генерисани и увезени кључеви
        треба да буду јасно видљиви на корисничком интерфејсу...
    """

    def get_key_pair_dictionary(self):
        return self._serialized_key_pair_dictionary


def test_secret_key_ring():
    secret_key_ring = SecretKeyRing(user_name="user1")
    key_pair_generator = KeyPairGenerator()
    key_pair: KeyPair = key_pair_generator.generate_key_pair(Algorithm.RSA, 1024)
    secret_key_ring.add_key_pair(key_pair=key_pair, password="password", user_email="email")
    secret_key_ring.save()
    key_pair_dictionary = secret_key_ring.get_key_pair_dictionary()
    print(key_pair_dictionary)
    key_pair = secret_key_ring.get_key_pair_by_user_email(
        user_mail="email", password="password")
    print(key_pair.get_public_key().get_key().save_pkcs1())
    secret_key_ring.delete_key_pair_by_user_email(user_email="email", password="password")
    secret_key_ring.save()
    key_pair_dictionary = secret_key_ring.get_key_pair_dictionary()
    print(key_pair_dictionary)


if __name__ == '__main__':
    test_secret_key_ring()
