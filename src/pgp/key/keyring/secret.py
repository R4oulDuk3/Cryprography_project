"""
    1. Генерисање новог и брисање постојећег пара кључева

    ...Студенти треба да предложе и имплементирају
    структуре у којима се чувају кључеви (прстен јавних и приватних кључева)...
"""
import json

from src.pgp.consts.consts import DATA_DIR, SECRET_KEY_RING_FILE
from src.pgp.key.key import KeyPair
from src.pgp.key.keyring.serializer import KeySerializer


class SecretKeyRing:

    def __init__(self, user_name: str):
        self._user_name = user_name
        self._serializer = KeySerializer()
        self._serialized_key_pair_dictionary = self._load_key_pair_dictionary_json()

    def form_key_id(self, user_email: str):
        return f"{self._user_name}:{user_email}"

    def form_key_pair_dictionary_path(self):
        return f"/{DATA_DIR}/{self._user_name}/{SECRET_KEY_RING_FILE}"

    def _load_key_pair_dictionary_json(self) -> dict:
        path = self.form_key_pair_dictionary_path()
        try:
            with open(path, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            return {}

    def add_key_pair(self, key_pair: KeyPair, password: str, user_email: str):
        self._serializer.key_pair_json_serialize(key_pair=key_pair, password=password, user_name=self._user_name,
                                                 user_email=user_email)
        self._serialized_key_pair_dictionary[self.form_key_id(user_email=user_email)] = key_pair

    def delete_private_key(self, user_email: str):
        self._serialized_key_pair_dictionary.pop(self.form_key_id(user_email=user_email))

    def get_key_pair_by_user_id(self, user_email: str, password: str) -> KeyPair:
        key_pair_json = self._serialized_key_pair_dictionary[self.form_key_id(user_email=user_email)]
        key_pair: KeyPair = self._serializer.key_pair_json_deserialize(key_json=key_pair_json, password=password)
        return key_pair

    """
        Увоз и извоз јавног или приватног кључа у .pem формату
    """

    def save(self):
        path = self.form_key_pair_dictionary_path()
        with open(path, 'w') as file:
            json.dump(self._serialized_key_pair_dictionary, file)

    """
        ...Сви генерисани и увезени кључеви
        треба да буду јасно видљиви на корисничком интерфејсу...
    """

    def get_key_pair_dictionary(self):
        return self._serialized_key_pair_dictionary
