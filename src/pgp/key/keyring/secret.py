"""
    1. Генерисање новог и брисање постојећег пара кључева

    ...Студенти треба да предложе и имплементирају
    структуре у којима се чувају кључеви (прстен јавних и приватних кључева)...
"""
import json
import os
from typing import List

from src.pgp.consts.consts import DATA_DIR, SECRET_KEY_RING_FILE, UTF_8, Algorithm, PrivateRingElementAttributes, \
    AlgorithmType, KeyPairPrivateRingAttributes
from src.pgp.key.generate.keypair import KeyPairGenerator
from src.pgp.key.key import KeyPair
from src.pgp.key.keyring.keyring_dto import PrivateKeyringRowDTO
from src.pgp.key.keyring.keyring_serializer import SecretKeyRingSerializer
from src.pgp.util.util import validate_if_algorithm_matches_algorithm_type


def _get_public_key_ring_element_attribute_by_algorithm_type(algorithm_type: AlgorithmType):
    if algorithm_type == AlgorithmType.ASYMMETRIC_ENCRYPTION:
        return PrivateRingElementAttributes.ENCRYPTION_KEY_PAIR
    elif algorithm_type == AlgorithmType.SIGNING:
        return PrivateRingElementAttributes.SIGNING_KEY_PAIR
    else:
        raise Exception("Invalid algorithm type: " + algorithm_type.value)


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

    def add_key_pair(self, key_pair: KeyPair, password: str, user_email: str, algorithm_type: AlgorithmType):
        validate_if_algorithm_matches_algorithm_type(algorithm=key_pair.get_algorithm(), algorithm_type=algorithm_type)
        secret_key_ring_element = {}
        if user_email in self._serialized_key_pair_dictionary:
            secret_key_ring_element = self._serialized_key_pair_dictionary[user_email]

        attribute: PrivateRingElementAttributes = _get_public_key_ring_element_attribute_by_algorithm_type(
            algorithm_type=algorithm_type)
        if attribute.value in secret_key_ring_element:
            raise Exception(f"Key pair for {algorithm_type.value} already exists for user email: " + user_email)

        key_pair_json = self._serializer.key_pair_json_serialize(key_pair=key_pair, password=password,
                                                                 user_name=self._user_name,
                                                                 user_email=user_email)
        secret_key_ring_element[attribute.value] = key_pair_json

        self._serialized_key_pair_dictionary[user_email] = secret_key_ring_element

    def _remove_element_if_empty(self, email: str):
        if self._serialized_key_pair_dictionary[email].keys().__len__() == 0:
            del self._serialized_key_pair_dictionary[email]

    def delete_key_pair_by_user_email(self, user_email: str, password: str, algorithm_type: AlgorithmType):
        self.get_key_pair_by_user_email(user_mail=user_email, password=password,
                                        algorithm_type=algorithm_type)  # checks if password is correct
        attribute = _get_public_key_ring_element_attribute_by_algorithm_type(algorithm_type=algorithm_type).value
        del self._serialized_key_pair_dictionary[user_email][attribute]
        self._remove_element_if_empty(user_email)

    def get_key_pair_by_user_email(self, user_mail: str, password: str, algorithm_type: AlgorithmType) -> KeyPair:
        if user_mail not in self._serialized_key_pair_dictionary:
            raise Exception("Key pair for user email: " + user_mail + " does not exist")
        secret_key_ring_element = self._serialized_key_pair_dictionary[user_mail]
        attribute: PrivateRingElementAttributes = _get_public_key_ring_element_attribute_by_algorithm_type(
            algorithm_type=algorithm_type)
        if attribute.value not in secret_key_ring_element:
            raise Exception(f"Key pair for {algorithm_type.value} does not exist for user email: " + user_mail)
        key_pair_json = secret_key_ring_element[attribute.value]
        key_pair: KeyPair = self._serializer.key_pair_json_deserialize(key_json=key_pair_json, password=password)
        return key_pair

    def delete_key_pair_by_key_id(self, key_id: str):
        for user_email in self._serialized_key_pair_dictionary:
            public_key_ring_element = self._serialized_key_pair_dictionary[user_email]
            for attribute in public_key_ring_element:
                public_key_json = public_key_ring_element[attribute]
                if public_key_json[PrivateRingElementAttributes.KEY_ID.value] == key_id:
                    del public_key_ring_element[attribute]
                    self._remove_element_if_empty(user_email)
                    return
        raise Exception("Key pair with key id: " + key_id + " does not exist")

    def get_key_pair_by_key_id(self, key_id: str, password: str) -> KeyPair:
        for user_email in self._serialized_key_pair_dictionary:
            secret_key_ring_element = self._serialized_key_pair_dictionary[user_email]
            for attribute in secret_key_ring_element:
                key_pair_json = secret_key_ring_element[attribute]
                if key_pair_json[KeyPairPrivateRingAttributes.KEY_ID.value] == key_id:
                    return self._serializer.key_pair_json_deserialize(key_json=key_pair_json, password=password)
        raise Exception("Key pair with key id: " + key_id + " does not exist")

    def get_signing_key_id_for_email(self, email: str) -> str:
        if email not in self._serialized_key_pair_dictionary:
            raise Exception("Key pair for email: " + email + " does not exist")
        public_key_ring_element = self._serialized_key_pair_dictionary[email]
        if PrivateRingElementAttributes.SIGNING_KEY_PAIR.value not in public_key_ring_element:
            raise Exception("Signing key id does not exist for email: " + email)
        return public_key_ring_element[PrivateRingElementAttributes.SIGNING_KEY_PAIR.value][KeyPairPrivateRingAttributes.KEY_ID.value]

    def get_encryption_key_id_for_email(self, email: str) -> str:
        if email not in self._serialized_key_pair_dictionary:
            raise Exception("Key pair for email: " + email + " does not exist")
        public_key_ring_element = self._serialized_key_pair_dictionary[email]
        if PrivateRingElementAttributes.ENCRYPTION_KEY_PAIR.value not in public_key_ring_element:
            raise Exception("Encryption key id does not exist for email: " + email)
        return public_key_ring_element[PrivateRingElementAttributes.ENCRYPTION_KEY_PAIR.value][KeyPairPrivateRingAttributes.KEY_ID.value]



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

    def get_all_private_keyring_rows(self) -> List[PrivateKeyringRowDTO]:
        private_keyring_element_dtos = []
        for user_email in self._serialized_key_pair_dictionary:
            private_keyring_element = self._serialized_key_pair_dictionary[user_email]
            for attribute in private_keyring_element:
                key_pair_json = private_keyring_element[attribute]
                private_keyring_element_dtos.append(
                    PrivateKeyringRowDTO(
                        user_email=user_email,
                        user_name=key_pair_json[KeyPairPrivateRingAttributes.USER_NAME.value],
                        key_id=key_pair_json[KeyPairPrivateRingAttributes.KEY_ID.value],
                        algorithm_type=attribute,
                        algorithm=key_pair_json[KeyPairPrivateRingAttributes.ALGORITHM.value],
                        encrypted_private_key=key_pair_json[KeyPairPrivateRingAttributes.ENCRYPTED_PRIVATE_KEY.value],
                        hashed_password_with_salt=key_pair_json[KeyPairPrivateRingAttributes.HASHED_PASSWORD_WITH_SALT.value],
                        public_key=key_pair_json[KeyPairPrivateRingAttributes.PUBLIC_KEY.value],
                    ))
        return private_keyring_element_dtos

    def get_all_mails(self) -> List[str]:
        return list(self._serialized_key_pair_dictionary.keys())



def test_secret_key_ring():
    secret_key_ring = SecretKeyRing(user_name="user1")
    key_pair_generator = KeyPairGenerator()
    key_pair = key_pair_generator.generate_key_pair(
        algorithm=Algorithm.RSA, key_size=1024)
    secret_key_ring.add_key_pair(key_pair=key_pair, password="password", user_email="mail",
                                 algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION)
    secret_key_ring.save()

    key_pair = key_pair_generator.generate_key_pair(
        algorithm=Algorithm.RSA, key_size=1024)
    secret_key_ring.add_key_pair(key_pair=key_pair, password="password", user_email="mail",
                             algorithm_type=AlgorithmType.SIGNING)
    print(secret_key_ring.get_all_private_keyring_rows())
    print(key_pair.get_public_key().get_key())
    print(key_pair.get_private_key().get_key())
    print(secret_key_ring.get_signing_key_id_for_email(email="mail"))
    print(secret_key_ring.get_encryption_key_id_for_email(email="mail"))
    secret_key_ring.save()
    key_pair_fetched = secret_key_ring.get_key_pair_by_user_email(user_mail="mail", password="password",
                                                                  algorithm_type=AlgorithmType.SIGNING)
    print("key_pair_fetched " + str(key_pair_fetched.get_public_key().get_key()))
    key_id = secret_key_ring.get_signing_key_id_for_email(email="mail")
    print(key_id)
    key_pair_fetched2 = secret_key_ring.get_key_pair_by_key_id(key_id=key_id, password="password")
    print("key_pair_fetched " + str(key_pair_fetched2.get_public_key().get_key()))
    print(key_pair_fetched.get_public_key().get_key())
    print(key_pair_fetched.get_private_key().get_key())
    secret_key_ring.delete_key_pair_by_user_email(user_email="mail", password="password",
                                                  algorithm_type=AlgorithmType.SIGNING)
    secret_key_ring.save()
    key_pair_fetched = secret_key_ring.get_key_pair_by_user_email(user_mail="mail", password="password",
                                                                  algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION)


if __name__ == '__main__':
    test_secret_key_ring()
