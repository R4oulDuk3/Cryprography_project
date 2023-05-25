"""
    1. Генерисање новог и брисање постојећег пара кључева

    ...Студенти треба да предложе и имплементирају
    структуре у којима се чувају кључеви (прстен јавних и приватних кључева)...
"""
import json
import os
from typing import List

from src.pgp.consts.consts import DATA_DIR, PUBLIC_KEY_RING_FILE, Algorithm, AlgorithmType, \
    PublicKeyRingElementAttributes, PublicKeyPublicRingAttributes
from src.pgp.key.generate.keypair import KeyPairGenerator
from src.pgp.key.key import PublicKey, KeyPair
from src.pgp.key.keyring.keyring_dto import PublicKeyringRowDTO
from src.pgp.key.keyring.keyring_serializer import PublicKeyRingSerializer
from src.pgp.util.util import validate_if_algorithm_matches_algorithm_type


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


def _get_public_key_ring_element_attribute_by_algorithm_type(algorithm_type: AlgorithmType):
    if algorithm_type == AlgorithmType.ASYMMETRIC_ENCRYPTION:
        return PublicKeyRingElementAttributes.ENCRYPTION_KEY
    elif algorithm_type == AlgorithmType.SIGNING:
        return PublicKeyRingElementAttributes.SIGNING_KEY
    else:
        raise Exception("Invalid algorithm type: " + algorithm_type.value)


class PublicKeyRing:

    def __init__(self, user_name: str):
        self._user_name = user_name
        self._serializer = PublicKeyRingSerializer()
        self._serialized_key_dictionary = _load_key_dictionary_json()

    """
        The user_name is the name of the user who owns the private key for this public key.
    """

    def add_public_key(self, public_key: PublicKey, user_email: str, algorithm_type: AlgorithmType):
        validate_if_algorithm_matches_algorithm_type(algorithm=public_key.get_algorithm(), algorithm_type=algorithm_type)
        public_key_ring_element = {
            PublicKeyRingElementAttributes.USER_NAME.value: self._user_name,
        }
        if user_email in self._serialized_key_dictionary:
            public_key_ring_element = self._serialized_key_dictionary[user_email]

        if public_key_ring_element[PublicKeyRingElementAttributes.USER_NAME.value] != self._user_name:
            raise Exception(f"A user already created keys for email: {user_email} with name: {self._user_name}")
        attribute = _get_public_key_ring_element_attribute_by_algorithm_type(algorithm_type)
        if attribute.value in public_key_ring_element:
            raise Exception(f"Public key for {algorithm_type.value} already exists for user email: " + user_email)

        public_key_json = self._serializer.public_key_json_serialize(public_key=public_key, user_name=self._user_name,
                                                                     user_email=user_email)
        public_key_ring_element[attribute.value] = public_key_json
        self._serialized_key_dictionary[user_email] = public_key_ring_element

    def _remove_element_if_empty(self, email: str):
        if self._serialized_key_dictionary[email].keys().__len__() == 0:
            del self._serialized_key_dictionary[email]

    def delete_public_key_by_user_email(self, user_email: str, algorithm_type: AlgorithmType):
        attribute = _get_public_key_ring_element_attribute_by_algorithm_type(algorithm_type)
        del self._serialized_key_dictionary[user_email][attribute.value]
        self._remove_element_if_empty(user_email)

    def delete_public_key_by_key_id(self, key_id: str):
        for user_email in self._serialized_key_dictionary:
            public_key_ring_element = self._serialized_key_dictionary[user_email]
            for attribute in public_key_ring_element:
                if attribute == PublicKeyRingElementAttributes.USER_NAME.value:
                    continue
                public_key_json = public_key_ring_element[attribute]
                if public_key_json[PublicKeyRingElementAttributes.KEY_ID.value] == key_id:
                    del public_key_ring_element[attribute]
                    self._remove_element_if_empty(user_email)
                    return

    def get_public_key_by_key_id(self, key_id: str):
        for user_email in self._serialized_key_dictionary:
            public_key_ring_element = self._serialized_key_dictionary[user_email]
            for attribute in public_key_ring_element:
                if attribute == PublicKeyRingElementAttributes.USER_NAME.value:
                    continue
                public_key_json = public_key_ring_element[attribute]
                if public_key_json[PublicKeyPublicRingAttributes.KEY_ID.value] == key_id:
                    return self._serializer.public_key_json_deserialize(public_key_json)
        raise Exception("No public key found for key id: " + key_id)

    def get_public_key_by_user_email(self, user_email: str, algorithm_type: AlgorithmType):
        attribute = _get_public_key_ring_element_attribute_by_algorithm_type(algorithm_type)
        public_key_ring_element = self._serialized_key_dictionary[user_email]
        public_key_json = public_key_ring_element[attribute.value]
        return self._serializer.public_key_json_deserialize(public_key_json)

    def get_signing_key_id_for_email(self, user_email):
        if user_email not in self._serialized_key_dictionary:
            raise Exception("No signing key found for user email: " + user_email)
        public_key_ring_element = self._serialized_key_dictionary[user_email]
        public_key_json = public_key_ring_element[PublicKeyRingElementAttributes.SIGNING_KEY.value]
        if public_key_json is None:
            raise Exception("No signing key found for user email: " + user_email)
        return public_key_json[PublicKeyPublicRingAttributes.KEY_ID.value]

    def get_encryption_key_id_for_email(self, user_email):
        if user_email not in self._serialized_key_dictionary:
            raise Exception("No encryption key found for user email: " + user_email)
        public_key_ring_element = self._serialized_key_dictionary[user_email]
        public_key_json = public_key_ring_element[PublicKeyRingElementAttributes.ENCRYPTION_KEY.value]
        if public_key_json is None:
            raise Exception("No encryption key found for user email: " + user_email)
        return public_key_json[PublicKeyPublicRingAttributes.KEY_ID.value]

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

    def get_all_public_keyring_rows(self) -> List[PublicKeyringRowDTO]:
        public_keyring_element_dtos = []
        for user_email in self._serialized_key_dictionary:
            public_key_ring_element = self._serialized_key_dictionary[user_email]
            for attribute in public_key_ring_element:
                if attribute == PublicKeyRingElementAttributes.USER_NAME.value:
                    continue
                public_key_json = public_key_ring_element[attribute]
                public_keyring_element_dtos.append(
                    PublicKeyringRowDTO(user_email=user_email,
                                        user_name=public_key_ring_element[PublicKeyRingElementAttributes.USER_NAME.value],
                                        key_id=public_key_json[PublicKeyPublicRingAttributes.KEY_ID.value],
                                        public_key=public_key_json[PublicKeyPublicRingAttributes.PUBLIC_KEY.value],
                                        algorithm_type=attribute,
                                        algorithm=public_key_json[PublicKeyPublicRingAttributes.ALGORITHM.value],
                                        ))

        return public_keyring_element_dtos

    def get_all_mails(self):
        return list(self._serialized_key_dictionary.keys())

    def get_mail_by_key_id(self, key_id: str):
        for user_email in self._serialized_key_dictionary:
            public_key_ring_element = self._serialized_key_dictionary[user_email]
            for attribute in public_key_ring_element:
                if attribute == PublicKeyRingElementAttributes.USER_NAME.value:
                    continue
                public_key_json = public_key_ring_element[attribute]
                if public_key_json[PublicKeyPublicRingAttributes.KEY_ID.value] == key_id:
                    return user_email
        raise Exception("No public key found for key id: " + key_id)



def test_public_key_ring():
    public_key_ring = PublicKeyRing(user_name="name")
    key_pair_generator = KeyPairGenerator()
    key_pair = key_pair_generator.generate_key_pair(Algorithm.RSA, 1024)
    public_key = key_pair.get_public_key()
    public_key_ring.add_public_key(public_key=public_key, user_email="email",
                                   algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION)
    public_key_ring.save()
    key_pair = key_pair_generator.generate_key_pair(Algorithm.RSA, 1024)
    public_key = key_pair.get_public_key()
    public_key_ring.add_public_key(public_key=public_key, user_email="email",
                                   algorithm_type=AlgorithmType.SIGNING)
    public_key_ring.save()
    print(public_key_ring.get_all_public_keyring_rows())
    print(public_key_ring.get_signing_key_id_for_email(user_email="email"))
    print(public_key_ring.get_encryption_key_id_for_email(user_email="email"))

    public_key_ring.delete_public_key_by_user_email(user_email="email",
                                                    algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION)
    public_key_ring.save()
    public_key_ring.delete_public_key_by_user_email(user_email="email", algorithm_type=AlgorithmType.SIGNING)
    public_key_ring.save()


if __name__ == '__main__':
    test_public_key_ring()
