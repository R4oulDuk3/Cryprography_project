from abc import ABC, abstractmethod
from enum import Enum

from src.pgp.consts.consts import KeyType


class Key:

    def __init__(self, key: str, key_type: KeyType, key_size: int, algorithm: str):
        self._key = key
        self._key_type = key_type
        self._key_size = key_size
        self._algorithm = algorithm

    def get_key(self):
        return self._key


class PrivateKey(Key):

    def __init__(self, key: str, key_size: int, algorithm: str):
        super().__init__(key, KeyType.PRIVATE, key_size, algorithm)


class PublicKey(Key):

    def __init__(self, key: str, key_size: int, algorithm: str):
        super().__init__(key, KeyType.PUBLIC, key_size, algorithm)


class SessionKey(Key):
    def __init__(self, key: str, key_size: int, algorithm: str):
        super().__init__(key, KeyType.SESSION, key_size, algorithm)


class KeyPair:

    def __init__(self, public_key: Key, private_key: Key):
        self._public_key = public_key
        self._private_key = private_key

    def get_public_key(self):
        return self._public_key

    def get_private_key(self):
        return self._private_key
