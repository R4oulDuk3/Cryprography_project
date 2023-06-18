from abc import ABC, abstractmethod
from Crypto.Hash import SHA1

from src.pgp.consts.consts import UTF_8


class Hasher(ABC):
    @abstractmethod
    def hash(self, message: str | bytes) -> bytes:
        pass


class SHA1Hasher(Hasher):
    def hash(self, message: str | bytes) -> bytes:
        if isinstance(message, str):
            message = message.encode(UTF_8)
        sha1_hash = SHA1.new(message)
        byte_hash = sha1_hash.digest()
        return byte_hash
