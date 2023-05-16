from abc import ABC, abstractmethod
from Crypto.Hash import SHA1


class Hasher(ABC):
    @abstractmethod
    def hash(self, message: str) -> str:
        pass


class SHA1Hasher(Hasher):
    def hash(self, message: str) -> str:
        byte_message = message.encode('utf-8')
        sha1_hash = SHA1.new(byte_message)
        byte_hash = sha1_hash.digest()
        return byte_hash.hex()