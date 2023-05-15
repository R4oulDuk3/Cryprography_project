from abc import ABC, abstractmethod


class Hasher(ABC):
    @abstractmethod
    def hash(self, message: str) -> str:
        pass


class SHA1Hasher(Hasher):
    def hash(self, message: str) -> str:
        pass
