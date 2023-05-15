from abc import ABC, abstractmethod


class Convertor(ABC):
    @abstractmethod
    def encode(self, data):
        raise NotImplementedError()

    @abstractmethod
    def decode(self, data):
        raise NotImplementedError()


class Radix64Convertor(Convertor):

    def encode(self, data):
        pass

    def decode(self, data):
        pass
