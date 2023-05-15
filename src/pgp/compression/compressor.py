from abc import ABC, abstractmethod


class Compressor(ABC):
    @abstractmethod
    def compress(self, data):
        raise NotImplementedError()

    @abstractmethod
    def decompress(self, data):
        raise NotImplementedError()


class ZIPCompressor(Compressor):
    def compress(self, data):
        pass

    def decompress(self, data):
        pass
