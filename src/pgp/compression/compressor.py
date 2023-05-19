from abc import ABC, abstractmethod
import zlib


class Compressor(ABC):
    @abstractmethod
    def compress(self, data: bytes):
        raise NotImplementedError()

    @abstractmethod
    def decompress(self, data: bytes):
        raise NotImplementedError()


class ZIPCompressor(Compressor):
    def compress(self, data: bytes):
        return zlib.compress(data)

    def decompress(self, data: bytes):
        return zlib.decompress(data)
