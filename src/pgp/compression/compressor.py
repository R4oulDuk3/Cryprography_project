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


def test_zip_compression():
    compressor = ZIPCompressor()
    data = b'Hello World'
    compressed = compressor.compress(data)
    decompressed = compressor.decompress(compressed)
    print(f"Compressed: {compressed}, decompressed: {decompressed}")
    assert data == decompressed


if __name__ == '__main__':
    test_zip_compression()
