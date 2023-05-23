from abc import ABC, abstractmethod
import base64


class Convertor(ABC):
    @abstractmethod
    def encode(self, data: str | bytes):
        raise NotImplementedError()

    @abstractmethod
    def decode(self, data: str | bytes):
        raise NotImplementedError()


class Radix64Convertor(Convertor):
    def encode(self, data: str | bytes):
        if isinstance(data, str):
            data = data.encode('utf-8')

        encoded_data = base64.b64encode(data)
        return encoded_data.decode('utf-8')

    def decode(self, data: str | bytes):
        decoded_data = base64.b64decode(data)
        return decoded_data


if __name__ == "__main__":
    convertor = Radix64Convertor()
    string_data = 'My string example.'
    encoded_data = convertor.encode(string_data)
    decoded_data = convertor.decode(encoded_data)
    print("============================================")
    print("\t" * 3 + "Radix64 - string")
    print("--------------------------------------------")
    print(f"Original data: {string_data}")
    print(f"Enciphered data: {encoded_data}")
    print(f"Decoded data: {decoded_data.decode('utf-8')}")
    print("============================================")

    byte_data = b'My binary data example.'
    encoded_bdata = convertor.encode(byte_data)
    decoded_bdata = convertor.decode(encoded_bdata)
    print("============================================")
    print("\t" * 3 + "Radix64 - string")
    print("--------------------------------------------")
    print(f"Original data: {byte_data}")
    print(f"Enciphered data: {encoded_bdata}")
    print(f"Decoded data: {decoded_bdata}")
    print("============================================")
