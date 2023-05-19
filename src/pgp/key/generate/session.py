from abc import abstractmethod, ABC
from Crypto.Random import get_random_bytes
from src.pgp.consts.consts import Algorithm
from src.pgp.key.key import SessionKey, TripleDESSessionKey
from src.pgp.util.util import validate_if_algorithm_symmetric_encryption


class SessionKeyGenerator:

    def __init__(self):
        self._strategies = {
            Algorithm.TRIPLE_DES: TripleDESSessionKeyGeneratorStrategy(),
            Algorithm.CAST_128: CAST128SessionKeyGeneratorStrategy()
        }

    def generate_session_key(self, algorithm: Algorithm) -> SessionKey:
        validate_if_algorithm_symmetric_encryption(algorithm)
        return self._strategies[algorithm].generate_session_key()


class SessionKeyGeneratorStrategy(ABC):
    @abstractmethod
    def generate_session_key(self) -> SessionKey:
        pass


class TripleDESSessionKeyGeneratorStrategy(SessionKeyGeneratorStrategy):
    def generate_session_key(self) -> TripleDESSessionKey:
        return TripleDESSessionKey(get_random_bytes(24))


class CAST128SessionKeyGeneratorStrategy(SessionKeyGeneratorStrategy):
    def generate_session_key(self) -> TripleDESSessionKey:
        return TripleDESSessionKey(get_random_bytes(16))
