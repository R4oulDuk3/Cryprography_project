from abc import abstractmethod, ABC
from Crypto.Random import get_random_bytes
from src.pgp.consts.consts import SessionKeyGeneratorAlgorithm
from src.pgp.key.key import SessionKey, TripleDESSessionKey


class SessionKeyGenerator:

    def __init__(self):
        self._strategies = {
            SessionKeyGeneratorAlgorithm.TRIPLE_DES: TripleDESSessionKeyGeneratorStrategy(),
            SessionKeyGeneratorAlgorithm.AES_128: AES128SessionKeyGeneratorStrategy()
        }

    def generate_session_key(self, algorithm: SessionKeyGeneratorAlgorithm) -> SessionKey:
        return self._strategies[algorithm].generate_session_key()


class SessionKeyGeneratorStrategy(ABC):
    @abstractmethod
    def generate_session_key(self) -> SessionKey:
        pass


class TripleDESSessionKeyGeneratorStrategy(SessionKeyGeneratorStrategy):
    def generate_session_key(self) -> SessionKey:
        return TripleDESSessionKey(get_random_bytes(24))


class AES128SessionKeyGeneratorStrategy(SessionKeyGeneratorStrategy):
    def generate_session_key(self) -> SessionKey:
        pass
