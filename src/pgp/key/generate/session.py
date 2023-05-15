from abc import abstractmethod, ABC

from src.pgp.consts.consts import SessionKeyGeneratorType
from src.pgp.key.key import Key


class SessionKeyGenerator:

    def __init__(self):
        self._strategies = {
            SessionKeyGeneratorType.TRIPLE_DES: TripleDESSessionKeyGeneratorStrategy(),
            SessionKeyGeneratorType.AES_128: AES128SessionKeyGeneratorStrategy()
        }

    def generate_session_key(self, algorithm: SessionKeyGeneratorType) -> Key:
        return self._strategies[algorithm].generate_session_key()


class SessionKeyGeneratorStrategy(ABC):
    @abstractmethod
    def generate_session_key(self) -> Key:
        pass


class TripleDESSessionKeyGeneratorStrategy(SessionKeyGeneratorStrategy):
    def generate_session_key(self) -> Key:
        pass


class AES128SessionKeyGeneratorStrategy(SessionKeyGeneratorStrategy):
    def generate_session_key(self) -> Key:
        pass
