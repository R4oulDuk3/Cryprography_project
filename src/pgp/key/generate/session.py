from abc import abstractmethod, ABC
from Crypto.Random import get_random_bytes
from src.pgp.consts.consts import SymmetricEncryptionAlgorithm
from src.pgp.key.key import SessionKey, TripleDESSessionKey


class SessionKeyGenerator:

    def __init__(self):
        self._strategies = {
            SymmetricEncryptionAlgorithm.TRIPLE_DES: TripleDESSessionKeyGeneratorStrategy(),
            SymmetricEncryptionAlgorithm.CAST_128: CAST128SessionKeyGeneratorStrategy()
        }

    def generate_session_key(self, algorithm: SymmetricEncryptionAlgorithm) -> SessionKey:
        return self._strategies[algorithm].generate_session_key()


class SessionKeyGeneratorStrategy(ABC):
    @abstractmethod
    def generate_session_key(self) -> SessionKey:
        pass


class TripleDESSessionKeyGeneratorStrategy(SessionKeyGeneratorStrategy):
    def generate_session_key(self) -> TripleDESSessionKey:
        return TripleDESSessionKey(get_random_bytes(24))


class CAST128SessionKeyGeneratorStrategy(SessionKeyGeneratorStrategy):
    def generate_session_key(self) -> SessionKey:
        return TripleDESSessionKey(get_random_bytes(16))
