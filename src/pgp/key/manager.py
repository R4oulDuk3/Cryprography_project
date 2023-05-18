from src.pgp.consts.consts import KEY_SIZES, KeyPairGeneratorType
from src.pgp.key.generate.keypair import KeyPairGenerator
from src.pgp.key.key import KeyPair
from src.pgp.key.keyring.secret import SecretKeyRing
from src.pgp.key.keyring.public import PublicKeyRing


class KeyManager:
    def __init__(self, user_name: str):
        self._user_name = user_name
        self._private_key_ring = SecretKeyRing(user_name)
        self._public_key_ring = PublicKeyRing(user_name)
        self._key_pair_generator = KeyPairGenerator()

    def generate_key_available_algorithms(self):
        return self._key_pair_generator.get_available_algorithms()

    def generate_key_available_key_sizes(self):
        return self._key_pair_generator.get_available_key_sizes()

    """
        1. Генерисање новог и брисање постојећег пара кључева
        ...При генерисању новог пара кључева, од корисника тражити унос имена, мејла, алгоритма за
        асиметричне кључеве и величине кључа...Након уноса свих потребних података, од корисника
        тражити унос лозинке под којом ће се чувати приватни кључ...
    """

    def generate_key_pair(self, algorithm: KeyPairGeneratorType, key_size: int, email: str, name: str, password: str):

        key_pair: KeyPair = self._key_pair_generator.generate_key_pair(algorithm=algorithm, key_size=key_size)
        self._private_key_ring.add_key_pair(key_pair=key_pair, password=password)
        self._public_key_ring.add_public_key(key_pair.get_public_key())
        self._public_key_ring.save()
        self._private_key_ring.save()

    """
        ...Сви генерисани и увезени кључеви
        треба да буду јасно видљиви на корисничком интерфејсу...
    """

    def get_public_key_by_key_id(self, key_id: bytes):
        return self._public_key_ring.get_public_key_by_key_id(key_id=key_id)

    def get_private_key_by_key_id(self, key_id: bytes, password: str):
        return self._private_key_ring.get_key_pair_by_key_id(key_id=key_id, password=password)

    def get_public_keyring_dictionary(self):
        return self._public_key_ring.get_key_pair_dictionary()

    def get_private_keyring_dictionary(self):
        return self._private_key_ring.get_key_pair_dictionary()
