from src.pgp.key.generate.keypair import KeyPairGenerator, KEY_SIZES, KeyPairGeneratorType
from src.pgp.key.keyring.private import PrivateKeyRing
from src.pgp.key.keyring.public import PublicKeyRing


class KeyManager:
    def __init__(self, user_id: str):
        self._user_id = user_id
        self._private_key_ring = PrivateKeyRing(user_id)
        self._public_key_ring = PublicKeyRing(user_id)
        self._key_pair_generator = KeyPairGenerator(KEY_SIZES)

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
        key_pair = self._key_pair_generator.generate_key_pair(algorithm=algorithm, key_size=key_size)
        self._private_key_ring.add_private_key(key_pair.get_private_key(), password)
        self._public_key_ring.add_public_key(key_pair.get_public_key(), email, name)
        self._public_key_ring.save()
        self._private_key_ring.save()

    """
        ...Сви генерисани и увезени кључеви
        треба да буду јасно видљиви на корисничком интерфејсу...
    """

    def get_public_key(self, recipient_email: str):
        return self._public_key_ring.get_public_key(recipient_email)

    def get_private_key(self, private_key_id: str, password: str):
        return self._private_key_ring.get_private_key(private_key_id, password)

    def get_public_keyring_all_rows(self):
        return self._public_key_ring.get_all_rows()

    def get_private_keyring_all_rows(self):
        return self._private_key_ring.get_all_rows()
