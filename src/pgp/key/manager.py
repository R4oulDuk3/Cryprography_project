from src.pgp.consts.consts import Algorithm
from src.pgp.key.generate.keypair import KeyPairGenerator
from src.pgp.key.key import KeyPair, PublicKey, PrivateKey
from src.pgp.key.key_serializer import KeySerializer
from src.pgp.key.keyring.public import PublicKeyRing
from src.pgp.key.keyring.secret import SecretKeyRing


class KeyManager:
    def __init__(self, user_name: str):
        self._user_name = user_name
        self._private_key_ring = SecretKeyRing(user_name)
        self._public_key_ring = PublicKeyRing()
        self._key_pair_generator = KeyPairGenerator()
        self._key_serializer = KeySerializer()

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

    def generate_key_pair(self, algorithm: Algorithm, key_size: int, email: str, password: str):
        key_pair: KeyPair = self._key_pair_generator.generate_key_pair(algorithm=algorithm, key_size=key_size)
        self._public_key_ring.add_public_key(public_key=key_pair.get_public_key(), user_email=email,
                                             user_name=self._user_name)
        self._private_key_ring.add_key_pair(key_pair=key_pair, password=password, user_email=email)
        self._public_key_ring.save()
        self._private_key_ring.save()

    """
        ...Сви генерисани и увезени кључеви
        треба да буду јасно видљиви на корисничком интерфејсу...
    """

    def import_key_pair_from_pem(self, public_key_pem_path: str, private_key_pem_path: str, email: str, password: str):
        private_key: PrivateKey = self._key_serializer.import_private_key_from_pem(
            private_key_pem_path=private_key_pem_path)
        public_key: PublicKey = self._key_serializer.import_public_key_from_pem(public_key_pem_path=public_key_pem_path)
        key_pair: KeyPair = KeyPair(public_key=public_key, private_key=private_key,
                                    algorithm=private_key.get_algorithm())

        self._public_key_ring.add_public_key(public_key=key_pair.get_public_key(), user_email=email,
                                             user_name=self._user_name)
        self._private_key_ring.add_key_pair(key_pair=key_pair, password=password, user_email=email)
        self._public_key_ring.save()
        self._private_key_ring.save()

    def export_key_pair_to_pem_by_user_email(self, email: str, password: str, public_key_pem_path: str,
                                             private_key_pem_path: str):
        key_pair: KeyPair = self._private_key_ring.get_key_pair_by_user_email(user_mail=email, password=password)
        self._key_serializer.export_private_key_to_pem(key_pair=key_pair, private_key_pem_path=private_key_pem_path)
        self._key_serializer.export_public_key_to_pem(key_pair=key_pair, public_key_pem_path=public_key_pem_path)

    def get_public_key_by_user_email(self, email: str) -> PublicKey:
        return self._public_key_ring.get_public_key_by_user_email(user_email=email)

    def get_key_pair_by_user_mail(self, email: str, password: str):
        return self._private_key_ring.get_key_pair_by_user_email(user_mail=email, password=password)

    def delete_key_pair_by_user_email(self, email: str, password: str):
        self._private_key_ring.delete_key_pair_by_user_email(user_email=email, password=password)
        self._public_key_ring.delete_public_key_by_user_email(user_email=email)
        self._private_key_ring.save()

    def get_public_keyring_dictionary(self):
        return self._public_key_ring.get_key_pair_dictionary()

    def get_private_keyring_dictionary(self):
        return self._private_key_ring.get_key_pair_dictionary()


def test_key_manager():
    key_manager = KeyManager("user")
    key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, email="email", password="password")
    key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, email="email5", password="password")
    key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, email="email2", password="password2")
    key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, email="email3", password="password3")
    key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, email="email4", password="password4")
    public_key = key_manager.get_public_key_by_user_email("email")
    print(public_key.get_key())
    key_manager.delete_key_pair_by_user_email("email", "password")
    key_manager.delete_key_pair_by_user_email("email2", "password2")
    key_manager.export_key_pair_to_pem_by_user_email("email3", "password3", "public.pem", "private.pem")


if __name__ == '__main__':
    test_key_manager()
