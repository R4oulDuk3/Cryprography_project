from src.pgp.consts.consts import Algorithm, AlgorithmType
from src.pgp.key.generate.keypair import KeyPairGenerator
from src.pgp.key.key import KeyPair, PublicKey, PrivateKey
from src.pgp.key.key_serializer import KeySerializer
from src.pgp.key.keyring.public import PublicKeyRing
from src.pgp.key.keyring.secret import SecretKeyRing


class KeyManager:
    def __init__(self, user_name: str):
        self._user_name = user_name
        self._private_key_ring = SecretKeyRing(user_name=user_name)
        self._public_key_ring = PublicKeyRing(user_name=user_name)
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

    def generate_key_pair(self, algorithm: Algorithm,
                          key_size: int,
                          email: str,
                          password: str,
                          algorithm_type: AlgorithmType):
        key_pair: KeyPair = self._key_pair_generator.generate_key_pair(algorithm=algorithm,
                                                                       key_size=key_size)
        self._public_key_ring.add_public_key(public_key=key_pair.get_public_key(),
                                             user_email=email,
                                             algorithm_type=algorithm_type)
        self._private_key_ring.add_key_pair(key_pair=key_pair,
                                            password=password,
                                            user_email=email,
                                            algorithm_type=algorithm_type)
        print(f"Storing keys...{key_pair.get_public_key().get_key()}")
        self._public_key_ring.save()
        self._private_key_ring.save()

    """
        ...Сви генерисани и увезени кључеви
        треба да буду јасно видљиви на корисничком интерфејсу...
    """

    def import_key_pair_from_pem(self, public_key_pem_path: str,
                                 private_key_pem_path: str,
                                 email: str,
                                 password: str,
                                 algorithm_type: AlgorithmType):
        private_key: PrivateKey = self._key_serializer.import_private_key_from_pem(
            private_key_pem_path=private_key_pem_path)
        public_key: PublicKey = self._key_serializer.import_public_key_from_pem(public_key_pem_path=public_key_pem_path)
        key_pair: KeyPair = KeyPair(public_key=public_key,
                                    private_key=private_key,
                                    algorithm=private_key.get_algorithm())

        self._public_key_ring.add_public_key(public_key=key_pair.get_public_key(),
                                             user_email=email,
                                             algorithm_type=algorithm_type)
        self._private_key_ring.add_key_pair(key_pair=key_pair,
                                            password=password,
                                            user_email=email,
                                            algorithm_type=algorithm_type)
        self._public_key_ring.save()
        self._private_key_ring.save()

    def export_key_pair_to_pem_by_user_email(self,
                                             key_id: str,
                                             password: str,
                                             public_key_pem_path: str,
                                             private_key_pem_path: str):
        key_pair: KeyPair = self._private_key_ring.get_key_pair_by_key_id(key_id=key_id,
                                                                          password=password)
        self._key_serializer.export_private_key_to_pem(key_pair=key_pair,
                                                       private_key_pem_path=private_key_pem_path)
        self._key_serializer.export_public_key_to_pem(key_pair=key_pair,
                                                      public_key_pem_path=public_key_pem_path)

    def get_public_key_by_user_email(self, email: str, algorithm_type: AlgorithmType) -> PublicKey:
        return self._public_key_ring.get_public_key_by_user_email(user_email=email,
                                                                  algorithm_type=algorithm_type)

    def get_key_pair_by_user_mail(self, email: str, password: str, algorithm_type: AlgorithmType) -> KeyPair:
        return self._private_key_ring.get_key_pair_by_user_email(user_mail=email,
                                                                 password=password,
                                                                 algorithm_type=algorithm_type)

    def get_key_pair_by_key_id(self, key_id: str, password: str) -> KeyPair:
        return self._private_key_ring.get_key_pair_by_key_id(key_id=key_id,
                                                             password=password)

    def get_public_key_by_key_id(self, key_id: str) -> PublicKey:
        return self._public_key_ring.get_public_key_by_key_id(key_id=key_id)

    def delete_key_pair_by_user_email(self, email: str, password: str, algorithm_type: AlgorithmType):
        self._private_key_ring.delete_key_pair_by_user_email(user_email=email,
                                                             password=password,
                                                             algorithm_type=algorithm_type)
        self._public_key_ring.delete_public_key_by_user_email(user_email=email,
                                                              algorithm_type=algorithm_type)
        self._private_key_ring.save()

    def get_signing_key_id_by_user_email(self, email: str) -> str:
        return self._public_key_ring.get_signing_key_id_for_email(user_email=email)

    def get_encryption_key_id_by_user_email(self, email: str) -> str:
        return self._public_key_ring.get_encryption_key_id_for_email(user_email=email)

    def get_all_public_keyring_rows(self):
        return self._public_key_ring.get_all_public_keyring_rows()

    def get_all_private_keyring_rows(self):
        return self._private_key_ring.get_all_private_keyring_rows()

    def get_all_private_keyring_mails(self):
        return self._private_key_ring.get_all_mails()

    def get_all_public_keyring_mails(self):
        return self._public_key_ring.get_all_mails()

    def get_user_mail_by_key_id(self, key_id: str):
        return self._public_key_ring.get_mail_by_key_id(key_id=key_id)



def test_key_manager():
    key_manager = KeyManager("user")
    key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, email="email:1", password="password:1",
                                  algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION)
    key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, email="email:2", password="password:2",
                                  algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION)
    key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, email="email:3", password="password:3",
                                  algorithm_type=AlgorithmType.ASYMMETRIC_ENCRYPTION)
    key_manager.generate_key_pair(algorithm=Algorithm.RSA, key_size=1024, email="email:1", password="password:4",
                                  algorithm_type=AlgorithmType.SIGNING)


if __name__ == '__main__':
    test_key_manager()
