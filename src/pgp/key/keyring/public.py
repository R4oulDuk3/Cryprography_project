"""
    1. Генерисање новог и брисање постојећег пара кључева

    ...Студенти треба да предложе и имплементирају
    структуре у којима се чувају кључеви (прстен јавних и приватних кључева)...
"""
from src.pgp.key.key import Key


class PublicKeyRing:
    def __init__(self, user_id: str):
        self._user_id = user_id

    def add_public_key(self, public_key: Key, name: str, email: str):
        raise NotImplementedError()

    def delete_public_key(self, public_key):
        raise NotImplementedError()

    def get_public_key(self, key_id):
        raise NotImplementedError()
    """
        Увоз и извоз јавног или приватног кључа у .pem формату
    """
    def import_public_key(self, path_to_pem: str):
        pass

    def export_public_key(self, key_id: int, path_to_pem: str):
        pass

    def save(self):
        raise NotImplementedError()

    """
        ...Сви генерисани и увезени кључеви
        треба да буду јасно видљиви на корисничком интерфејсу...
    """
    def get_all_rows(self):
        raise NotImplementedError()