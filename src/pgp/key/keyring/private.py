"""
    1. Генерисање новог и брисање постојећег пара кључева

    ...Студенти треба да предложе и имплементирају
    структуре у којима се чувају кључеви (прстен јавних и приватних кључева)...
"""


class PrivateKeyRing:

    def __init__(self, user_id: str):
        self._user_id = user_id

    def add_private_key(self, private_key: str, password):
        raise NotImplementedError()

    def delete_private_key(self, key_id: str):
        raise NotImplementedError()

    def get_private_key(self, key_id: int, password: str):
        raise NotImplementedError()
    """
        Увоз и извоз јавног или приватног кључа у .pem формату
    """
    def import_private_key(self, path_to_pem: str, password):
        pass

    def export_private_key(self, key_id: int, path_to_pem: str, password):
        pass

    def save(self):
        raise NotImplementedError()
    """
        ...Сви генерисани и увезени кључеви
        треба да буду јасно видљиви на корисничком интерфејсу...
    """
    def get_all_rows(self):
        raise NotImplementedError()
