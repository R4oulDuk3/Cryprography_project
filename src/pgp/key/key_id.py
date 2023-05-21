from src.pgp.consts.consts import KEY_ID_LENGTH


def made_key_id(key_bytes: bytes) -> str:
    return key_bytes[-KEY_ID_LENGTH:].hex()
