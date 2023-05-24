from dataclasses import dataclass


@dataclass
class PublicKeyringRowDTO:
    public_key: str
    key_id: str
    user_email: str
    user_name: str
    algorithm: str
    algorithm_type: str


@dataclass
class PrivateKeyringRowDTO:
    user_name: str
    user_email: str
    key_id: str
    public_key: str
    encrypted_private_key: str
    hashed_password_with_salt: str
    algorithm: str
    algorithm_type: str
