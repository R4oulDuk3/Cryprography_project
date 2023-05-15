class PGPMessage:
    def __init__(self, recipient_public_key_id, session_key, sender_public_key_id, data):
        self.recipient_public_key_id = recipient_public_key_id
        self.session_key = session_key
        self.sender_public_key_id = sender_public_key_id
        self.data = data

    @staticmethod
    def to_bytes(message):
        pass

    @staticmethod
    def from_bytes(message_bytes: bytes):
        pass