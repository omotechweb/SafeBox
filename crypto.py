from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os
import base64

class CryptoManager:
    def __init__(self, password: str):
        self.password = password.encode()
        self.salt = b"static_salt_for_demo"  # Üretim için random ve dosyada saklanmalı
        self.key = self.derive_key()

    def derive_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=390000,
            backend=default_backend()
        )
        return kdf.derive(self.password)

    def encrypt(self, data: bytes) -> bytes:
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)
        encrypted = aesgcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + encrypted)

    def decrypt(self, data: bytes) -> bytes:
        aesgcm = AESGCM(self.key)
        decoded = base64.b64decode(data)
        nonce = decoded[:12]
        ciphertext = decoded[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)
