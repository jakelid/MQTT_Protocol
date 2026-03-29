import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Encryptor:

    def __init__(self, session_key: bytes):

        if len(session_key) != 32:
            raise ValueError("Session key != 32 bytes.")

        self._aesgcm = AESGCM(session_key)

        self._counter = 0

    def encrypt(self, plaintext: str, topic: str = "") -> bytes:

        nonce = self._counter_to_nonce(self._counter)

        plaintext_bytes = plaintext.encode("utf-8")

        aad = topic.encode("utf-8") if topic else None

        ciphertext_with_tag = self._aesgcm.encrypt(nonce, plaintext_bytes, aad)

        counter_bytes = struct.pack(">I", self._counter)

        packet = counter_bytes + nonce + ciphertext_with_tag

        self._counter += 1

        return packet

    @staticmethod
    def _counter_to_nonce(counter: int) -> bytes:

        return counter.to_bytes(12, byteorder="big")

    @property
    def current_counter(self) -> int:
        """Return the next counter value that will be used."""
        return self._counter
