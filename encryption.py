import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Encryptor:

    def __init__(self, session_key: bytes):

        if len(session_key) != 32:
            raise ValueError("Session key != 32 bytes.")

        self._aesgcm = AESGCM(session_key)

        # counter is used as the nonce, embedded in packets to prevent replay attacks
        # incremented with each message
        self._counter = 0

    def encrypt(self, plaintext: str, topic: str = "") -> bytes:

        # creates a 12 byte nonce from counter
        nonce = self._counter_to_nonce(self._counter)

        plaintext_bytes = plaintext.encode("utf-8")

        # topic is authenticated but not encrypted -> so broker can read it for routing
        # any modification to the topic will case the GCM tag verification to fail (Subscriber will check this)
        aad = topic.encode("utf-8") if topic else None

        # essentially the ciphertext with the 16 byte tag appended
        ciphertext_with_tag = self._aesgcm.encrypt(nonce, plaintext_bytes, aad)

        # pack the counter as 4 bytes
        counter_bytes = struct.pack(">I", self._counter)

        # packout format -> [counter (4 bytes)] [nonce (12 bytes)] [ciphertext + tag (variable)]
        packet = counter_bytes + nonce + ciphertext_with_tag

        self._counter += 1

        return packet

    # helper method to convert counter to a 12 byte nonce (AES-GCM needs this)
    @staticmethod
    def _counter_to_nonce(counter: int) -> bytes:

        return counter.to_bytes(12, byteorder="big")