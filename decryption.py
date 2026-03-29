import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class Decryptor:

    def __init__(self, session_key: bytes):

        if len(session_key) != 32:
            raise ValueError("Session key != 32 bytes.") 

        self._aesgcm = AESGCM(session_key)
        self._last_counter = -1

    def decrypt(self, packet: bytes, topic: str = "") -> str:

        if len(packet) < 32:
            raise ValueError("Packet < 32 bytes.")

        counter = struct.unpack(">I", packet[:4])[0]

        if counter <= self._last_counter:
            msg = (f"Replay Attack detected! Counter: {counter} <= last accepted: "
                   f"{self._last_counter}.")
            raise ReplayAttack(msg)

        nonce = packet[4:16]

        ciphertext_with_tag = packet[16:]

        aad = topic.encode("utf-8") if topic else None

        try:
            plaintext_bytes = self._aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
        except InvalidTag:
            msg = "GCM tag verification has failed, message may have been tampered with."
            raise Tampered(msg)

        plaintext = plaintext_bytes.decode("utf-8")

        self._last_counter = counter

        return plaintext

    @property
    def last_accepted_counter(self) -> int:
        return self._last_counter

class ReplayAttack(Exception):
    pass

class Tampered(Exception):
    pass