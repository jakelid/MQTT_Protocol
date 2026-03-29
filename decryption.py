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

        # Step 1 -> packet length check
        # counter = 4 bytes, nonce = 12 bytes, tag = 16 bytes

        if len(packet) < 32:
            raise ValueError("Packet < 32 bytes.")

        # Step 2 -> get counter (first 4 bytes)
        counter = struct.unpack(">I", packet[:4])[0]

        # Step 3 -> check for replay attack
        if counter <= self._last_counter:
            msg = (f"Replay Attack detected! Counter: {counter} <= last accepted: "
                   f"{self._last_counter}.")
            raise ReplayAttack(msg)

        # Step 4 -> get nonce (bytes 4 to 16)
        nonce = packet[4:16]

        # Step 5 -> get ciphertext and tag (rest of bytes)
        ciphertext_with_tag = packet[16:]

        # Step 6 -> compute associated authenticated data (AAD) from topic
        aad = topic.encode("utf-8") if topic else None

        # Step 7 -> try decryption and verify the GCM tag
        try:
            plaintext_bytes = self._aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
        except InvalidTag:
            msg = "GCM tag verification has failed, message may have been tampered with."
            raise Tampered(msg)

        plaintext = plaintext_bytes.decode("utf-8")

        # Step 8 -> update counter (basically means we accept this message)
        self._last_counter = counter

        return plaintext

# custom exceptions for replay attack and message tampering
class ReplayAttack(Exception):
    pass

class Tampered(Exception):
    pass