from encryption import Encryptor
from decryption import Decryptor, ReplayAttack, Tampered

class Broker:

    def __init__(self):
        self._subscriptions: dict[str, list] = {}
        print("\n[BROKER] Broker initialized.")

    def subscribe(self, topic: str, callback):

        if topic not in self._subscriptions:
            self._subscriptions[topic] = []
        self._subscriptions[topic].append(callback)
        print(f"[BROKER] New subscription to '{topic}'.")

    def publish(self, topic: str, payload: bytes):

        print(f"\n[BROKER] Received publish on '{topic}' "
              f"({len(payload)} bytes).")
        print(f"[BROKER] Payload: {payload[:24].hex()}...")

        if topic in self._subscriptions:
            for callback in self._subscriptions[topic]:
                callback(topic, payload)
        else:
            print(f"[BROKER] No subscribers for '{topic}'. Message dropped.")

class Publisher:

    def __init__(self, name: str, broker: Broker, session_key: bytes):
        self.name = name
        self.broker = broker
        self.encryptor = Encryptor(session_key)
        print(f"[{self.name}] Publisher initialized.")

    def publish(self, topic: str, message: str):

        print(f"\n[{self.name}] Publishing \"{message}\" to '{topic}'")
        encrypted_packet = self.encryptor.encrypt(message, topic=topic)
        print(f"[{self.name}] Encrypted into {len(encrypted_packet)} bytes.")

        self.broker.publish(topic, encrypted_packet)

        return encrypted_packet

class Subscriber:

    def __init__(self, name: str, broker: Broker, session_key: bytes):
        self.name = name
        self.broker = broker
        self.decryptor = Decryptor(session_key)
        self.received_messages = []
        print(f"[{self.name}] Subscriber initialized.")

    def subscribe(self, topic: str):
        self.broker.subscribe(topic, self._on_message)
        self._subscribed_topic = topic
        print(f"[{self.name}] Subscribed to '{topic}'.")

    def _on_message(self, topic: str, payload: bytes):
        print(f"\n[{self.name}] Received {len(payload)} bytes on '{topic}'.")
        try:
            plaintext = self.decryptor.decrypt(payload, topic=topic)
            print(f"[{self.name}] Decrypted message: \"{plaintext}\"")
            self.received_messages.append(plaintext)

        except ReplayAttack as e:
            print(f"[{self.name}] {e}")

        except Tampered as e:
            print(f"[{self.name}] {e}")

        except Exception as e:
            print(f"[{self.name}] {e}")