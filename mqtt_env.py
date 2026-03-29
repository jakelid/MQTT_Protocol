from encryption import Encryptor
from decryption import Decryptor, ReplayAttack, Tampered

# routes messages by topic to subs, is untrusted
# only sees encrypted payloads, but cannot decrypt
class Broker:

    def __init__(self):
        self._subscriptions: dict[str, list] = {}
        print("\n[BROKER] Broker initialized.")

    # adds new subscriptions to topics not already subscribed to
    def subscribe(self, topic: str, callback):

        if topic not in self._subscriptions:
            self._subscriptions[topic] = []
        self._subscriptions[topic].append(callback)
        print(f"[BROKER] New subscription to '{topic}'.")

    # forwards encrypted payloads to all subscribers for a given topic
    def publish(self, topic: str, payload: bytes):

        print(f"\n[BROKER] Received publish on '{topic}' "
              f"({len(payload)} bytes).")
        print(f"[BROKER] Payload: {payload[:24].hex()}...")

        if topic in self._subscriptions:
            for callback in self._subscriptions[topic]:
                callback(topic, payload)
        else:
            print(f"[BROKER] No subscribers for '{topic}'. Message dropped.")

# encrypts messages before sending them to the broker
class Publisher:

    def __init__(self, name: str, broker: Broker, session_key: bytes):
        self.name = name
        self.broker = broker
        self.encryptor = Encryptor(session_key)
        print(f"[{self.name}] Publisher initialized.")

    # encrypts the plaintext and passes the associated encrypted packet to the broker
    def publish(self, topic: str, message: str):

        print(f"\n[{self.name}] Publishing \"{message}\" to '{topic}'")
        encrypted_packet = self.encryptor.encrypt(message, topic=topic)
        print(f"[{self.name}] Encrypted into {len(encrypted_packet)} bytes.")

        self.broker.publish(topic, encrypted_packet)

        return encrypted_packet

# receives encrypted messages from broker and decrypts them
# checks for replay attacks and message tampering
class Subscriber:

    def __init__(self, name: str, broker: Broker, session_key: bytes):
        self.name = name
        self.broker = broker
        self.decryptor = Decryptor(session_key)
        self.received_messages = []
        print(f"[{self.name}] Subscriber initialized.")

    # subscribes to a topic with the broker
    def subscribe(self, topic: str):
        self.broker.subscribe(topic, self._on_message)
        self._subscribed_topic = topic
        print(f"[{self.name}] Subscribed to '{topic}'.")

    # called by the broker when a message arrives on a subscribed topic
    # decrypts the message, checks for replay attacks and message tampering
    # stores plaintext if valid
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